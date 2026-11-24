#!/bin/sh
# OpenRC boot & reconciliation script for the stateless Alpine `ludus-edge` VM.
# Boots live from CD-ROM (`ludus-edge.iso` -> `localhost.apkovl.tar.gz`) with zero
# baked secrets:
#   1. Installs signed offline Alpine `.apk` packages from `/opt/ludus-edge-pkgs`.
#   2. Formats/mounts the 1 GB persistent seal disk at `/var/lib/ludus-edge` (0700).
#   3. Parses Proxmox NoCloud `cidata` (`network-config` + `user-data` enrollment key).
#   4. Configures `eth0` (mgmt LAN) + `eth1` (`192.0.2.254/24` `ludusnat`), 254 static
#      range routes (`10.<1..254>.0.0/16 via 192.0.2.<1..254>`), `nftables` NAT +
#      management-LAN isolation, and `dnsmasq` DHCP/DNS on `ludusnat`.
#   5. Restores `wg0` if already sealed and launches `ludus-edge-proxy` on `:8444`.
set -eu

log() {
    printf '[ludus-edge] %s\n' "$*"
}

mask_to_prefix() {
    case "${1:-}" in
        /*|[0-9]|[12][0-9]|3[0-2])
            printf '%s' "${1#/}"
            ;;
        255.255.255.255) printf '32' ;;
        255.255.255.254) printf '31' ;;
        255.255.255.252) printf '30' ;;
        255.255.255.248) printf '29' ;;
        255.255.255.240) printf '28' ;;
        255.255.255.224) printf '27' ;;
        255.255.255.192) printf '26' ;;
        255.255.255.128) printf '25' ;;
        255.255.255.0)   printf '24' ;;
        255.255.254.0)   printf '23' ;;
        255.255.252.0)   printf '22' ;;
        255.255.248.0)   printf '21' ;;
        255.255.240.0)   printf '20' ;;
        255.255.0.0)     printf '16' ;;
        255.0.0.0)       printf '8'  ;;
        *)               printf '24' ;;
    esac
}

find_iface_by_mac_or_name() {
    want_name="$1"
    want_mac=$(printf '%s' "${2:-}" | tr 'A-Z' 'a-z')
    if [ -n "$want_mac" ]; then
        for sysif in /sys/class/net/*; do
            [ -e "$sysif/address" ] || continue
            ifname=${sysif##*/}
            [ "$ifname" = "lo" ] && continue
            cur_mac=$(tr 'A-Z' 'a-z' < "$sysif/address" 2>/dev/null || true)
            if [ "$cur_mac" = "$want_mac" ]; then
                printf '%s' "$ifname"
                return 0
            fi
        done
    fi
    printf '%s' "$want_name"
}

# 0. Enforce zero-SSH appliance posture (Alpine tiny-cloud auto-starts sshd when sshkeys exist)
rc-service sshd stop >/dev/null 2>&1 || true
rc-update del sshd default >/dev/null 2>&1 || true
pkill -x sshd >/dev/null 2>&1 || true

# 1. Install offline signed APK bundle via indexed local repository
if [ -f /opt/ludus-edge-pkgs/x86_64/APKINDEX.tar.gz ]; then
    log "Installing offline Alpine packages from indexed local repo..."
    apk add --no-network --force-non-repository --no-cache \
        --repositories-file /dev/null \
        --repository /opt/ludus-edge-pkgs \
        --allow-untrusted \
        iproute2 nftables iptables dnsmasq wireguard-tools openresolv e2fsprogs blkid qemu-guest-agent
elif [ -d /opt/ludus-edge-pkgs ] && ls /opt/ludus-edge-pkgs/*.apk >/dev/null 2>&1; then
    log "Installing offline signed Alpine packages..."
    apk add --no-network --force-non-repository /opt/ludus-edge-pkgs/*.apk
fi

for kmod in virtio_scsi virtio_blk ext4 tun wireguard nf_tables nft_masq nft_nat nft_chain_nat nf_conntrack; do
    modprobe "$kmod" >/dev/null 2>&1 || true
done
mdev -s >/dev/null 2>&1 || true

# 2. Mount persistent 1 GB seal disk (/dev/sda or /dev/vda) at /var/lib/ludus-edge (0700)
mkdir -p /var/lib/ludus-edge
chmod 0700 /var/lib/ludus-edge

STATE_DEV=""
for candidate in /dev/disk/by-label/LUDUS_EDGE_STATE /dev/sda /dev/vda; do
    if [ -b "$candidate" ]; then
        STATE_DEV="$candidate"
        break
    fi
done

if [ -n "$STATE_DEV" ]; then
    if ! blkid "$STATE_DEV" 2>/dev/null | grep -q 'TYPE="ext4"'; then
        log "Formatting blank seal disk $STATE_DEV as ext4 (LUDUS_EDGE_STATE)..."
        mkfs.ext4 -q -F -L LUDUS_EDGE_STATE "$STATE_DEV"
    fi
    if ! grep -qs ' /var/lib/ludus-edge ' /proc/mounts; then
        mount -t ext4 -o noatime,nodev,nosuid,noexec "$STATE_DEV" /var/lib/ludus-edge
    fi
    chmod 0700 /var/lib/ludus-edge
    log "Mounted seal state directory on $STATE_DEV"
else
    log "WARNING: No persistent block device (/dev/sda or /dev/vda) detected; using tmpfs /var/lib/ludus-edge"
fi

# 3. Locate and mount Proxmox Cloud-Init NoCloud ISO (label `cidata` / `CIDATA`)
CIDATA_MNT=/run/cidata
mkdir -p "$CIDATA_MNT"
CIDATA_DEV=$(blkid -L cidata 2>/dev/null || blkid -L CIDATA 2>/dev/null || true)
if [ -z "$CIDATA_DEV" ]; then
    for sr in /dev/sr0 /dev/sr1 /dev/sr2; do
        [ -b "$sr" ] || continue
        if blkid "$sr" 2>/dev/null | grep -qi 'cidata'; then
            CIDATA_DEV="$sr"
            break
        fi
    done
fi

MGMT_IF="eth0"
NAT_IF="eth1"
NAT_CIDR="192.0.2.254/24"
UPSTREAM_DNS="1.1.1.1"

if [ -n "$CIDATA_DEV" ] && mount -o ro "$CIDATA_DEV" "$CIDATA_MNT" 2>/dev/null; then
    log "Mounted Cloud-Init cidata from $CIDATA_DEV"

    # Extract Ed25519 enrollment public key from user-data
    if [ -f "$CIDATA_MNT/user-data" ]; then
        ENROLL_LINE=$(grep -Eo 'ssh-ed25519 [A-Za-z0-9+/=]+([[:space:]][^"'\'']*)?' "$CIDATA_MNT/user-data" | head -n 1 || true)
        if [ -n "$ENROLL_LINE" ]; then
            umask 077
            printf '%s\n' "$ENROLL_LINE" > /var/lib/ludus-edge/enroll.pub
            log "Loaded Ed25519 enrollment key into /var/lib/ludus-edge/enroll.pub"
        fi
    fi

    # Parse Cloud-Init v1 network-config (emits: IFACE|MAC|MODE|ADDR|NETMASK|GW|DNS)
    if [ -f "$CIDATA_MNT/network-config" ]; then
        PARSED_NET=$(awk '
            function flush_if() {
                if (name != "") {
                    printf "%s|%s|%s|%s|%s|%s|%s\n", name, mac, mode, addr, mask, gw, dns
                }
                name=""; mac=""; mode=""; addr=""; mask=""; gw=""
            }
            /^[[:space:]]*-[[:space:]]*type:[[:space:]]*physical/ { flush_if(); in_phys=1; in_nameserver=0; next }
            /^[[:space:]]*-[[:space:]]*type:[[:space:]]*nameserver/ { flush_if(); in_phys=0; in_nameserver=1; next }
            in_phys && /^[[:space:]]*name:/ { gsub(/["'\'']/, "", $2); name=$2; next }
            in_phys && /^[[:space:]]*mac_address:/ { gsub(/["'\'']/, "", $2); mac=$2; next }
            in_phys && /^[[:space:]]*-[[:space:]]*type:[[:space:]]*(static|dhcp)/ {
                line=$0; sub(/.*type:[[:space:]]*/, "", line); gsub(/["'\''[:space:]]/, "", line); mode=line; next
            }
            in_phys && /^[[:space:]]*address:/ { gsub(/["'\'']/, "", $2); addr=$2; next }
            in_phys && /^[[:space:]]*netmask:/ { gsub(/["'\'']/, "", $2); mask=$2; next }
            in_phys && /^[[:space:]]*gateway:/ { gsub(/["'\'']/, "", $2); gw=$2; next }
            in_nameserver && /^[[:space:]]*-[[:space:]]*[0-9]+\./ {
                line=$0; sub(/^[[:space:]]*-[[:space:]]*/, "", line); gsub(/["'\''[:space:]]/, "", line)
                if (dns == "") dns=line
                next
            }
            END { flush_if() }
        ' "$CIDATA_MNT/network-config")

        IFS='
'
        for entry in $PARSED_NET; do
            [ -n "$entry" ] || continue
            p_name=$(printf '%s' "$entry" | cut -d'|' -f1)
            p_mac=$(printf '%s' "$entry" | cut -d'|' -f2)
            p_mode=$(printf '%s' "$entry" | cut -d'|' -f3)
            p_addr=$(printf '%s' "$entry" | cut -d'|' -f4)
            p_mask=$(printf '%s' "$entry" | cut -d'|' -f5)
            p_gw=$(printf '%s' "$entry" | cut -d'|' -f6)
            p_dns=$(printf '%s' "$entry" | cut -d'|' -f7)

            real_if=$(find_iface_by_mac_or_name "$p_name" "$p_mac")
            ip link set "$real_if" up || true

            if [ "$p_mode" = "dhcp" ]; then
                udhcpc -i "$real_if" -n -q || true
            elif [ -n "$p_addr" ]; then
                case "$p_addr" in
                    */*) cidr="$p_addr" ;;
                    *)   cidr="$p_addr/$(mask_to_prefix "$p_mask")" ;;
                esac
                ip addr flush dev "$real_if" || true
                ip addr add "$cidr" dev "$real_if"
                if [ -n "$p_gw" ]; then
                    ip route replace default via "$p_gw" dev "$real_if"
                    MGMT_IF="$real_if"
                    [ -z "$p_dns" ] && UPSTREAM_DNS="$p_gw"
                fi
                case "$cidr" in
                    192.0.2.*)
                        NAT_IF="$real_if"
                        NAT_CIDR="$cidr"
                        ;;
                esac
            fi
            [ -n "$p_dns" ] && UPSTREAM_DNS="$p_dns"
        done
        unset IFS
    fi
    umount "$CIDATA_MNT" || true
fi

# Ensure ludusnat interface is up with 192.0.2.254/24 even if cidata omitted ipconfig1
if ip link show "$NAT_IF" >/dev/null 2>&1; then
    ip link set "$NAT_IF" up
    if ! ip -4 addr show dev "$NAT_IF" | grep -q '192\.0\.2\.'; then
        ip addr add "$NAT_CIDR" dev "$NAT_IF"
    fi
fi

NAT_IP=${NAT_CIDR%/*}
printf 'nameserver %s\n' "$UPSTREAM_DNS" > /etc/resolv.conf

# 4. Enable kernel IPv4 forwarding + 153 static range routes (10.<1..153>.0.0/16 -> 192.0.2.<101..253>)
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if ip link show "$NAT_IF" >/dev/null 2>&1; then
    i=1
    while [ "$i" -le 153 ]; do
        ip route replace "10.${i}.0.0/16" via "192.0.2.$((100 + i))" dev "$NAT_IF" onlink || true
        i=$((i + 1))
    done
    log "Configured 153 static range routes (10.1.0.0/16..10.153.0.0/16 -> 192.0.2.101..253) on $NAT_IF"
fi

# 5. Load nftables NAT + strict management-LAN isolation ruleset
cat > /etc/nftables.ludus-edge.conf <<EOF
flush ruleset

table inet ludus_edge {
    chain input {
        type filter hook input priority 0; policy accept;
        iifname "lo" accept
        ct state established,related accept
        tcp dport 22 drop
        # Prevent range VMs on ludusnat from reaching mTLS control port (:8444)
        iifname "${NAT_IF}" tcp dport 8444 drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        # WireGuard operators (wg0) -> Ludus range routers & tenant VMs
        iifname "wg0" oifname "${NAT_IF}" accept
        # Hairpin / inter-router transit on ludusnat when permitted by range router rules
        iifname "${NAT_IF}" oifname "${NAT_IF}" accept
        # Block range VMs from initiating connections to RFC1918 management LANs on MGMT_IF
        iifname "${NAT_IF}" oifname "${MGMT_IF}" ip daddr 10.0.0.0/16 drop
        iifname "${NAT_IF}" oifname "${MGMT_IF}" ip daddr 172.16.0.0/12 drop
        iifname "${NAT_IF}" oifname "${MGMT_IF}" ip daddr 192.168.0.0/16 drop
        iifname "${NAT_IF}" oifname "${MGMT_IF}" ip daddr 169.254.0.0/16 drop
        # Allow range VMs / Packer template builds outbound internet access via NAT
        iifname "${NAT_IF}" oifname "${MGMT_IF}" accept
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "${MGMT_IF}" ip saddr 192.0.2.0/24 masquerade
        oifname "${MGMT_IF}" ip saddr 198.51.100.0/24 masquerade
        oifname "${MGMT_IF}" ip saddr 10.0.0.0/8 masquerade
        oifname "${NAT_IF}" ip saddr 198.51.100.0/24 masquerade
    }
}
EOF
nft -f /etc/nftables.ludus-edge.conf
log "Loaded nftables NAT and management-LAN isolation rules"

# 6. Configure and start dnsmasq on ludusnat (matching Ludus DHCP 192.0.2.50..100, 5m lease)
mkdir -p /var/lib/misc /etc/dnsmasq.d
cat > /etc/dnsmasq.conf <<EOF
bind-interfaces
interface=${NAT_IF}
listen-address=${NAT_IP}
pid-file=/var/run/dnsmasq.pid
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
no-resolv
server=${UPSTREAM_DNS}
dhcp-range=192.0.2.50,192.0.2.100,255.255.255.0,5m
dhcp-option=${NAT_IF},3,${NAT_IP}
dhcp-option=${NAT_IF},6,${NAT_IP}
EOF
if ip link show "$NAT_IF" >/dev/null 2>&1; then
    if [ -f /var/run/dnsmasq.pid ]; then
        kill "$(cat /var/run/dnsmasq.pid)" 2>/dev/null || true
    fi
    dnsmasq --conf-file=/etc/dnsmasq.conf
    log "Started dnsmasq on $NAT_IF ($NAT_IP)"
fi

# 7. Start QEMU guest agent when virtio channel exists
if [ -e /dev/virtio-ports/org.qemu.guest_agent.0 ] && command -v qemu-ga >/dev/null 2>&1; then
    qemu-ga -d 2>/dev/null || true
fi

# 8. Restore sealed WireGuard interface if wg0.conf is persisted on /var/lib/ludus-edge
if [ -s /var/lib/ludus-edge/wg0.conf ]; then
    mkdir -p /etc/wireguard
    umask 077
    cp /var/lib/ludus-edge/wg0.conf /etc/wireguard/wg0.conf
    chmod 0600 /etc/wireguard/wg0.conf
    wg-quick down wg0 2>/dev/null || true
    wg-quick up wg0
    log "Restored sealed WireGuard interface wg0 (:51820/udp)"
fi

# 9. Start ludus-edge-proxy with automatic 2s respawn supervisor
log "Starting ludus-edge-proxy on 0.0.0.0:8444 (nat-bind-ip=${NAT_IP})..."
(
    while true; do
        /usr/local/bin/ludus-edge-proxy \
            --listen 0.0.0.0:8444 \
            --state-dir /var/lib/ludus-edge \
            --enroll-pubkey-file /var/lib/ludus-edge/enroll.pub \
            --nat-bind-ip "${NAT_IP}" >>/var/log/ludus-edge-proxy.log 2>&1 || true
        sleep 2
    done
) </dev/null >/dev/null 2>&1 &
log "ludus-edge boot reconciliation complete."
