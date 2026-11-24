# Ludus Containerization & Split Edge Architecture Plan (`Architecture A`)

**Status:** Approved Design — Ready for Phased Implementation  
**Target Repositories:**
- `cseelhoff/ludus` (`/home/caleb/ludus`, branch `feat/container-architecture` stacked on `feat/remote-proxmox-vm`)
- `cseelhoff/ludus-ux` (planned fork of `ryokubaka/ludus-ux` for SSH-free HTTPS REST + Keycloak OIDC)
- `soc-range` / `sophon` integration artifacts (`ops/pve-prod-02/` Alpine `ludus-edge` provisioner + Sophon Pure GitOps Compose stack)

**Companion Roadmap:** [Ludus Containerization Implementation Roadmap](./ludus-container-roadmap.md)  
**Prior Foundation:** Builds directly on `Option 2` (`remote_proxmox: true`, 100% Proxmox HTTPS API `:8006`, cluster node pinning), upgrading Proxmox authentication from per-user `@pve` passwords to a single pre-registered, least-privilege Proxmox API token (`PVEAPIToken`, `service_token` mode).

---

## 1. Executive Summary & Architectural Principles

With `Option 2` (`feat/remote-proxmox-vm`) complete, Ludus no longer touches Proxmox CLI binaries (`pveum`, `pvesm`, `qm`), `/etc/pve`, hypervisor PAM accounts, or nested KVM. The remaining host coupling inside `ludus-ctrl` (`VM 122`) falls into two cleanly separable concerns:

1. **Control Plane (`ludus` + `lux` on `sophon-infravm`, `pve-prod-01`):**
   - PocketBase state (`/opt/ludus/db`), Proxmox `:8006` REST orchestration, Ansible range configuration, Packer template builds, Keycloak OIDC + local PocketBase authentication, and the LUX web UI.
   - Needs **zero** kernel capabilities (`cap_drop: ALL`, `no-new-privileges:true`), **zero** Linux `/etc/passwd` user mutations, **zero** host/LAN static routes, and runs natively inside **Sophon's rootless Podman** environment on Fedora CoreOS (`sophon-infravm`).

2. **Stateless L2/L3 Data-Plane Appliance (`ludus-edge` Alpine VM on `pve-prod-02`):**
   - Terminates L2 adjacency on Proxmox SDN VNet `ludusnat` (`192.0.2.254/24`, MTU `1450`) where range VMs live (`pve-prod-02`).
   - Runs `dnsmasq` (bootstrap DHCP `192.0.2.50–100` + DNS forwarding), outbound NAT (`MASQUERADE`) with strict `RFC1918` isolation (`nftables`), **153 precomputed static range routes** (`10.<1..153>.0.0/16 via 192.0.2.<101..253>`), **1-hop kernel WireGuard (`wg0`, `:51820/udp`)** with a **pre-allocated 250-slot static peer pool**, and a tiny mTLS 1.3 userspace proxy (`ludus-edge-proxy`, `:8444/tcp`) for Ludus Ansible/WinRM/Packer traffic.

### Core Design Invariants (Avoiding Distributed-State Anti-Patterns)
1. **Zero Runtime Router Control API:** `ludus` never SSHes into `ludus-edge` or mutates `ludus-edge` routes, firewall rules, DHCP leases, or WireGuard configs at runtime. Everything on `ludus-edge` is **statically precomputed at boot** from closed-form addressing (`Range N -> 192.0.2.(100+N)`, `User M -> 198.51.100.M/32`).
2. **Zero Host or LAN Routing Table Changes:** Neither `sophon-infravm` (Fedora CoreOS) nor the physical `10.0.20.1` LAN router carries static routes for `192.0.2.0/24` or `10.<N>.0.0/16`. All orchestrator traffic (`ansible-playbook` SSH/WinRM + `packer` SSH/WinRM + Packer Linux preseed HTTP) traverses a single pinned **mTLS 1.3 userspace proxy channel** (`ludus -> ludus-edge:8444`).
3. **Zero Hairpin on Analyst VPN:** Operator WireGuard (`:51820/udp`) terminates directly on `ludus-edge` (`pve-prod-02`), forwarding decrypted packets straight onto `ludusnat` in a single kernel hop without touching `pve-prod-01` or `sophon-infravm`.
4. **Zero Proxmox Passwords, Zero Per-User `@pve` Shadow Accounts, Zero SSH in Operator UIs:**
   - Human users authenticate to LUX and Ludus via **Keycloak OIDC (`https://auth.<domain>/realms/<realm>`)** with **local PocketBase email/password** as break-glass fallback, and LUX talks to Ludus exclusively over **HTTPS/HTTP REST** (`Authorization: Bearer <jwt>`).
   - Ludus authenticates to Proxmox (`:8006`) exclusively with **one pre-registered, least-privilege Proxmox API token** (`PVEAPIToken=ludus-svc@pve!controller=<secret>`, `proxmox_auth_mode: "service_token"`). Zero Proxmox passwords exist on `sophon-infravm`, zero per-user `@pve` accounts are created when Keycloak users log in, and Ludus holds **zero `User.Modify` or `Permissions.Modify` privileges** on `ProdCluster`.

---

## 2. Target Topology (`sophon-infravm` on `pve-prod-01` + `ludus-edge` on `pve-prod-02`)

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ pve-prod-01: sophon-infravm (Fedora CoreOS — Rootless Podman, ZERO host route changes) │
│                                                                                        │
│  [ Traefik (:443 *.domain) ] ───► [ Keycloak (auth.domain) ◄── OpenLDAP (ldap.domain)] │
│        │                 │                                                             │
│        ▼                 ▼                                                             │
│  ┌───────────────┐  ┌───────────────────────────────────────────────────────────────┐  │
│  │ lux           │  │ ludus (Single rootless container, UID 1000, cap_drop: ALL)    │  │
│  │ (Next.js UI)  ├─►│  • ludus-server --container (:8080 public + 127.0.0.1:8081)   │  │
│  │ OIDC + Local  │  │  • PocketBase SQLite (/opt/ludus/db — Kopia backed up)        │  │
│  │ HTTPS REST    │  │  • Baked-in Ansible + Galaxy cache + Packer + plugins         │  │
│  │ (ZERO SSH!)   │  │  • Loopback proxy 127.0.0.1:1080 (SOCKS5 + HTTP CONNECT)      │  │
│  └───────────────┘  └───────────────┬──────────────────────────────┬────────────────┘  │
└─────────────────────────────────────┼──────────────────────────────┼───────────────────┘
                                      │ HTTPS :8006                  │ mTLS 1.3 :8444
                                      │ (Single PVEAPIToken)         │ (Userspace Proxy +
                                      │                              │  Packer HTTP Rev)
               ═══════════════════════╪══════════════════════════════╪══════════════════
                 Management LAN vmbr0 (10.0.20.0/24 — NO lab routes on LAN)
               ═══════════════════════╤══════════════════════════════╤══════════════════
                                      │                              │
      [ Analyst Laptop ]              ▼                              ▼
              │         ┌──────────────────────────────────────────────────────────────┐
    UDP :51820│(WG VPN) │ pve-prod-02 (10.0.20.12 — Range Hypervisor)                  │
              │         │                                                              │
              │         │  ┌────────────────────────────────────────────────────────┐  │
              └────────►│  │ VM 122: ludus-edge (Alpine Linux, 256 MB RAM, Read-Only│  │
                        │  │                     Stateless Appliance, No KVM vmx)   │  │
                        │  │  • eth0 (vmbr0 10.0.20.181): :51820/udp WG + :8444/tcp │  │
                        │  │  • wg0 (198.51.100.1/24): 250 pre-seeded static peers  │  │
                        │  │  • ludus-edge-proxy (:8444 mTLS -> 192.0.2/24, 10.N/16)│  │
                        │  │  • ludusnat (192.0.2.254/24, MTU 1450):                │  │
                        │  │      - dnsmasq (DHCP 192.0.2.50–100 + DNS :53)         │  │
                        │  │      - Precomputed routes: 10.<1..153>.0.0/16          │  │
                        │  │        via 192.0.2.<101..253> dev ludusnat             │  │
                        │  │      - nftables: NAT egress + strict RFC1918 drop      │  │
                        │  └───────────────────────────┬────────────────────────────┘  │
                        │                              │ L2 SDN VNet `ludusnat`        │
                        │              ┌───────────────┼───────────────┐               │
                        │              ▼               ▼               ▼               │
                        │       [Packer Build]  [Range 1 Router] [Range 2 Router]      │
                        │        192.0.2.5x      192.0.2.101      192.0.2.102          │
                        │                             │                │               │
                        │                        SDN VNet r1      SDN VNet r2          │
                        │                        10.1.0.0/16      10.2.0.0/16          │
                        └──────────────────────────────────────────────────────────────┘
```

---

## 3. Detailed Subsystem Design

### 3.1 Unified Unprivileged Container Mode (`ludus-server --container` / `container_mode: true`)

Stock Ludus splits execution across two `systemd` units (`ludus-admin.service` as `uid=0` on `127.0.0.1:8081` and `ludus.service` as `uid=ludus` on `0.0.0.0:8080`) and relies on `os.Geteuid() == 0` in 20+ call sites across `ludus-api` to distinguish the admin server from the user server.

In rootless Podman (`user: 1000:1000`, `cap_drop: ALL`, `no-new-privileges:true`), nothing requires Linux `uid=0`:
1. **Replace `os.Geteuid() == 0` with explicit server role (`s.IsAdmin`):**
   - Introduce `Server.IsAdmin` (and package helper `IsAdminProcess()`), set `true` when invoked with `--admin` (falling back to `os.Geteuid() == 0` only in legacy non-container mode).
   - `--container` supervisor mode spawns the `--admin` child process (`127.0.0.1:8081`) and the user-facing server (`0.0.0.0:8080`) under the **same unprivileged UID (`1000`, `ludus`)**, forwarding `SIGTERM`/`SIGINT` cleanly and exiting if either listener dies.
2. **Pure-Go User Workspace Provisioning (Zero `/etc/passwd`, Zero `add-user.yml`):**
   - When `container_mode: true`:
     - Skip `ansible.builtin.user` (`adduser`/`deluser`), `pveusers` group lookups, `/usr/bin/id` host checks (`userExistsOnHostSystem()` returns `false`), and `os.Chown` (`chownFileToUsername` / `setRangeDirPermissions` become `chmod`-only no-ops since all files belong to container UID `ludus`).
     - Replace `RunAddUserPlaybookStandalone()` / `RunDeleteUserPlaybookStandalone()` with `provisionContainerUserWorkspace()` / `removeContainerUserWorkspace()` in pure Go:
       - Creates `/opt/ludus/users/<username>/{packer/tmp,.ansible}` (`0750`).
       - Symlinks `/opt/ludus/users/<username>/.ansible/collections` and `roles` to the image's pre-baked `/opt/ludus/resources/ansible-cache` (with writable user overlay support when users install extra roles), cutting user creation time from ~8s to `<5ms` and saving ~400 MB disk per user.
       - Renders `/opt/ludus/ranges/<userID>/range-config.yml` directly in Go when `create_default_range: true`.
3. **Disable Host-Mutating Operations in Container Mode:**
   - `sdn.go`: `routeForRangeNetworkInVNetAction()` becomes a clean no-op when `container_mode: true` (routes are statically precomputed on `ludus-edge`, and container traffic uses the userspace proxy).
   - `update.go`: `ludus-server --update` exits with a clear message instructing operators to pull the updated container image (`registry.<domain>/ludus-server:<tag>`).

---

### 3.2 Least-Privilege Proxmox Service API Token (`proxmox_auth_mode: "service_token"`)

#### Why API Tokens Eliminate the Last Proxmox Password & Privilege Escalation Vector
98% of Ludus's Proxmox runtime calls (`go-proxmox` VM lifecycle, `dynamic-inventory`, Ansible `proxmox_kvm`, Packer `PROXMOX_USERNAME`/`PROXMOX_TOKEN`, SDN VNet CRUD, and WebSocket VNC `/vm/console/view`) **already use Proxmox API tokens (`PVEAPIToken`)**. Username/password ticket auth (`proxmox_admin_password_file`) only existed in `Option 2` because Proxmox VE 8/9's `pve-access-control` hard-blocks API tokens from calling `PUT /api2/json/access/password` when mirroring human Ludus users into Proxmox `@pve` accounts.

In Architecture A, human authentication and per-range RBAC live in **Keycloak OIDC + Ludus PocketBase (`HasRangeAccess`)**, and operators never log directly into `ProdCluster` `:8006` with Ludus-created accounts. Switching to a **single pre-registered Proxmox API token (`ludus-svc@pve!controller`)** removes that legacy user-mirroring layer completely:

1. **One-Time Scoped Provisioning on Proxmox (`pve-prod-02`):**
   Create disabled-password service principal `ludus-svc@pve` and API token `ludus-svc@pve!controller` with propagated pool/SDN rights and **zero IAM/ACL modification privileges**:
   - `/` -> `ResourceAudit` (`Sys.Audit,Datastore.Audit`)
   - `/nodes/pve-prod-02` -> `ResourceAudit,AccessNetwork` (**omits** `pve-prod-01` and `pve-prod-03`)
   - `/storage/vm-storage`, `/storage/fs-storage` -> `DatastoreUser` (`Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit`)
   - `/pool` -> `PVEPoolAdmin,PVEVMAdmin,PVESDNAdmin` (`propagate=1` — newly created `/pool/<rangeID>` and `/pool/SHARED` automatically inherit permissions without runtime `PUT /access/acl` calls)
   - `/pool/SOC-Range` (and any protected infra pools / VMIDs `107..112, 120, 121, 122`) -> **`NoAccess`** (`propagate=1` — Proxmox itself hard-blocks the token from touching `soc-so-standalone`, `soc-lux`, `ludus-edge`, or `soc-first-proof`)
   - `/sdn/zones/ludus` -> `PVESDNAdmin` (`propagate=1` — allows creating/deleting `r<N>` VNets inside zone `ludus` without runtime `PUT /access/acl` calls)
   - **Zero `User.Modify`, zero `Realm.AllocateUser`, zero `Permissions.Modify`!** Even a full compromise of the `ludus` container cannot create Proxmox users, rotate passwords, alter ACLs, or touch VMs outside Ludus pools on `pve-prod-02`.
2. **Runtime Behavior in `ludus-api` (`proxmox_auth_mode: "service_token"`):**
   - **Startup Verification (`VerifyProxmoxServiceToken`):** Validates `GET /version`, `GET /pools/SHARED`, and `GET /cluster/sdn/zones/ludus` via `PVEAPIToken`; skips `/access/roles`, `/access/groups`, `/access/users`, and `/access/acl` bootstrap mutations.
   - **Zero Proxmox Calls on User Add/Delete/SSO Login:** `AddUser`, `DeleteUser`, and `ProvisionOAuth2User` create/remove the PocketBase user and container workspace in `<5ms` without calling Proxmox `/access/users` or `/access/password`.
   - **Unified Token Resolution:** `GetGoProxmoxClientForUserUsingToken()`, `dynamic-inventory`, Ansible `api_token_id`/`api_token_secret`, Packer `PROXMOX_USERNAME`/`PROXMOX_TOKEN`, and `/vm/console/view` all resolve the shared `ludus-svc@pve!controller` token after PocketBase `HasRangeAccess()` / `isAdmin` authorization succeeds.
   - **Clean Range Pool & SDN VNet Lifecycle:** `CreateRange`, `DeleteRange`, and `createRangeNetworkInZone` still organize every range into its own Proxmox pool (`/pools/<rangeID>`) and SDN VNet (`r<N>`), while skipping per-user `/access/acl` writes.
   - **Backward Compatibility:** Setting `proxmox_auth_mode: "per_user_pve"` preserves `Option 2`'s per-user `@pve` behavior if ever needed on standalone deployments.

---

### 3.3 Userspace Proxy Bridge (`ludus` <-> `ludus-edge:8444` over Pinned mTLS 1.3)

To preserve **zero host/LAN static routes** on `sophon-infravm` and `10.0.20.0/24` while supporting 100% of Ludus's provisioning tools inside an unprivileged `cap_drop: ALL` container, we build a ~250-line zero-dependency Go binary (`cmd/ludus-edge-proxy` + client package in `ludus-api/edgeproxy`):

#### Protocol & Security Boundary
- **Transport:** TCP `:8444` on `ludus-edge` (`10.0.20.181`), TLS 1.3 **mutual TLS (`RequireAndVerifyClientCert`)** pinned to a dedicated `ludus-edge-ca.crt` (`ludus-controller` client cert <-> `ludus-edge` server cert). Unauthenticated probes on `10.0.20.0/24` fail at the TLS handshake, and `ludus-edge` `nftables` restricts `:8444/tcp` to `EDGE_ALLOWED_CLIENT_CIDRS` (e.g., `sophon-infravm` IP).
- **Strict Destination Allowlist Enforced by `ludus-edge-proxy`:**
  - `DIAL <ip>:<port>\n`: `ludus-edge-proxy` parses `<ip>` via `net/netip` and **only** dials destinations inside:
    - `192.0.2.0/24` (excluding `192.0.2.254` itself unless DNS `:53`, so Ludus cannot hit `ludus-edge` services)
    - `10.1.0.0/16` through `10.254.0.0/16`
  - Explicitly **rejects** `10.0.0.0/16` (`vmbr0` LAN), `127.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, IPv6 link-local, and DNS hostnames pointing outside range space. Even if the `ludus` container were compromised, `ludus-edge-proxy` **cannot** be used to pivot onto `vmbr0` or `ludus-edge` localhost.
- **Reverse Listener for Packer Linux Preseed (`LISTEN <port>\n`):**
  - Only ports in `8350..8399` may be requested, bound **strictly** to `192.0.2.254:<port>` (on `ludusnat`).
  - While `packer build` runs inside the `ludus` container (`127.0.0.1:<port>`), `ludus` holds a `LISTEN <port>` mTLS control stream open. Each HTTP `GET /debian-13-preseed.cfg` from the installing VM (`192.0.2.5x`) triggers a reverse stream back to `127.0.0.1:<port>` inside the `ludus` container.
  - When `packer build` finishes, aborts, or crashes, EOF on the control stream immediately closes `192.0.2.254:<port>` on `ludus-edge` — **zero** `ludusnat -> 10.0.20.0/24` packets ever cross the firewall, and **zero** manual `soc-packer-http-window.sh` toggles are required.

#### How Every Tool Inside `ludus` Container Uses `127.0.0.1:1080`
`ludus-server` starts an in-process dual-protocol listener on `127.0.0.1:1080` (auto-detecting SOCKS5 `0x05` vs HTTP `CONNECT` `'C'` on the first byte and forwarding matching range CIDRs over mTLS to `ludus-edge:8444`):

| Tool inside `ludus` Container | Target | Mechanism (Zero `CAP_NET_ADMIN`) |
|---|---|---|
| `ludus-server` / `dynamic-inventory` / `proxmox_kvm` | `https://10.0.20.12:8006` | Direct TCP (matched by `NO_PROXY=127.0.0.1,localhost,10.0.20.0/24,.<domain>`) |
| `ansible-playbook` (`ssh` to Linux/macOS routers & VMs) | `192.0.2.x:22`, `10.N.V.H:22` | `ansible_ssh_common_args` injects `-o ProxyCommand='ludus-proxy-dial %h %p'` (or `nc -X 5 -x 127.0.0.1:1080 %h %p`) |
| `ansible-playbook` (`pywinrm` to Windows VMs) | `10.N.V.H:5985/5986` | `HTTP_PROXY=http://127.0.0.1:1080` + `HTTPS_PROXY=http://127.0.0.1:1080` (native `requests` HTTP `CONNECT` tunnel) |
| Custom Ansible local tasks / Python scripts (`ldap3`, `impacket`, `curl`) | `10.N.V.H:*` | `proxychains4` (`LD_PRELOAD=libproxychains4.so`) configured with `localnet` bypass for `127.0.0.0/8` & `10.0.20.0/24`, routing `192.0.2.0/24` & `10.0.0.0/8` -> `socks5 127.0.0.1 1080` |
| HashiCorp `packer` (`communicator = "ssh"`) | `192.0.2.5x:22` | Native HCL vars `ssh_proxy_host = "127.0.0.1"`, `ssh_proxy_port = 1080` |
| HashiCorp `packer` (`communicator = "winrm"`) | `192.0.2.5x:5986` | Native Packer `winrm` `HTTPS_PROXY=http://127.0.0.1:1080` + `NO_PROXY=10.0.20.0/24,127.0.0.1` |
| HashiCorp `packer` (Linux HTTP preseed server) | `192.0.2.254:8350–8360` | Packer binds `http_bind_address = "127.0.0.1"`, passes `http_ip = "192.0.2.254"`, and `ludus` opens temporary `LISTEN <port>` reverse forward on `ludus-edge` |

---

### 3.4 Pre-Allocated Deterministic WireGuard Pool on `ludus-edge` (`:51820/udp`)

To run `wg0` directly on `ludus-edge` (`10.0.20.181:51820`) with **zero runtime network sync** and **cryptographic least privilege**:

1. **One-Time Provisioning Generator (`ludus-edge-keygen` / `ludus-server --gen-edge-bundle`):**
   - Generates:
     - `ServerPrivateKey` + `ServerPublicKey` (Curve25519).
     - Random 32-byte `ClientPoolSeed`.
     - For each `slot` in `1..250`: derives deterministic client private key via `HKDF-SHA256(ClientPoolSeed, salt="ludus-wg-pool-v1", info="client-slot:<slot>")` + RFC 7748 X25519 scalar clamping (`k[0] &= 248; k[31] = (k[31] & 127) | 64`) and computes `ClientPublicKey = curve25519.ScalarBaseMult(ClientPrivateKey)`.
2. **Least-Privilege Split of Artifacts:**
   - **`ludus-edge` (`/etc/wireguard/wg0.conf`, `0600`):** Receives `ServerPrivateKey` and 250 `[Peer]` stanzas containing **only** `PublicKey = <ClientPublicKey[slot]>` + `AllowedIPs = 198.51.100.<slot>/32`. **`ludus-edge` never stores client private keys.**
   - **`ludus` container (`/etc/ludus/wg-pool.json`, `0400`):** Receives `ServerPublicKey`, `Endpoint` (`10.0.20.181:51820`), and `ClientPoolSeed` (2 fields total). **`ludus` never stores `ludus-edge`'s `ServerPrivateKey`.**
3. **Runtime Lookup in `ludus-api/wireguard.go`:**
   - `getWireGuardConfigForUser(user)` computes `ClientPrivateKey = DeriveWireGuardSlotKey(seed, user.UserNumber())` in O(1) memory with zero disk reads per user and renders the standard client `.conf` (`Address = 198.51.100.<user_number>/32`, `Endpoint = 10.0.20.181:51820`, `AllowedIPs = 198.51.100.1/32, 10.<accessible_ranges>.0.0/16`).
   - Because PocketBase assigns `userNumber` monotonically (`1..250`) and Range Router firewalls (`set-firewall-rules.yml`) explicitly allowlist active users' `198.51.100.<N>/32` IPs per range (while `ludus-edge` `nftables` drops `wg0 -> vmbr0`), deleted user slots have zero LAN or active-range access.

---

### 3.5 Stateless Alpine `ludus-edge` VM & Automatic Day-0 Self-Provisioning via Proxmox `:8006`

`ludus-edge` replaces the heavy 8 GB Debian/Ansible/Packer `ludus-ctrl` VM on `pve-prod-02` with a minimal, immutable **256 MB RAM / 2 vCPU Alpine Linux** appliance (`cpu: x86-64-v2-AES`, pool `ADMIN`), **deployed and upgraded automatically by `ludus-server` over its existing Proxmox `PVEAPIToken` connection (`edge_auto_provision: true`)**:

#### Secret-Free Embedded Appliance ISO + Zero-Manual-Copy Bootstrap
1. **Secret-Free `ludus-edge.iso` Baked Into the `ludus-server` OCI Image (`/opt/ludus/resources/ludus-edge.iso`):**
   - Built during the `Containerfile.ludus` multi-stage image build using the exact same signed-repo Alpine `Containerfile` + deterministic `localhost.apkovl.tar.gz` + `xorriso` pattern as Sophon's `sophon-sftp-server.iso`.
   - Contains **zero secrets** — only Alpine `linux-virt`, `dnsmasq`, `nftables`, `wireguard-tools`, `ludus-edge-proxy`, OpenRC runlevels, and the static `10.<1..153>.0.0/16` route boot script.
2. **Automatic PKI & WireGuard Pool State in `/opt/ludus/db/edge/` (Kopia Backed Up):**
   - When `edge_auto_provision: true` (and manual override files are omitted), `ludus-server` automatically generates and persists in `/opt/ludus/db/edge/` (`0600`):
     - Dedicated `ludus-edge` mTLS 1.3 CA + `edge-server` cert/key + `ludus-controller` client cert/key.
     - 250-slot deterministic HKDF-SHA256 WireGuard `wg_pool.json` + `ludus-edge` `wg0.conf` (`ServerPrivateKey` + 250 client public keys — zero client private keys).
     - Ephemeral Ed25519 one-time enrollment keypair used only during initial `ludus-edge` first-boot sealing.
3. **Day-0 Reconciliation Over Proxmox HTTPS `:8006` (`ludus-api/edge_provision.go`):**
   - Using `ludus-svc@pve!controller` (`PVEVMAdmin` + `PVEPoolAdmin` on `/pool/ADMIN`, `DatastoreUser` on `fs-storage` & `vm-storage`, `PVESDNAdmin` on `/sdn/zones/ludus`, `AccessNetwork` on `/nodes/pve-prod-02`):
     1. Checks whether `ludus-edge` (`edge_vmid` in `/pool/ADMIN`) is `running`, matches the current `ludus-edge.iso` SHA-256 + config digest, and completes an mTLS 1.3 health check on `edge_vm_ip:8444`. If healthy, startup proceeds in `<50ms`.
     2. Otherwise, uploads `/opt/ludus/resources/ludus-edge.iso` to `fs-storage:iso/ludus-edge-<sha12>.iso` (`POST /nodes/pve-prod-02/storage/fs-storage/upload`), creates/reconciles the `ludus-edge` VM in `/pool/ADMIN` with:
        - `ide2`: `fs-storage:iso/ludus-edge-<sha12>.iso,media=cdrom` (read-only live OS in RAM)
        - `virtio0`: `vm-storage:1` (`1 GB` private disk in `/pool/ADMIN` — inaccessible outside `ADMIN` — storing sealed `/var/lib/ludus-edge` state across hypervisor reboots)
        - `ide0`: `vm-storage:cloudinit` with standard API-token-compatible Cloud-Init attributes (`ipconfig0=ip=<edge_vm_ip>/<prefix>,gw=<gw>`, `ipconfig1=ip=192.0.2.254/24`, `nameserver`, `sshkeys=<enrollment_pubkey>` — zero `cicustom` or `root@pam` required)
        - `net0`: `virtio,bridge=vmbr0`, `net1`: `virtio,bridge=ludusnat,mtu=1450`, `onboot=1`
     3. Starts the VM (`POST /nodes/pve-prod-02/qemu/{vmid}/status/start`), performs a single authenticated seal call to `edge_vm_ip:8444` delivering `wg0.conf` + `edge-server` mTLS certs onto `virtio0` (`0600`), permanently locks the bootstrap endpoint, and opens the persistent mTLS proxy channel.
   - **Day-2 Immutability Preserved:** Once sealed, `ludus-edge` requires zero runtime config pushes when users or ranges are added/removed, and survives `pve-prod-02` reboots (`onboot=1`) even if `sophon-infravm` (`pve-prod-01`) is temporarily offline.

#### `ludus-edge` Runtime Specification
- **Interfaces:**
  - `eth0` (`vmbr0`, `10.0.20.181/24`, gateway `10.0.20.1`): accepts only `UDP :51820` (WireGuard) and `TCP :8444` (`ludus-edge-proxy` mTLS from `sophon-infravm`).
  - `eth1` / `ludusnat` (`bridge=ludusnat`, `192.0.2.254/24`, MTU `1450`): L2/L3 cyber-range transit interface.
- **Boot-Time Precomputed Routing (`/etc/local.d/10-ludus-routes.start`):**
  ```sh
  #!/bin/sh
  set -eu
  for n in $(seq 1 153); do
    ip route replace "10.${n}.0.0/16" via "192.0.2.$((100 + n))" dev ludusnat
  done
  ```
- **Services (OpenRC — 4 tiny daemons, <60 MB RSS total):**
  1. `dnsmasq`: bound strictly to `ludusnat` (`bind-interfaces`, `dhcp-range=192.0.2.50,192.0.2.100,255.255.255.0,5m`, upstream DNS forwarder).
  2. `wg-quick.wg0`: static 250-peer `wg0` (`198.51.100.1/24`, `:51820/udp`).
  3. `nftables`: enforces:
     - `ludusnat -> RFC1918` (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`) **DROP** (with `allow_rfc1918_cidrs` CSV exception), guaranteeing range VMs can **never** initiate connections to `sophon-infravm` (`pve-prod-01`) or `pve-prod-02`.
     - `wg0 -> eth0` **DROP**; `wg0 -> ludusnat` **ACCEPT**.
     - `ludusnat -> eth0` (non-RFC1918 internet egress) **`masquerade`**.
  4. `ludus-edge-proxy`: static Go binary running as dedicated unprivileged user `edgeproxy` (binding `:8444` mTLS + ephemeral `192.0.2.254:8350-8399` >1024).

---

### 3.6 Container Image Build & Dual-Registry Publishing (`registry-push.<domain>` + `ghcr.io/cseelhoff`)

Sophon's Pure GitOps engine (`Arcane`) reconciles Compose stacks on `sophon-infravm` by pulling immutable pre-built OCI images through `https://registry.<domain>` rather than running `compose build` on Fedora CoreOS. Both `ludus-server` (bundling `/opt/ludus/resources/ludus-edge.iso`) and `lux` are built and published prior to Compose deployment:

1. **Dual-Target Build & Push Pipeline (`docker/build-and-push.sh` + GitHub Actions `.github/workflows/container-images.yml`):**
   - **Sophon Nexus Hosted Registry (`https://registry-push.<domain>/ludus/ludus-server:<tag>`, `https://registry-push.<domain>/ludus/lux:<tag>`):** Stored in Nexus's `hosted` blob store (**automatically backed up by Sophon Kopia** so `sophon-restore` and air-gapped `standby_restore` drills pull 100% locally via `https://registry.<domain>/ludus/*`).
   - **GitHub Container Registry (`ghcr.io/cseelhoff/ludus-server:<tag>`, `ghcr.io/cseelhoff/ludus-ux:<tag>`):** Automated CI image publishing on `cseelhoff/ludus` and `cseelhoff/ludus-ux` pushes/tags (also transparently cached/mirrored on `sophon-infravm` via Nexus's `ghcr-proxy`).

---

### 3.7 LUX <-> Ludus Pure HTTPS REST & Sophon Keycloak OIDC Integration

Both `ludus` and `lux` deploy onto `sophon-infravm` as Sophon Pure GitOps Compose stacks behind Traefik (`https://ludus.<domain>` and `https://lux.<domain>`) and Keycloak (`https://auth.<domain>/realms/<realm>`):

1. **Declarative Keycloak OIDC Bootstrap in `ludus-api` (`ludus-api/oidc_bootstrap.go`):**
   - Today, configuring OIDC in Ludus requires manually logging into PocketBase's `/_/` superuser UI and pasting client IDs/URLs into SQLite.
   - We add declarative `config.yml` / env configuration (`oidc_enabled`, `oidc_issuer_url`, `oidc_client_id`, `oidc_client_secret_file`, `oidc_display_name`, `oidc_admin_groups`, `oidc_allowed_groups`, `sso_require_existing_user: false`).
   - On startup, `ludus-admin` idempotently configures PocketBase's `users` collection `oauth2.providers` (`oidc`) from `config.yml` and maps Keycloak/OpenLDAP `groups` claims (`ludus-admins` -> `isAdmin: true`, `ludus-operators` -> `isAdmin: false`).
   - Also allow `/api/v2/user/provision-oauth2` internal call to synchronize `isAdmin` from verified OIDC group claims on login.
2. **First-Class Local Fallback + Token Exchange Endpoints (`ludus-api`):**
   - **Local Fallback:** PocketBase already exposes `POST /api/collections/users/auth-with-password` (`{identity, password}` -> `{token: "<PocketBase-JWT>", record: {...}}`), and `ludus-api` middleware already accepts `Authorization: Bearer <PocketBase-JWT>` on every `/api/v2/*` endpoint (including admin routes reverse-proxied from `:8080` -> `127.0.0.1:8081`).
   - **Server-to-Server OIDC Token Exchange for LUX (`POST /api/v2/auth/oidc`):** When a user logs into LUX via Keycloak OIDC PKCE/Auth-Code, LUX verifies or forwards the Keycloak OIDC ID/Access token (or PocketBase OAuth2 code) to `http://ludus:8080` over the internal Podman network and receives a short-lived Ludus PocketBase JWT (`Authorization: Bearer <jwt>`) for that user — auto-provisioning the user's Ludus PocketBase record and container workspace in `<5ms` on first login (with zero Proxmox user/password mutations).
3. **SSH-Free `cseelhoff/ludus-ux` Fork (`lux` Container):**
   - Replace `src/lib/auth-ssh.ts` (`ssh2` login + `~/.bashrc` `LUDUS_API_KEY` scraping) with:
     1. **Keycloak OIDC SSO** (`AUTH_OIDC_ISSUER_URL`, `AUTH_OIDC_CLIENT_ID`, `AUTH_OIDC_CLIENT_SECRET`), exchanging identity with `LUDUS_INTERNAL_URL=http://ludus:8080`.
     2. **Local Ludus Password Fallback** (`POST ${LUDUS_INTERNAL_URL}/api/collections/users/auth-with-password`).
   - Remove `lux-host` root SSH helper, remove `/var/run/docker.sock` mount, and route all `/api/v2/*` calls (including admin endpoints already reverse-proxied by Ludus `:8080`) over internal HTTP/HTTPS with `Authorization: Bearer <ludus_jwt>`.
4. **Sophon Rootless Podman & Kopia Backup Contract:**
   - Containers run with `cap_drop: [ALL]`, `security_opt: ["no-new-privileges:true", "label=disable"]`, `networks: [proxy, ludus-internal]`.
   - Traefik labels expose `https://ludus.<domain>` (`:8080` HTTP/HTTPS behind Traefik) and `https://lux.<domain>` (`:3000`).
   - `sophon.backup.enable=true` labels back up `/opt/ludus/db` (online SQLite `.backup` dump hook via Sophon's `dump-proxy`), `/opt/ludus/ranges`, and `/opt/ludus/users` while excluding reconstructible caches (`.packer_cache`, `.ansible`).

---

## 4. Configuration Contract Additions (`/opt/ludus/config.yml`)

All new settings default `false`/empty so bare-metal Proxmox and `Option 2` single-VM (`VM 122`) deployments remain 100% backward-compatible:

```yaml
# Container + Remote Proxmox mode (rootless Podman / Docker Compose)
remote_proxmox: true
container_mode: true

# Outer Proxmox VE 8/9 HTTPS API (100% PVEAPIToken — zero Proxmox passwords)
proxmox_url: "https://10.0.20.12:8006"
proxmox_node: "pve-prod-02"
proxmox_hostname: "10.0.20.12"
proxmox_pin_to_node: true
proxmox_auth_mode: "service_token"
proxmox_api_token_id: "ludus-svc@pve!controller"
proxmox_api_token_file: "/run/secrets/proxmox_api_token"
reserved_range_numbers: [1]

# Automatic ludus-edge VM deployment & userspace mTLS proxy on pve-prod-02
# (mTLS PKI + 250-slot WireGuard pool auto-generated in /opt/ludus/db/edge/)
edge_auto_provision: true
edge_vmid: 122
edge_vm_name: "ludus-edge"
edge_vm_ip: "10.0.20.181"
edge_vm_cidr_prefix: 24
edge_vm_gateway: "10.0.20.1"
edge_vm_bridge: "vmbr0"
edge_allowed_client_cidrs: ["10.0.20.0/24"]
edge_iso_path: "/opt/ludus/resources/ludus-edge.iso"
edge_proxy_enabled: true
edge_proxy_addr: "10.0.20.181:8444"
edge_local_socks_port: 1080
edge_nat_ip: "192.0.2.254"
packer_http_port_min: 8350
packer_http_port_max: 8360

# Pre-allocated static WireGuard pool (served on ludus-edge :51820/udp)
proxmox_public_ip: "10.0.20.181"
wireguard_port: 51820

# Declarative Keycloak OIDC SSO (with PocketBase local password fallback always available)
oidc_enabled: true
oidc_display_name: "Sophon SSO"
oidc_issuer_url: "https://auth.example.com/realms/sophon"
oidc_client_id: "ludus"
oidc_client_secret_file: "/run/secrets/oidc_client_secret"
oidc_allowed_groups: ["ludus-admins", "ludus-operators"]
oidc_admin_groups: ["ludus-admins"]
sso_require_existing_user: false
```
