#!/bin/sh
# Non-root (1000:1000) entrypoint for ludus-server OCI container mode.
# Synchronizes immutable image-baked assets (ludus-edge.iso, Packer plugins,
# global Ansible roles/collections, and Windows SSH Ansible venv) into /opt/ludus
# across empty volumes and image upgrades, optionally renders /opt/ludus/config.yml
# from /etc/ludus/config.yml or LUDUS_PROXMOX_* environment variables, and
# execs ludus-server --container under tini.
set -eu

LUDUS_DIR="${LUDUS_INSTALL_PATH:-/opt/ludus}"
SEED_DIR="/usr/share/ludus-seed"
IMAGE_BUILD_ID=""
if [ -f "${SEED_DIR}/build-id" ]; then
    IMAGE_BUILD_ID="$(cat "${SEED_DIR}/build-id")"
fi

CURRENT_SEED_ID=""
if [ -f "${LUDUS_DIR}/.image-seed-id" ]; then
    CURRENT_SEED_ID="$(cat "${LUDUS_DIR}/.image-seed-id" 2>/dev/null || true)"
fi

mkdir -p \
    "${LUDUS_DIR}/resources/packer" \
    "${LUDUS_DIR}/resources/global-collections" \
    "${LUDUS_DIR}/resources/global-roles" \
    "${LUDUS_DIR}/runtimes"

# Refresh image-baked assets on first boot or whenever the container image changes.
if [ "${IMAGE_BUILD_ID}" != "${CURRENT_SEED_ID}" ] || [ ! -f "${LUDUS_DIR}/resources/ludus-edge.iso" ]; then
    if [ -f "${SEED_DIR}/resources/ludus-edge.iso" ]; then
        cp -f "${SEED_DIR}/resources/ludus-edge.iso" "${LUDUS_DIR}/resources/ludus-edge.iso"
    fi
    if [ -d "${SEED_DIR}/resources/packer/plugins" ]; then
        rm -rf "${LUDUS_DIR}/resources/packer/plugins"
        cp -a "${SEED_DIR}/resources/packer/plugins" "${LUDUS_DIR}/resources/packer/plugins"
    fi
    if [ -d "${SEED_DIR}/resources/global-collections" ]; then
        cp -a "${SEED_DIR}/resources/global-collections/." "${LUDUS_DIR}/resources/global-collections/"
    fi
    if [ -d "${SEED_DIR}/resources/global-roles" ]; then
        cp -a "${SEED_DIR}/resources/global-roles/." "${LUDUS_DIR}/resources/global-roles/"
    fi
    # Clear extracted embedded playbooks on image upgrade so ludus-server re-extracts
    # the matching embedded ansible/, packer/, and ci/ trees on startup.
    if [ -n "${CURRENT_SEED_ID}" ] && [ "${IMAGE_BUILD_ID}" != "${CURRENT_SEED_ID}" ]; then
        rm -rf "${LUDUS_DIR}/ansible" "${LUDUS_DIR}/packer" "${LUDUS_DIR}/ci"
    fi
    if [ -n "${IMAGE_BUILD_ID}" ]; then
        printf '%s\n' "${IMAGE_BUILD_ID}" > "${LUDUS_DIR}/.image-seed-id"
    fi
fi

if [ -d "${SEED_DIR}/runtimes/ansible-windows-ssh" ] && [ ! -e "${LUDUS_DIR}/runtimes/ansible-windows-ssh" ]; then
    ln -s "${SEED_DIR}/runtimes/ansible-windows-ssh" "${LUDUS_DIR}/runtimes/ansible-windows-ssh"
fi

# Stage /opt/ludus/config.yml from /etc/ludus/config.yml (read-only secret mount)
# or synthesize from LUDUS_* environment variables when no config.yml is present.
if [ -f "/etc/ludus/config.yml" ] && [ ! -f "${LUDUS_DIR}/config.yml" ]; then
    cp "/etc/ludus/config.yml" "${LUDUS_DIR}/config.yml"
    chmod 0600 "${LUDUS_DIR}/config.yml" 2>/dev/null || true
elif [ -f "/etc/ludus/config.yml" ] && [ -w "${LUDUS_DIR}/config.yml" ]; then
    cp "/etc/ludus/config.yml" "${LUDUS_DIR}/config.yml"
    chmod 0600 "${LUDUS_DIR}/config.yml" 2>/dev/null || true
elif [ ! -f "${LUDUS_DIR}/config.yml" ] && [ -n "${LUDUS_PROXMOX_URL:-}" ]; then
    python3 - "${LUDUS_DIR}/config.yml" <<'PY'
import os, sys, yaml

def env_bool(name, default):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")

def env_int(name, default):
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw.strip())

def read_secret(val_env, file_env):
    fpath = os.environ.get(file_env, "").strip()
    if fpath:
        with open(fpath, "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return os.environ.get(val_env, "").strip()

def write_secret_file(path, value):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(value)
    os.chmod(path, 0o600)
    return path

secrets_dir = "/opt/ludus/db/.secrets"

pve_token_file = os.environ.get("LUDUS_PROXMOX_API_TOKEN_SECRET_FILE", "").strip()
pve_token_secret = os.environ.get("LUDUS_PROXMOX_API_TOKEN_SECRET", "").strip()
if not pve_token_file and pve_token_secret:
    pve_token_file = write_secret_file(os.path.join(secrets_dir, "proxmox-api-token"), pve_token_secret)

oidc_secret_file = os.environ.get("LUDUS_OIDC_CLIENT_SECRET_FILE", "").strip()
oidc_secret = os.environ.get("LUDUS_OIDC_CLIENT_SECRET", "").strip()
if not oidc_secret_file and oidc_secret:
    oidc_secret_file = write_secret_file(os.path.join(secrets_dir, "oidc-client-secret"), oidc_secret)

db_enc_key = read_secret("LUDUS_DATABASE_ENCRYPTION_KEY", "LUDUS_DATABASE_ENCRYPTION_KEY_FILE")
if not db_enc_key:
    db_enc_key = read_secret("LUDUS_ENCRYPTION_KEY", "LUDUS_ENCRYPTION_KEY_FILE")

reserved_raw = os.environ.get("LUDUS_RESERVED_RANGE_NUMBERS", "").strip()
reserved_ranges = [int(x.strip()) for x in reserved_raw.split(",") if x.strip()] if reserved_raw else []

allowed_groups_raw = os.environ.get("LUDUS_OIDC_ALLOWED_GROUPS", os.environ.get("LUDUS_OIDC_USER_GROUPS", "")).strip()
allowed_groups = [g.strip() for g in allowed_groups_raw.split(",") if g.strip()]

extra_aud_raw = os.environ.get("LUDUS_OIDC_EXTRA_AUDIENCES", "").strip()
extra_audiences = [a.strip() for a in extra_aud_raw.split(",") if a.strip()]

edge_cidr_raw = os.environ.get("LUDUS_EDGE_VM_CIDR_PREFIX", "").strip()
if not edge_cidr_raw and "/" in os.environ.get("LUDUS_EDGE_VM_CIDR", ""):
    edge_cidr_raw = os.environ["LUDUS_EDGE_VM_CIDR"].rsplit("/", 1)[-1].strip()
edge_cidr_prefix = int(edge_cidr_raw) if edge_cidr_raw else 24

cfg = {
    "container_mode": True,
    "remote_proxmox": True,
    "tls_enabled": env_bool("LUDUS_TLS_ENABLED", False),
    "port": env_int("LUDUS_PORT", 8080),
    "admin_port": env_int("LUDUS_ADMIN_PORT", 8081),
    "expose_admin_port": env_bool("LUDUS_EXPOSE_ADMIN_PORT", False),
    "proxmox_pin_to_node": env_bool("LUDUS_PROXMOX_PIN_TO_NODE", True),
    "prevent_user_ansible_add": env_bool("LUDUS_PREVENT_USER_ANSIBLE_ADD", True),
    "create_default_range": env_bool("LUDUS_CREATE_DEFAULT_RANGE", False),
    "register_default_source": env_bool("LUDUS_REGISTER_DEFAULT_SOURCE", False),
    "sync_sources_on_startup": env_bool("LUDUS_SYNC_SOURCES_ON_STARTUP", False),
    "proxmox_auth_mode": os.environ.get("LUDUS_PROXMOX_AUTH_MODE", "service_token"),
    "proxmox_url": os.environ["LUDUS_PROXMOX_URL"].strip(),
    "proxmox_node": os.environ.get("LUDUS_PROXMOX_NODE", "pve-prod-02").strip(),
    "proxmox_hostname": os.environ.get("LUDUS_PROXMOX_HOSTNAME", os.environ.get("LUDUS_PROXMOX_NODE", "pve-prod-02")).strip(),
    "proxmox_public_ip": os.environ.get("LUDUS_PROXMOX_PUBLIC_IP", "").strip(),
    "proxmox_interface": os.environ.get("LUDUS_PROXMOX_INTERFACE", "vmbr0").strip(),
    "proxmox_local_ip": os.environ.get("LUDUS_PROXMOX_LOCAL_IP", "").strip(),
    "proxmox_gateway": os.environ.get("LUDUS_PROXMOX_GATEWAY", "").strip(),
    "proxmox_netmask": os.environ.get("LUDUS_PROXMOX_NETMASK", "255.255.255.0").strip(),
    "proxmox_vm_storage_pool": os.environ.get("LUDUS_PROXMOX_VM_STORAGE_POOL", "local-lvm").strip(),
    "proxmox_vm_storage_format": os.environ.get("LUDUS_PROXMOX_VM_STORAGE_FORMAT", "raw").strip(),
    "proxmox_iso_storage_pool": os.environ.get("LUDUS_PROXMOX_ISO_STORAGE_POOL", "local").strip(),
    "proxmox_invalid_cert": env_bool("LUDUS_PROXMOX_INVALID_CERT", True),
    "proxmox_api_token_id": os.environ.get("LUDUS_PROXMOX_API_TOKEN_ID", "ludus-svc@pve!controller").strip(),
    "proxmox_api_token_file": pve_token_file,
    "database_encryption_key": db_enc_key,
    "ludus_nat_interface": os.environ.get("LUDUS_NAT_INTERFACE", "ludusnat").strip(),
    "sdn_zone": os.environ.get("LUDUS_SDN_ZONE", os.environ.get("LUDUS_SDN_ZONE_NAME", "ludus")).strip(),
    "edge_proxy_enabled": env_bool("LUDUS_EDGE_PROXY_ENABLED", True),
    "edge_auto_provision": env_bool("LUDUS_EDGE_AUTO_PROVISION", True),
    "edge_vmid": env_int("LUDUS_EDGE_VMID", env_int("LUDUS_EDGE_VM_ID", 123)),
    "edge_vm_name": os.environ.get("LUDUS_EDGE_VM_NAME", "ludus-edge").strip(),
    "edge_vm_ip": os.environ.get("LUDUS_EDGE_VM_IP", "").strip(),
    "edge_vm_cidr_prefix": edge_cidr_prefix,
    "edge_vm_gateway": os.environ.get("LUDUS_EDGE_VM_GATEWAY", "").strip(),
    "edge_vm_bridge": os.environ.get("LUDUS_EDGE_VM_BRIDGE", "vmbr0").strip(),
    "edge_nat_ip": os.environ.get("LUDUS_EDGE_NAT_IP", "192.0.2.254").strip(),
    "edge_nat_mac": os.environ.get("LUDUS_EDGE_NAT_MAC", "").strip(),
    "packer_http_port_min": env_int("LUDUS_PACKER_HTTP_PORT_MIN", 8350),
    "packer_http_port_max": env_int("LUDUS_PACKER_HTTP_PORT_MAX", 8360),
    "oidc_enabled": env_bool("LUDUS_OIDC_ENABLED", False),
    "oidc_issuer_url": os.environ.get("LUDUS_OIDC_ISSUER_URL", "").strip(),
    "oidc_client_id": os.environ.get("LUDUS_OIDC_CLIENT_ID", "").strip(),
    "oidc_client_secret_file": oidc_secret_file,
    "oidc_skip_tls_verify": env_bool("LUDUS_OIDC_SKIP_TLS_VERIFY", False),
    "oidc_display_name": os.environ.get("LUDUS_OIDC_DISPLAY_NAME", "Sophon SSO").strip(),
    "oidc_admin_groups": [g.strip() for g in os.environ.get("LUDUS_OIDC_ADMIN_GROUPS", "ludus-admins").split(",") if g.strip()],
    "sso_require_existing_user": env_bool("LUDUS_SSO_REQUIRE_EXISTING_USER", False),
}

if os.environ.get("LUDUS_CLUSTER_MODE", "").strip() != "":
    cfg["cluster_mode"] = env_bool("LUDUS_CLUSTER_MODE", True)
if reserved_ranges:
    cfg["reserved_range_numbers"] = reserved_ranges
if allowed_groups:
    cfg["oidc_allowed_groups"] = allowed_groups
if extra_audiences:
    cfg["oidc_extra_audiences"] = extra_audiences

# Drop empty optional strings so ApplyRemoteProxmoxDefaults fills canonical defaults.
clean = {k: v for k, v in cfg.items() if v != ""}
out_path = sys.argv[1]
with open(out_path, "w", encoding="utf-8") as fh:
    yaml.safe_dump(clean, fh, default_flow_style=False, sort_keys=False)
os.chmod(out_path, 0o600)
PY
fi

if [ "$#" -gt 0 ]; then
    case "$1" in
        --* )
            exec /usr/local/bin/ludus-server --container "$@"
            ;;
        * )
            exec "$@"
            ;;
    esac
fi

exec /usr/local/bin/ludus-server --container
