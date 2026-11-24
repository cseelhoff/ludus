#!/usr/bin/env bash
# Idempotent one-time bootstrap script run on the target Proxmox VE 8/9 host
# (e.g. pve-prod-02) to provision the least-privilege service API token
# (`ludus-svc@pve!controller`) and base pools/SDN for Ludus Architecture A.
#
# Security guarantees:
#   - Zero PAM user or root@pam password stored by Ludus
#   - Zero Permissions.Modify, User.Modify, Realm.AllocateUser, or Sys.Console privileges
#   - Works on both Proxmox VE 8 and Proxmox VE 9 (dynamically reads PVEVMAdmin's
#     supported VM.* privileges so removed PVE 8 privileges like VM.Monitor never fail on PVE 9)
set -euo pipefail

ROLE_NAME="${ROLE_NAME:-LudusController}"
SVC_USER="${SVC_USER:-ludus-svc@pve}"
TOKEN_NAME="${TOKEN_NAME:-controller}"
SDN_ZONE="${SDN_ZONE:-ludus}"
NAT_VNET="${NAT_VNET:-ludusnat}"
DENY_POOLS="${DENY_POOLS:-SOC-Range}"
DRY_RUN=false
ROTATE_TOKEN=false

usage() {
  cat <<EOF
Usage: $(basename "$0") [options]

Options:
  --dry-run            Print all Proxmox commands without mutating state
  --rotate-token       Delete and re-issue ${SVC_USER}!${TOKEN_NAME} if it already exists
  --role <name>        Custom Proxmox role name (default: ${ROLE_NAME})
  --user <user@pve>    Service principal (default: ${SVC_USER})
  --token <name>       API token name (default: ${TOKEN_NAME})
  --sdn-zone <zone>    Proxmox SDN Simple zone name (default: ${SDN_ZONE})
  --nat-vnet <vnet>    Proxmox SDN NAT VNet name (default: ${NAT_VNET})
  --deny-pools <csv>   Comma-separated pools to protect with NoAccess ACL (default: ${DENY_POOLS})
  -h, --help           Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=true; shift ;;
    --rotate-token) ROTATE_TOKEN=true; shift ;;
    --role) ROLE_NAME="$2"; shift 2 ;;
    --user) SVC_USER="$2"; shift 2 ;;
    --token) TOKEN_NAME="$2"; shift 2 ;;
    --sdn-zone) SDN_ZONE="$2"; shift 2 ;;
    --nat-vnet) NAT_VNET="$2"; shift 2 ;;
    --deny-pools) DENY_POOLS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

run_cmd() {
  if [[ "${DRY_RUN}" == "true" ]]; then
    printf '[dry-run] '
    printf '%q ' "$@"
    printf '\n'
    return 0
  fi
  "$@"
}

if [[ "${DRY_RUN}" == "false" ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: must run as root on the Proxmox VE host (or pass --dry-run)" >&2
    exit 1
  fi
  for bin in pveum pvesh python3; do
    if ! command -v "${bin}" >/dev/null 2>&1; then
      echo "ERROR: required Proxmox command '${bin}' not found in PATH" >&2
      exit 1
    fi
  done
fi

# Resolve VM.* privileges dynamically from built-in PVEVMAdmin on live Proxmox 8/9,
# falling back to standard PVE 9 VM privileges during --dry-run on non-Proxmox hosts.
BASE_PRIVS="Datastore.Allocate,Datastore.AllocateSpace,Datastore.AllocateTemplate,Datastore.Audit,Pool.Allocate,Pool.Audit,SDN.Allocate,SDN.Audit,SDN.Use,Sys.AccessNetwork,Sys.Audit"
DEFAULT_VM_PRIVS="VM.Allocate,VM.Audit,VM.Backup,VM.Clone,VM.Config.CDROM,VM.Config.Cloudinit,VM.Config.CPU,VM.Config.Disk,VM.Config.HWType,VM.Config.Memory,VM.Config.Network,VM.Config.Options,VM.Console,VM.Migrate,VM.PowerMgmt,VM.Snapshot,VM.Snapshot.Rollback"

if command -v pvesh >/dev/null 2>&1 && [[ "${DRY_RUN}" == "false" ]]; then
  VM_PRIVS="$(pvesh get /access/roles/PVEVMAdmin --output-format json | python3 -c 'import json,sys; d=json.load(sys.stdin); print(",".join(sorted(k for k,v in d.items() if v)))')"
else
  VM_PRIVS="${DEFAULT_VM_PRIVS}"
fi

PRIV_LIST="$(python3 -c "import sys; s=set('${BASE_PRIVS}'.split(','))|set('${VM_PRIVS}'.split(',')); s.discard(''); print(','.join(sorted(s)))")"

echo "==> Configuring least-privilege role ${ROLE_NAME}"
if [[ "${DRY_RUN}" == "false" ]] && pvesh get "/access/roles/${ROLE_NAME}" >/dev/null 2>&1; then
  run_cmd pveum role modify "${ROLE_NAME}" -privs "${PRIV_LIST}"
else
  run_cmd pveum role add "${ROLE_NAME}" -privs "${PRIV_LIST}"
fi

echo "==> Ensuring service principal ${SVC_USER} (no password login)"
if [[ "${DRY_RUN}" == "false" ]] && pvesh get "/access/users/${SVC_USER}" >/dev/null 2>&1; then
  run_cmd pveum user modify "${SVC_USER}" -enable 1 -comment "Ludus unprivileged container controller service principal"
else
  run_cmd pveum user add "${SVC_USER}" -enable 1 -comment "Ludus unprivileged container controller service principal"
fi

echo "==> Binding ACL / -> ${SVC_USER} (${ROLE_NAME})"
run_cmd pveum acl modify / -user "${SVC_USER}" -role "${ROLE_NAME}" -propagate 1

for pool_spec in "SHARED:Templates shared with all Ludus users" "ADMIN:VMs managed by the Ludus admin"; do
  pool_id="${pool_spec%%:*}"
  pool_comment="${pool_spec#*:}"
  echo "==> Ensuring resource pool ${pool_id}"
  if [[ "${DRY_RUN}" == "false" ]] && pvesh get "/pools/${pool_id}" >/dev/null 2>&1; then
    echo "    Pool ${pool_id} already exists"
  else
    run_cmd pvesh create /pools --poolid "${pool_id}" --comment "${pool_comment}"
  fi
done

if [[ -n "${DENY_POOLS}" ]]; then
  IFS=',' read -r -a deny_arr <<< "${DENY_POOLS}"
  for dpool in "${deny_arr[@]}"; do
    dpool="$(printf '%s' "${dpool}" | tr -d '[:space:]')"
    [[ -z "${dpool}" ]] && continue
    if [[ "${DRY_RUN}" == "true" ]] || pvesh get "/pools/${dpool}" >/dev/null 2>&1; then
      echo "==> Enforcing NoAccess blast-radius fence on /pool/${dpool} for ${SVC_USER}"
      run_cmd pveum acl modify "/pool/${dpool}" -user "${SVC_USER}" -role NoAccess -propagate 1
    fi
  done
fi

echo "==> Ensuring SDN Simple zone '${SDN_ZONE}' and VNet '${NAT_VNET}'"
if [[ "${DRY_RUN}" == "false" ]] && pvesh get "/cluster/sdn/zones/${SDN_ZONE}" >/dev/null 2>&1; then
  echo "    SDN zone ${SDN_ZONE} already exists"
else
  run_cmd pvesh create /cluster/sdn/zones --zone "${SDN_ZONE}" --type simple
fi

if [[ "${DRY_RUN}" == "false" ]] && pvesh get "/cluster/sdn/vnets/${NAT_VNET}" >/dev/null 2>&1; then
  echo "    SDN VNet ${NAT_VNET} already exists"
else
  run_cmd pvesh create /cluster/sdn/vnets --vnet "${NAT_VNET}" --zone "${SDN_ZONE}" --alias "Ludus shared NAT transit VNet"
fi

echo "==> Applying Proxmox SDN configuration"
run_cmd pvesh set /cluster/sdn

FULL_TOKEN_ID="${SVC_USER}!${TOKEN_NAME}"
TOKEN_EXISTS=false
if [[ "${DRY_RUN}" == "false" ]] && pvesh get "/access/users/${SVC_USER}/token/${TOKEN_NAME}" >/dev/null 2>&1; then
  TOKEN_EXISTS=true
fi

if [[ "${TOKEN_EXISTS}" == "true" && "${ROTATE_TOKEN}" == "false" ]]; then
  echo ""
  echo "==> API token ${FULL_TOKEN_ID} already exists (pass --rotate-token to re-issue)."
  exit 0
fi

if [[ "${TOKEN_EXISTS}" == "true" && "${ROTATE_TOKEN}" == "true" ]]; then
  echo "==> Rotating existing API token ${FULL_TOKEN_ID}"
  run_cmd pveum user token remove "${SVC_USER}" "${TOKEN_NAME}"
fi

echo "==> Creating non-privilege-separated service token ${FULL_TOKEN_ID}"
if [[ "${DRY_RUN}" == "true" ]]; then
  run_cmd pveum user token add "${SVC_USER}" "${TOKEN_NAME}" --privsep 0 --comment "Ludus container controller token" --output-format json
  exit 0
fi

TOKEN_JSON="$(pveum user token add "${SVC_USER}" "${TOKEN_NAME}" --privsep 0 --comment "Ludus container controller token" --output-format json)"
TOKEN_SECRET="$(printf '%s' "${TOKEN_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin)["value"])')"

cat <<EOF

========================================================================
Proxmox Service Token Provisioned Successfully (SAVE THIS SECRET NOW)
========================================================================
LUDUS_PROXMOX_AUTH_MODE=service_token
LUDUS_PROXMOX_API_TOKEN_ID=${FULL_TOKEN_ID}
LUDUS_PROXMOX_API_TOKEN_SECRET=${TOKEN_SECRET}
========================================================================
EOF
