# Ludus + LUX Container Cutover Runbook (Architecture A)

This runbook covers deploying the rootless containerized **Ludus (`ludus-server`) + LUX (`ludus-ux`)** control plane on **Sophon `infravm`** (`pve-prod-01`) with a self-provisioned stateless Alpine **`ludus-edge`** L2/L3 gateway VM on **`pve-prod-02`**, **Proxmox service API token** authentication (`ludus-svc@pve!controller`), **Sophon Keycloak OIDC SSO** (with PocketBase local password fallback), and clean retirement of legacy Debian controller VM `122` (`ludus-ctrl`).

---

## 1. Topology Summary

| Component | Host | Runtime / Identity | Purpose |
| :--- | :--- | :--- | :--- |
| **`ludus`** (`ludus-server`) | `sophon-infravm` (`pve-prod-01`, `10.0.60.3`) | Rootless Podman (`1000:1000`, `cap_drop: [ALL]`) | PocketBase DB, Proxmox `:8006` REST/Packer orchestrator, Ansible runner, WireGuard pool allocator, OIDC + JWT auth (`https://ludus-api.<domain>`) |
| **`lux`** (`ludus-ux`) | `sophon-infravm` (`pve-prod-01`, `10.0.60.3`) | Rootless Podman (`1000:1000`, `cap_drop: [ALL]`) | Next.js web UI + token-backed noVNC WebSocket proxy (`https://ludus.<domain>`) — zero SSH |
| **`ludus-edge`** (VM `123`) | `pve-prod-02` (`10.0.20.182`) | Auto-provisioned stateless Alpine 3.24 live-ISO VM + 1 GB state disk (`LUDUS_EDGE_STATE`) | Bridges `vmbr0` (`10.0.20.182`) + `ludusnat` (`192.0.2.254/24`), runs `nftables` NAT/isolation, `dnsmasq`, `wg0` (`:51820/udp`), and mTLS 1.3 `ludus-edge-proxy` (`:8444/tcp`) |

---

## 2. Step 1 — One-Time Proxmox Service Token & Hub Tap Prep (`pve-prod-02`)

1. Copy and execute `docker/proxmox-bootstrap-token.sh` once as `root` on `pve-prod-02` (`10.0.20.12`):

```bash
scp docker/proxmox-bootstrap-token.sh root@10.0.20.12:/tmp/
ssh root@10.0.20.12 'bash /tmp/proxmox-bootstrap-token.sh --dry-run'
ssh root@10.0.20.12 'bash /tmp/proxmox-bootstrap-token.sh && rm -f /tmp/proxmox-bootstrap-token.sh'
```

What this script configures idempotently:
- Role `LudusController` (`VM.*` + `SDN.*` + `Pool.*` + `Datastore.*` + `Sys.Audit` + `Sys.AccessNetwork`; **no** `Permissions.Modify`, `User.Modify`, `Realm.AllocateUser`, or `Sys.Console`).
- User `ludus-svc@pve` with `PVEAuditor` on `/`, `LudusController` scoped only to `/nodes/pve-prod-02`, `/pool`, `/sdn`, `/storage/vm-storage`, and `/storage/fs-storage`.
- Explicit `NoAccess` blast-radius fences on `/nodes/pve-prod-01`, `/nodes/pve-prod-03`, `/pool/{SOC-Range,soc-first-proof,Internal-Infrastructure,Test-Infrastructure,Range-Infrastructure}`, and `/vms/10000`.
- Resource pools `SHARED` and `ADMIN`, SDN Simple zone `ludus` + transit VNet `ludusnat`, and non-privilege-separated token `ludus-svc@pve!controller` (`privsep=0`, created via `pvesh create ... --output-format json` for Proxmox VE 9.2 compatibility).

2. Before starting `ludus` (which assigns `192.0.2.254/24` on `ludusnat` to `ludus-edge` VM `123`), stop legacy `ludus-ctrl` (`VM 122`) without deleting it (preserving instant rollback) and allow `tap123i1` in `/usr/local/sbin/soc-ludus-ctrl-hub.sh`:

```bash
ssh root@10.0.20.12 '
  qm set 122 --onboot 0
  qm shutdown 122 && qm wait 122
'
```

---

## 3. Step 2 — Configure Unified Keycloak OIDC Client (`sophon` Realm)

Create a single confidential OpenID Connect client **`ludus`** in the Sophon Keycloak realm (`https://auth.<domain>/realms/sophon`) shared by both `ludus-server` and `lux` so ID/access tokens minted for LUX naturally carry `aud: "ludus"`:

- **Client ID**: `ludus`
- **Client authentication**: `On` (confidential)
- **Standard flow**: `On` (`PKCE Code Challenge Method`: `S256`)
- **Valid redirect URIs**:
  - `https://lux.<domain>/api/auth/oidc/callback`
  - `https://ludus.<domain>/sso/callback`
  - `https://ludus.<domain>/api/oauth2-redirect`
  - `http://localhost:19876/callback`
  - `http://127.0.0.1:19876/callback`
- **Valid post logout redirect URIs**:
  - `+`
- **Web origins**:
  - `https://lux.<domain>`
  - `https://ludus.<domain>`
- **Client Scopes / Group Mapper**:
  - Attach the `groups` scope (or a `Group Membership` mapper with **Token Claim Name** = `groups`, Full group path `Off`, included in **ID token**, **Access token**, and **UserInfo**).
  - Create/assign Keycloak groups:
    - `ludus-admins` -> auto-provisioned in Ludus with `isAdmin=true`
    - `ludus-users` -> auto-provisioned in Ludus as standard range owners

---

## 4. Step 3 — Build & Push OCI Images (Sophon Nexus + GHCR)

From your workstation with `/home/caleb/ludus` and `/home/caleb/ludus-ux` checked out side-by-side:

```bash
cd /home/caleb/ludus

# Log in to Sophon Nexus push endpoint (and optionally GHCR):
podman login registry-push.<domain>

# Build both images (including deterministic Alpine ludus-edge.iso) and push:
./docker/build-and-push.sh --sophon-domain <domain> --tag 2.0.0-container --no-ghcr
```

Ensure `registry.<domain>` (`sophon-pull` credentials) is registered in Arcane (**Settings -> Registries**) when `nexus_anonymous_enabled: false`.

---

## 5. Step 4 — Commit `ludus/compose.yaml` to Gitea `ops/workloads` & Sync in Arcane

1. Add `ludus/compose.yaml` (modeled on `docker/sophon-compose.yml`, including `x-sophon-standby: skip` and Kopia v3 `sophon.backup.paths` / `sophon.backup.volumes`) to the Sophon Gitea **`ops/workloads`** repository and push to `main`.
2. In **Arcane** (`https://arcane.<domain>`), create/sync the GitOps stack `ludus` from `ops/workloads` (`ludus/compose.yaml`) and supply the secret environment variables (`.env` / Arcane Environment):
   - `LUDUS_PROXMOX_API_TOKEN_SECRET=<secret from Step 1>`
   - `LUDUS_ENCRYPTION_KEY=<32-char key>`
   - `LUX_APP_SECRET=$(openssl rand -hex 32)`
   - `LUDUS_ADMIN_EMAIL` & `LUDUS_ADMIN_PASSWORD` (local emergency break-glass admin)
   - `LUDUS_OIDC_CLIENT_SECRET=<Keycloak ludus client secret>`

Expected first-boot sequence:
1. `coredns-dockerdiscovery` automatically publishes split-horizon DNS (`10.0.60.3`) and Cloudflare Tunnel routes for `ludus.<domain>` and `ludus-api.<domain>` from Traefik `Host(...)` labels.
2. `ludus-entrypoint.sh` seeds `/opt/ludus/resources/ludus-edge.iso`, Packer plugins, global Ansible collections/roles, and renders `/opt/ludus/config.yml` + `0600` secret files under `/opt/ludus/db/.secrets/`.
3. `VerifyProxmoxServiceToken` verifies Proxmox VE 9 API connectivity over `:8006` and confirms `/pool/SHARED`, `/pool/ADMIN`, SDN zone `ludus`, and `ludusnat`.
4. `ReconcileEdgeVMAndProxy` uploads `ludus-edge.iso` to `fs-storage` on `pve-prod-02`, creates & boots VM `123` (`ludus-edge` at `10.0.20.182` + `192.0.2.254/24`), generates mTLS 1.3 Root CA + client/server certs in `/opt/ludus/db/edge/`, and seals `https://10.0.20.182:8444/v1/bootstrap` over mTLS 1.3.
5. On `pve-prod-02`, re-run `/usr/local/sbin/soc-ludus-ctrl-hub.sh` once VM `123` is up so `tap123i1` is accepted by `soc_range_build_l2`.
6. `ludus-admin` (`127.0.0.1:8081`) runs PocketBase migrations, seeds emergency admin `CA`, registers Keycloak OIDC, and starts `ludus` user API (`0.0.0.0:8080`).

---

## 6. Step 5 — Live Acceptance Checklist

1. **Container Hardening & Health**:
   - `podman ps` shows both `ludus` and `lux` `healthy` running as UID `1000:1000` with `CapEff: 0000000000000000`.
2. **SSO + Local Fallback Auth**:
   - Browse to `https://ludus.<domain>/login`.
   - Verify **"Sign in with Sophon SSO"** redirects to Keycloak (`PKCE S256`), exchanges OIDC token for a Ludus `luds.` JWT, and opens the LUX dashboard with zero SSH prompts.
   - Verify local fallback login (`CA` + `LUDUS_ADMIN_PASSWORD`) works when emergency local login is used.
3. **`ludus-edge` Connectivity & WireGuard**:
   - Create a range user via LUX or `ludus users add`, download their WireGuard profile (`Endpoint = 10.0.20.123:51820`), connect a client, and confirm `198.51.100.1` responds via `ludus-edge`.
4. **Template Build & Range Deployment over `ludus-edge` mTLS Tunnel**:
   - Build or clone a Debian template (`ludus templates build -n debian-12-x64-server-template`) — verify Packer HTTP preseed traffic traverses the `ludus-edge` reverse mTLS listener seamlessly.
   - Deploy a 1-VM range (`ludus range deploy`) — verify `vyos` router + guest VM land in `/pool/<USER>` on `pve-prod-02` and Ansible configures the guest over the `ludus-edge` mTLS SOCKS5/TCP tunnel (`127.0.0.1:1080`).
5. **Browser noVNC Console**:
   - Click **Console** on the deployed VM in LUX -> verify browser noVNC connects directly through `/ws/vnc` -> `GET /api/v2/vm/console/view?ticket=...` -> Proxmox `:8006` `vncwebsocket` with zero Proxmox PAM credentials.
6. **Kopia Backup Verification**:
   - Trigger a Sophon Kopia backup run for group `ludus` and confirm `ludus-pocketbase.sql`, `ludus-ux.sql`, `/opt/ludus/db`, `/opt/ludus/edge/pki`, and `/app/data` are captured cleanly.

---

## 7. Step 6 — Decommission Legacy Debian Controller VM `122` (`ludus-ctrl`)

Once Steps 4–5 are verified:

1. Export any range configs or blueprints you wish to keep from VM `122` (`ludus range config get > range-backup.yml`).
2. Destroy any obsolete test range VMs owned by VM `122` (`ludus range rm`) so no duplicate `192.0.2.<range>` router IPs remain attached to `ludusnat`.
3. On `pve-prod-02`, shut down and remove VM `122` (`ludus-ctrl`):
   ```bash
   ssh root@10.0.20.12 'qm shutdown 122 && qm wait 122 && qm destroy 122 --purge 1 --destroy-unreferenced-disks 1'
   ```
4. Remove any obsolete `@pve` per-user accounts/tokens created during the interim Option 2 VM phase (`pveum user list`), leaving only `ludus-svc@pve!controller`.
