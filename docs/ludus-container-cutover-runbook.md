# Ludus + LUX Container Cutover Runbook (Architecture A)

This runbook covers deploying the rootless containerized **Ludus (`ludus-server`) + LUX (`ludus-ux`)** control plane on **Sophon `infravm`** (`pve-prod-01`) with a self-provisioned stateless Alpine **`ludus-edge`** L2/L3 gateway VM on **`pve-prod-02`**, **Proxmox service API token** authentication (`ludus-svc@pve!controller`), **Sophon Keycloak OIDC SSO** (with PocketBase local password fallback), and clean retirement of legacy Debian controller VM `122` (`ludus-ctrl`).

---

## 1. Topology Summary

| Component | Host | Runtime / Identity | Purpose |
| :--- | :--- | :--- | :--- |
| **`ludus`** (`ludus-server`) | `infravm` (`pve-prod-01`, `10.0.20.11`) | Rootless Podman (`1000:1000`, `cap_drop: [ALL]`) | PocketBase DB, Proxmox `:8006` REST/Packer orchestrator, Ansible runner, WireGuard pool allocator, OIDC + JWT auth |
| **`lux`** (`ludus-ux`) | `infravm` (`pve-prod-01`, `10.0.20.11`) | Rootless Podman (`1000:1000`, `cap_drop: [ALL]`) | Next.js web UI + token-backed noVNC WebSocket proxy (`https://ludus.<domain>`) — zero SSH |
| **`ludus-edge`** (VM `999`) | `pve-prod-02` (`10.0.20.123`) | Auto-provisioned stateless Alpine 3.24 live-ISO VM + 1 GB state disk (`LUDUS_EDGE_STATE`) | Bridges `vmbr0` (`10.0.20.123`) + `ludusnat` (`192.0.2.254/24`), runs `nftables` NAT/isolation, `dnsmasq`, `wg0` (`:51820/udp`), and mTLS 1.3 `ludus-edge-proxy` (`:8444/tcp`) |

---

## 2. Step 1 — One-Time Proxmox Service Token Bootstrap (`pve-prod-02`)

Copy and execute `docker/proxmox-bootstrap-token.sh` once as `root` on `pve-prod-02` (`10.0.20.12`).

```bash
# Preview actions first without modifying Proxmox state:
scp docker/proxmox-bootstrap-token.sh root@10.0.20.12:/tmp/
ssh root@10.0.20.12 'bash /tmp/proxmox-bootstrap-token.sh --dry-run'

# Execute bootstrap and capture LUDUS_PROXMOX_API_TOKEN_SECRET:
ssh root@10.0.20.12 'bash /tmp/proxmox-bootstrap-token.sh && rm -f /tmp/proxmox-bootstrap-token.sh'
```

What this script configures idempotently:
1. Role `LudusController` (`VM.*` + `SDN.*` + `Pool.*` + `Datastore.*` + `Sys.Audit` + `Sys.AccessNetwork`; **no** `Permissions.Modify`, `User.Modify`, `Realm.AllocateUser`, or `Sys.Console`).
2. User `ludus-svc@pve` (no password login) + ACL `/` -> `LudusController` (`propagate=1`).
3. Resource pools `SHARED` and `ADMIN`.
4. Proxmox SDN Simple zone `ludus` + shared transit VNet `ludusnat`.
5. Non-privilege-separated token `ludus-svc@pve!controller` (`privsep=0`).

---

## 3. Step 2 — Configure Keycloak OIDC Clients (`sophon` Realm)

Create two confidential OpenID Connect clients in the Sophon Keycloak realm (`https://auth.<domain>/realms/sophon`):

1. **`ludus-api`** (PocketBase OIDC provider + CLI SSO + JWT audience):
   - **Client authentication**: `On` (confidential)
   - **Standard flow**: `On`
   - **Valid redirect URIs**:
     - `https://ludus-api.<domain>/api/oauth2-redirect`
     - `http://127.0.0.1:*/callback` (optional future CLI PKCE helper)
   - **Group Mapper**: Add a `Group Membership` mapper with **Token Claim Name** = `groups` (Full group path `Off`), included in **ID token**, **Access token**, and **UserInfo**.
   - Create/assign Keycloak groups:
     - `ludus-admins` -> auto-provisioned in Ludus with `isAdmin=true`
     - `ludus-users` -> auto-provisioned in Ludus as standard range owners

2. **`lux`** (LUX web UI OIDC Authorization Code + PKCE S256 client):
   - **Client authentication**: `On` (confidential)
   - **Standard flow**: `On` (`PKCE Code Challenge Method`: `S256`)
   - **Valid redirect URIs**:
     - `https://ludus.<domain>/api/auth/oidc/callback`
   - **Web origins**:
     - `https://ludus.<domain>`
   - **Audience / Group Mapper**:
     - Add the same `groups` mapper (`ludus-admins`, `ludus-users`).
     - Ensure `ludus-api` is included in `aud` (via an `Audience` protocol mapper for `ludus-api`, or share the `ludus-api` client ID if preferred) so LUX can exchange the Keycloak token at `POST /api/v2/auth/oidc/exchange` for a scoped Ludus `luds.` JWT.

---

## 4. Step 3 — Build & Push OCI Images (Nexus + GHCR)

From your workstation with `/home/caleb/ludus` and `/home/caleb/ludus-ux` checked out side-by-side:

```bash
cd /home/caleb/ludus

# Log in to Sophon Nexus push endpoint and GHCR:
podman login registry-push.<domain>
podman login ghcr.io

# Build both images (including deterministic Alpine ludus-edge.iso) and push to both registries:
./docker/build-and-push.sh --sophon-domain <domain> --tag 2.0.0
```

Sophon `infravm` pulls from `registry.<domain>/ludus/{ludus-server,lux}:2.0.0`.

---

## 5. Step 4 — Deploy Stack on Sophon `infravm`

On `infravm` (under the unprivileged service user running rootless Podman + Traefik `proxy` network):

```bash
mkdir -p ~/stacks/ludus
cp docker/sophon-compose.yml ~/stacks/ludus/docker-compose.yml
cp docker/.env.example ~/stacks/ludus/.env
chmod 0600 ~/stacks/ludus/.env
```

Populate `~/stacks/ludus/.env`:
- `SOPHON_DOMAIN`, `INFRAVM_IP`, `IMAGE_TAG=2.0.0`
- `LUDUS_PROXMOX_API_TOKEN_SECRET=<secret from Step 1>`
- `LUDUS_ENCRYPTION_KEY=$(openssl rand -base64 32)`
- `LUX_APP_SECRET=$(openssl rand -hex 32)`
- `LUDUS_ADMIN_EMAIL` & `LUDUS_ADMIN_PASSWORD` (local emergency break-glass admin)
- `LUDUS_OIDC_CLIENT_SECRET` & `LUX_OIDC_CLIENT_SECRET`
- `LUDUS_EDGE_VM_IP=10.0.20.123` / `LUDUS_EDGE_VM_CIDR=10.0.20.123/24` / `LUDUS_EDGE_VM_GATEWAY=10.0.20.1` (an unused management IP on `pve-prod-02`'s `vmbr0` subnet)

Start the stack:

```bash
cd ~/stacks/ludus
podman compose up -d
podman logs -f ludus
```

Expected first-boot sequence in `podman logs ludus`:
1. `ludus-entrypoint.sh` seeds `/opt/ludus/resources/ludus-edge.iso`, Packer plugins, global Ansible collections/roles, and renders `/opt/ludus/config.yml` (`0600`).
2. `VerifyProxmoxServiceToken` verifies Proxmox VE 8/9 API connectivity over `:8006` and ensures `/pool/SHARED`, `/pool/ADMIN`, SDN zone `ludus`, and `ludusnat`.
3. `ReconcileEdgeVMAndProxy` uploads `ludus-edge.iso` to `pve-prod-02`, creates & boots VM `999` (`ludus-edge`), generates an ephemeral mTLS 1.3 Root CA + client/server certs in `/opt/ludus/edge/pki/`, and seals `https://10.0.20.123:8444/v1/bootstrap` over mTLS 1.3.
4. `ludus-admin` (`127.0.0.1:8081`) runs PocketBase migrations, seeds emergency admin `CA`, registers Keycloak OIDC, and starts `ludus` user API (`0.0.0.0:8080`).

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
