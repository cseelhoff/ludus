# Ludus Containerization & Split Edge Implementation Roadmap (`Architecture A`)

**Companion Architecture Plan:** [Ludus Containerization & Split Edge Architecture Plan](./ludus-container-plan.md)  
**Target Repositories:**
- `/home/caleb/ludus` (`cseelhoff/ludus`, branch `feat/container-architecture`)
- `cseelhoff/ludus-ux` (fork of `ryokubaka/ludus-ux` for pure HTTPS REST + Keycloak OIDC)
- `/mnt/c/Users/caleb/Projects/soc-range` & `/home/caleb/sophon` (Alpine `ludus-edge` provisioner + Sophon GitOps stack)

---

## Phase Roadmap & Milestone Checklist

### Phase 1 — Rootless Container Mode, Proxmox `service_token` Auth & OS Decoupling (`ludus-api` + `ludus-server`)
*Goal: Allow `ludus-server` (both user `:8080` and admin `127.0.0.1:8081` roles) to run inside a single unprivileged rootless Podman/Docker container (`UID 1000`, `cap_drop: ALL`, `no-new-privileges:true`) using a single pre-registered Proxmox API token (`PVEAPIToken`, zero Proxmox passwords, zero per-user `@pve` accounts) and zero `/etc/passwd`, `chown`, `ip route`, or `systemd` calls.*

- [x] **1.1 Config Contract (`ludus-api/config.go`, `ludus-server/ansible/config.yml.example`):**
  - Add `container_mode`, `proxmox_auth_mode` (`"service_token"` | `"per_user_pve"`), `proxmox_api_token_id`, `proxmox_api_token_file`, `edge_proxy_*`, `wireguard_pool_file`, `packer_http_port_min/max`, and `oidc_*` fields with validation and sensible defaults (`container_mode: true` automatically implies `remote_proxmox: true` and defaults `proxmox_auth_mode` to `"service_token"` when `proxmox_api_token_id` is set).
  - Support plain HTTP listener option (`tls_enabled: false` or internal TLS) behind Traefik reverse proxy while keeping `127.0.0.1:8081` admin loopback communication intact.
- [x] **1.2 Single Proxmox Service Token Mode (`ludus-api/proxmox_remote.go`, `proxmox_bootstrap.go`, `proxmox.go`, `api_user_management.go`, `sdn.go`):**
  - Implement `VerifyProxmoxServiceToken(ctx, cfg)` for startup validation (`GET /version`, `GET /pools/SHARED`, `GET /cluster/sdn/zones/<zone>`) without touching `/access/roles`, `/access/groups`, `/access/users`, or `/access/acl` (zero `User.Modify` or `Permissions.Modify` required on Proxmox).
  - Route `GetGoProxmoxClientForUserUsingToken()`, `dynamic-inventory`, Ansible `api_token_id`/`api_token_secret`, Packer `PROXMOX_USERNAME`/`PROXMOX_TOKEN`, and WebSocket VNC `/vm/console/view` through the shared `proxmox_api_token_id` + `proxmox_api_token_file` when `proxmox_auth_mode == "service_token"`.
  - Skip Proxmox `@pve` user creation, password updates (`PUT /access/password`), per-user token minting, and per-range `/access/acl` calls in `service_token` mode (relying on propagated `/pool` and `/sdn/zones/ludus` permissions + PocketBase `HasRangeAccess()` RBAC, and returning a clean message on `ludus user creds`).
- [x] **1.3 Replace `os.Geteuid() == 0` with Explicit `IsAdminProcess()` (`ludus-api/*`, `ludus-server/*`):**
  - Audit and replace all ~25 `os.Geteuid() == 0` / `os.Geteuid() != 0` checks across `middleware.go`, `routers.go`, `database.go`, `ansible.go`, `api_user_management.go`, `api_range_management.go`, `api_migration.go`, `range_auth.go`, `utils.go`, `license.go`, and `plugins.go` with `IsAdminProcess()` (driven by `--admin` flag; defaults to `os.Geteuid() == 0` only when `--admin` is unset in non-container mode).
  - Add `--container` unified entrypoint flag to `ludus-server` that launches the internal `127.0.0.1:8081` admin listener and `0.0.0.0:8080` public listener cleanly with coordinated signal shutdown (`SIGTERM`/`SIGINT`).
- [x] **1.4 Pure-Go User Workspaces & Container Guards (`ludus-api/container_user.go`, `filesystem.go`, `sdn.go`, `ludus-server/update.go`):**
  - Implement `provisionContainerUserWorkspace()` and `removeContainerUserWorkspace()` in pure Go (replaces `add-user.yml` / `del-user.yml` when `container_mode: true`): creates `/opt/ludus/users/<username>/{packer/tmp,.ansible}`, links pre-baked `/opt/ludus/resources/ansible-cache`, and writes default `range-config.yml`.
  - Make `chownFileToUsername()`, `chownDirToUsernameRecursive()`, `setRangeDirPermissions()`, and `userExistsOnHostSystem()` safe container-mode no-ops (`chmod`-only, single container UID).
  - Skip kernel `ip route` / `/etc/network/if-up.d/sdn-routes` mutations in `sdn.go` when `container_mode: true` or `edge_proxy_enabled: true`.
  - Guard `ludus-server --update` in `update.go` when `container_mode: true`.
- [x] **1.5 Unit Tests (`ludus-api/container_mode_test.go`, `proxmox_remote_test.go`):**
  - Verify `service_token` mode performs zero `/access/users`, `/access/password`, or `/access/acl` calls across startup, user CRUD, and range CRUD; verify non-root (`UID != 0`) admin + user routing, pure-Go user workspace lifecycle, and zero host shell execution (`adduser`, `ip route`, `chown`, `systemctl`).

---

### Phase 2 — Deterministic Pre-Allocated WireGuard Pool (`ludus-api/wireguard_pool.go`)
*Goal: Run WireGuard (`:51820/udp`) natively at 1-hop wire speed on `ludus-edge` with zero runtime sync between `ludus` and `ludus-edge` and strict cryptographic key separation.*

- [x] **2.1 Deterministic HKDF X25519 Pool Generator (`ludus-api/wireguard_pool.go`):**
  - Implement `DeriveWireGuardSlotKey(clientPoolSeed []byte, slot int)` using `crypto/hkdf` (`SHA-256`, domain separator `"ludus-wg-pool-v1"`) + RFC 7748 Curve25519 clamping + `golang.org/x/crypto/curve25519`.
  - Implement `GenerateEdgeWireGuardBundle(endpoint string, maxSlots int)` CLI subcommand (`ludus-server --gen-wg-pool`) emitting:
    1. `wg0.conf` for `ludus-edge` (`ServerPrivateKey` + `2..250` `[Peer]` public keys `198.51.100.<2..250>/32` with `198.51.100.1/24` reserved for `wg0` `[Interface]` — **zero client private keys**).
    2. `wg_pool.json` for `ludus` (`ServerPublicKey`, `Endpoint`, `ClientPoolSeed`, `MaxSlots` — **zero server private key**).
- [x] **2.2 Wire `getWireGuardConfigForUser()` to Pool (`ludus-api/wireguard.go`):**
  - When `wireguard_pool_file` is configured (or `container_mode: true`), derive `user.UserNumber()`'s client keypair directly in memory instead of reading `/etc/wireguard/<id>-client-private-key`, and allocate monotonic non-recycled user slots (`AllocateMonotonicWireGuardUserSlot`).
- [x] **2.3 Unit Tests (`ludus-api/wireguard_pool_test.go`):**
  - Verify deterministic key derivation, Curve25519 public-key match between `ludus`'s derived client config and `ludus-edge`'s generated `wg0.conf`, slot bounds (`2..250`), monotonic slot allocation, and zero secret leakage across the two artifacts.

---

### Phase 3 — Userspace mTLS Edge Proxy, Self-Provisioning `ludus-edge` & Packer/Ansible Wiring
*Goal: Have `ludus-server` automatically deploy/seal `ludus-edge` on Proxmox over `:8006` (`edge_auto_provision: true`) and tunnel all Ansible SSH/WinRM, custom role tools, and Packer SSH/WinRM/HTTP preseed traffic through `ludus -> ludus-edge:8444` mTLS 1.3 with zero host/LAN static routes.*

- [x] **3.1 `ludus-edge-proxy` Server & `edgeproxy` Client Package (`ludus-api/edgeproxy/` + `ludus-server/cmd/ludus-edge-proxy/`):**
  - Server (`ludus-edge-proxy` static Linux/amd64 binary for Alpine):
    - Zero-private-key first-boot enrollment (`ENROLL_CSR` / `ENROLL_SEAL` verifying Ed25519 signature against `ssh-ed25519` enrollment pubkey from standard Proxmox `cloud-init` `sshkeys`, generating `server.key` + `wg_server.key` locally on `/var/lib/ludus-edge` `0600`, sealing `wg0.conf` + signed `server.crt`, and permanently locking enrollment into strict mTLS 1.3).
    - TLS 1.3 listener (`RequireAndVerifyClientCert`) on `:8444`.
    - `DIAL <ip>:<port>` handler enforcing strict `netip.Prefix` allowlist (`192.0.2.0/24` excluding `.254` + `10.1.0.0/16..10.254.0.0/16`; hard-denies `10.0.0.0/16`, `127.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local, hostnames).
    - `LISTEN <port>` + `ACCEPT_JOIN` reverse listener bound strictly to `192.0.2.254:<8350..8399>` for multi-request ephemeral Packer HTTP preseed callbacks, auto-closing on stream EOF.
  - Client (`ludus-api/edgeproxy` started in-process by `ludus-server` when `edge_proxy_enabled: true`):
    - Dual-protocol loopback listener on `127.0.0.1:1080` handling **SOCKS5 (`CONNECT`)**, **HTTP `CONNECT`** (`:5986`), and **plain HTTP forward proxying** (`:5985`) on the same port (routing range CIDRs via `ludus-edge:8444` and bypassing non-range targets directly).
    - `OpenPackerReverseListener(localPort)` helper wrapping `buildVMFromTemplateWithPacker()`.
    - Built-in `ludus-server --proxy-dial <host> <port>` subcommand so OpenSSH `ProxyCommand` needs zero external `nc`/`socat` flag discrepancies.
- [x] **3.2 Automatic `ludus-edge` Reconciliation via Proxmox `:8006` (`ludus-api/edge_provision.go`):**
  - Auto-initialize & persist mTLS PKI + 250-slot WireGuard pool in `/opt/ludus/db/edge/` when not pre-supplied.
  - Reconcile `ludus-edge` VM on Proxmox via `PVEAPIToken` (`edge_auto_provision: true`): upload secret-free `/opt/ludus/resources/ludus-edge.iso` to `fs-storage:iso/`, create/start `ludus-edge` (`256 MB` RAM, `/pool/ADMIN`, `vmbr0` + `ludusnat`, standard `cloudinit` `ipconfig0`/`ipconfig1` + enrollment pubkey, `1 GB` private seal disk on `vm-storage`), complete one-time seal over `:8444`, and verify mTLS readiness.
- [x] **3.3 Ansible & Packer Proxy Injection (`ludus-api/ansible.go`, `api_template_management.go`, `packer/**/*.pkr.hcl`):**
  - When `edge_proxy_enabled: true`:
    - Inject `ProxyCommand` (`ludus-server --proxy-dial %h %p`) for range SSH hosts, `HTTP_PROXY`/`HTTPS_PROXY=http://127.0.0.1:1080` + `NO_PROXY=127.0.0.1,localhost,<proxmox_host>,10.0.20.0/24` for `pywinrm`, and optional `proxychains4` wrapper config for third-party local action modules.
    - Update Packer invocation & built-in templates (`debian12`, `debian13`, `kali`, `win2022`, `win11`) to accept optional `ssh_proxy_host` / `ssh_proxy_port`, `http_bind_address` (`127.0.0.1`), `http_ip` (`192.0.2.254`), deterministic `http_port` (`8350..8360`), and `HTTPS_PROXY`/`NO_PROXY` for `winrm` while preserving 100% stock behavior when `edge_proxy_enabled: false`.
- [x] **3.4 Integration Tests (`ludus-api/edgeproxy/edgeproxy_test.go`, `ludus-api/edge_provision_test.go`):**
  - End-to-end loopback mTLS + mock Proxmox `:8006` tests verifying `ludus-edge` ISO upload + VM create + first-boot seal, idempotent fast-path skip when already healthy, SOCKS5/HTTP `CONNECT`/plain HTTP forward proxy, `10.0.20.x` SSRF rejection, and ephemeral `LISTEN` reverse HTTP preseed serving.

---

### Phase 4 — Declarative Keycloak OIDC + Local Auth REST Contract (`ludus-api` + `ludus-ux` Fork)
*Goal: Eliminate SSH and Proxmox auth from the UI path; connect LUX <-> Ludus purely over HTTPS/HTTP REST with Sophon Keycloak OIDC primary auth and PocketBase local auth fallback.*

- [x] **4.1 Declarative OIDC Provider & Group RBAC in `ludus-api` (`ludus-api/oidc_bootstrap.go`, `database.go`):**
  - Reconcile PocketBase `users` collection `oauth2` OIDC provider (`oidc_issuer_url`, `oidc_client_id`, secret from `oidc_client_secret_file`) automatically on `ludus-admin` startup.
  - Decode/verify Keycloak group claims (`groups` / `roles`) during OAuth2 login: enforce `oidc_allowed_groups` (when non-empty), auto-provision new users when `sso_require_existing_user: false`, and sync `isAdmin` dynamically from `oidc_admin_groups`.
- [x] **4.2 Server-to-Server OIDC Token Exchange & Session Introspection (`ludus-api/api_auth.go`):**
  - Add `POST /api/v2/auth/oidc-exchange` (validates a Keycloak OIDC access/ID token against configured `oidc_issuer_url` JWKS, provisions/loads the matching Ludus user, and returns a PocketBase JWT + user profile `{userID, email, name, isAdmin}`), `POST /api/v2/auth/login` (SSH-free local password login), `POST /api/v2/auth/impersonate` (admin impersonation JWT minting), `GET /api/v2/auth/providers`, and `GET /api/v2/auth/me`.
- [x] **4.3 SSH-Free `cseelhoff/ludus-ux` Fork (`lux` Container):**
  - Branch `feat/container-oidc-rest` in `/home/caleb/ludus-ux` (fork of `ryokubaka/ludus-ux`).
  - Replace `auth-ssh.ts` (`ssh2` + `.bashrc` scraping) and `lux-host` in container mode with:
    1. Keycloak OIDC Authorization Code + PKCE login (`/api/auth/oidc/{login,callback}` -> `POST /api/v2/auth/oidc-exchange` -> Ludus JWT).
    2. Local Ludus email/userID/password fallback (`POST /api/v2/auth/login` -> Ludus JWT).
  - Route all LUX backend proxy requests to `LUDUS_URL` (`http://ludus:8080`) with `Authorization: Bearer <jwt>`, support `X-Impersonate-User` + `POST /api/v2/auth/impersonate`, route noVNC via RBAC-checked `/api/v2/vm/console/ticket` + `/api/v2/vm/console/view`, and support rootless non-root container execution.
- [x] **4.4 Auth Unit Tests (`ludus-api/oidc_bootstrap_test.go`, `ludus-ux/src/lib/auth/oidc-pkce.test.ts`, `ludus-ux/src/lib/ludus/ludus-auth-headers.test.ts`):**
  - Mock OIDC discovery + JWKS server testing login, group allowlist rejection, `ludus-admins` -> `isAdmin: true` promotion, auto-provisioning, local password login, admin impersonation, `X-Impersonate-User` + `service_token` VM RBAC, S256 PKCE + AES-GCM state cookies, and LUX security audit suites.

---

### Phase 5 — Build & Publish OCI Images + Embedded `ludus-edge.iso` (`registry-push.<domain>` & `ghcr.io/cseelhoff`)
*Goal: Build immutable rootless-Podman OCI images (`ludus-server` bundling secret-free `/opt/ludus/resources/ludus-edge.iso`, and `lux`) and publish them to Sophon Nexus (`registry-push.<domain>`) and GHCR (`ghcr.io/cseelhoff`) prior to Compose deployment.*

- [x] **5.1 Secret-Free Alpine `ludus-edge.iso` Builder Stage (`docker/edge-iso/`):**
  - Follow Sophon's signed-repo Alpine `Containerfile` + deterministic `localhost.apkovl.tar.gz` + `xorriso` pattern (`dnsmasq`, `nftables`, `wireguard-tools`, `ludus-edge-proxy`, 153 static `10.<N>.0.0/16` routes, Cloud-Init `cidata` network/enrollment reader) producing `/opt/ludus/resources/ludus-edge.iso`.
- [x] **5.2 Multi-Stage `Containerfile.ludus` & `lux` `Dockerfile` (`docker/Containerfile.ludus`, `cseelhoff/ludus-ux/docker/Dockerfile`):**
  - `ludus-server` image (`debian:bookworm-slim` Python 3.11 for dual `ansible-core 2.16.20` + `ansible-windows-ssh 2.18.19` compatibility, non-root `USER 1000:1000`): static `dynamic-inventory` + `ludus-server` + `ludus-edge-proxy` + `ludus`, embedded 81 MB `/opt/ludus/resources/ludus-edge.iso`, `python3`, `ansible`, `proxmoxer`, `pywinrm`, `netaddr`, `dnspython`, `jmespath`, `sshpass`, `openssh-client`, `proxychains4`, `git`, `jq`, `curl`, `tini`, `sqlite3`, HashiCorp `packer` `1.9.4` + plugins, and `/usr/share/ludus-seed` upgrade-safe volume synchronizer (`docker/ludus-entrypoint.sh`).
  - `lux` image (`node:24-alpine` standalone Next.js build, `sqlite` for Kopia hot dumps, non-root `USER 1000:1000`).
- [x] **5.3 Dual-Registry Build & Push Pipeline (`docker/build-and-push.sh` + `.github/workflows/container-images.yml`):**
  - Build and push immutable versioned + SHA-tagged images to **Sophon Nexus Hosted Registry** (`https://registry-push.<domain>/ludus/{ludus-server,lux}:<tag>`, stored in Kopia-backed `hosted` blob store and pulled on `sophon-infravm` via `https://registry.<domain>/ludus/*`) and **GHCR** (`ghcr.io/cseelhoff/{ludus-server,ludus-ux}:<tag>`).
- [x] **5.4 Local Rootless Podman / Docker Image Smoke Test:**
  - Verified built OCI images (`localhost/ludus-server:local` + `localhost/lux:local`) boot cleanly under rootless Podman with `--cap-drop=ALL --security-opt=no-new-privileges`, run non-root (`UID 1000:1000`, `CapEff: 0000000000000000`), pass healthchecks, authenticate against `PVEAPIToken=ludus-svc@pve!controller=...`, and complete end-to-end SSH-free `LUX -> Ludus` REST login + Bearer JWT proxy calls.

---

### Phase 6 — Compose Stacks, One-Time Proxmox Token Setup & Live Cutover (`sophon-infravm` + `pve-prod-02`)
*Goal: Package the Pure GitOps Compose stack for `sophon-infravm` (referencing pre-built registry images) and the minimal one-time Proxmox `ludus-svc@pve!controller` token setup, then validate end-to-end before retiring legacy `ludus-ctrl`.*

- [x] **6.1 Portable & Sophon Pure GitOps Compose Stacks (`docker/docker-compose.yml` + `docker/sophon-compose.yml` + `docker/.env.example`):**
  - Reference pre-built `registry.<domain>/ludus/ludus-server:<tag>` & `registry.<domain>/ludus/lux:<tag>` (with `ghcr.io/cseelhoff/*` override for standalone Docker Compose).
  - Rootless Podman security profile (`cap_drop: [ALL]`, `security_opt: [no-new-privileges:true, label=disable]`), persistent `/opt/ludus` + `/app/data` volumes, Traefik `websecure` + wildcard TLS (`ludus.<domain>`, `ludus-api.<domain>`), hairpin-free `extra_hosts` Keycloak OIDC resolution, and Sophon Kopia `sophon.backup.*` hot SQLite dump labels.
- [x] **6.2 Minimal One-Time Proxmox Token & SDN Bootstrap Snippet (`docker/proxmox-bootstrap-token.sh`):**
  - Idempotent helper (verified with `--dry-run`) that creates `LudusController` + `ludus-svc@pve!controller`, `/pool/ADMIN` + `/pool/SHARED`, SDN zone `ludus` (`ludusnat`), node scope `/nodes/pve-prod-02`, and `NoAccess` on `/pool/SOC-Range` (zero `User.Modify` / `Permissions.Modify` granted to token) — after which `ludus-server` self-deploys `ludus-edge` automatically over `:8006`!
- [ ] **6.3 Parallel Validation & Cutover Runbook (`sophon-infravm` <-> `pve-prod-02`) — Runbook Complete (`docs/ludus-container-cutover-runbook.md`), Ready for Live Execution:**
  - Deploy Compose stack on `sophon-dev-infravm` / `sophon-infravm` (`pve-prod-01`) -> verify `ludus-server` automatically uploads `ludus-edge.iso`, boots & seals `ludus-edge` on `pve-prod-02` over `:8006`, and brings up `:8444` mTLS + `:51820` WireGuard.
  - Verify end-to-end acceptance: Keycloak SSO login in LUX -> create user -> WireGuard `:51820` 1-hop ping -> Packer template build over reverse preseed/WinRM proxy -> multi-VM Range `2` deploy (`SUCCESS`) -> clean `rm-range` teardown with Range `1` (`soc-first-proof`) untouched.
