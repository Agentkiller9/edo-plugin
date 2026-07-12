# edo-plugin

CTFd master plugin for VPN, per-owner Docker isolation, and advanced scoring.
Named after Edo Tensei — the reanimation protocol.

Companion to [Agentkiller9/edo](https://github.com/Agentkiller9/edo), the CLI
that manages WireGuard, iptables routing, and Docker bridges on the host. The
daemon in this repo (`daemon/edo_core/`) is informed by edo's real code —
same subprocess patterns, same atomic SQLite allocation — but is a
from-scratch implementation, not an import of it. See **Design notes**
below for why.

## What it does

- **WireGuard VPN**: Admins bulk-generate peers; participants download their
  `.conf` from the dashboard.
- **Per-owner Docker isolation**: One dedicated container per (challenge,
  owner) — "owner" is a team in team-mode CTFd, or an individual user in
  user-mode. Each owner gets its own Docker network and subnet; the daemon's
  iptables rules block one owner's containers from ever reaching another's,
  and a WireGuard peer can only route into the container subnet of its own
  owner (enforced server-side, not just via the client's AllowedIPs).
- **Multi-flag challenges**: A single challenge can have several flags —
  CTFd's own native Flags table and flag-editor UI, unmodified. The only
  addition is a percentage weight per flag, so partial credit works and the
  challenge modal shows live "N/M flags captured" progress.
- **Difficulty tiers**: Easy (green) / Medium (yellow) / Hard (red) / Very
  Hard (purple), rendered on challenge cards.
- **Scoring**: Static or dynamic (linear decay).
- **Rate limits**: Per-owner, per-challenge submission bucket in-process;
  the daemon also caps concurrent container builds so a burst of "spawn"
  clicks can't fork off dozens of `docker build`s at once.
- **Lifecycle**: Configurable TTL, "Extend Time" that unlocks under 10 min
  remaining, live countdown, background sweeper for expiry.
- **Reconciliation**: A worker polls the daemon and heals DB drift when
  containers crash or are killed out-of-band. Everything is audited. The
  daemon itself also adopts orphaned containers back on restart rather than
  losing track of them.
- **Kill switch**: One admin action tears down every tracked container
  across every owner. Leaves VPN access intact — it's an infra reset, not a
  lockout.

## Architecture

Strict split so the CTFd worker never runs as root.

```
+---------------------+                +--------------------+
|  CTFd worker        |  length-framed |  edo-daemon         |
|  (unprivileged,     |  JSON over     |  (root)              |
|   Docker container)  |  Unix socket   |                     |
|                     | -------------> |  edo_core/          |
|  - Blueprint        |                |   wireguard.py      |
|  - SQLAlchemy       |                |   network.py        |
|  - Scheduler        | <------------- |   containers.py     |
|  - Rate limiter     |    replies     |   db.py (SQLite)    |
+---------------------+                +--------------------+
```

Wire format: 4-byte big-endian length | JSON payload. No signature — the
daemon authenticates the caller via `SO_PEERCRED`, reading the connecting
process's **real, kernel-verified UID** off the socket. The socket's
filesystem permissions (0660, `root:<ctfd-group>`) are what let the CTFd
container connect at all; SO_PEERCRED then confirms it really is that UID.
There is no shared secret to generate, rotate, or leak.

## Design notes (read before touching the daemon)

- **Owner model.** Every owner-scoped table uses a generic
  `(owner_type, owner_id)` pair instead of separate nullable `team_id`/
  `user_id` columns. `owner.py`'s `resolve_owner()` wraps CTFd's own
  `get_model()` / `get_current_user()` / `get_current_team()` so every route
  and the daemon RPCs agree on what "owner" means in both CTFd user-mode and
  team-mode. VPN peer *identity* is always per-CTFd-user (every teammate
  keeps their own device); owner_type/owner_id on a peer just tags which
  container subnet that peer may reach.

- **Flags are CTFd's native Flags table — not a reimplementation.** CTFd
  already loops over a challenge's Flags in `attempt()` via
  `get_flag_class(flag.type).compare()`, and its admin UI already renders a
  generic "Flags" tab for every challenge type. `EdoFlagWeight` is the only
  new table on the flag side: one row per native flag, holding what
  percentage of the challenge's value it's worth.

- **edo's real container model has no owner concept.** edo's
  `docker_mgr.py` names containers `edo_<challenge>` — no team/user
  component — so only one instance of a challenge can exist at a time,
  globally, on one shared bridge with no inter-container isolation at all
  (its iptables rules only isolate WireGuard peers from each other). Getting
  "one container per challenge per team" and "Team A can't reach Team B's
  containers" required new logic beyond what edo does today:
  `daemon/edo_core/` gives every owner its own Docker network (a `/24` out
  of `10.9.0.0/16`) and enforces isolation between them, on top of edo's
  WireGuard/DB/security-profile patterns, which carried over largely as-is.
  See the module docstrings in `daemon/edo_core/network.py` and
  `containers.py` for the exact rule set.

- **Daemon state is the source of truth; CTFd's DB records intent.**
  Per-owner subnet allocation (`owner_octets`) lives entirely in the
  daemon's own SQLite (`daemon/edo_core/db.py`) — the plugin never needs to
  know an owner's octet, only its `(owner_type, owner_id)`.

## Layout

```
edo_plugin/                        (folder name when installed under CTFd/plugins/)
├── __init__.py                    CTFd load(app) — tables, blueprint, scheduler
├── config.py                      Env-driven defaults, difficulty tiers
├── owner.py                       resolve_owner() — the team/user abstraction
├── models.py                      EdoChallenge, EdoFlagWeight, EdoFlagSolve,
│                                  EdoInstance, EdoPeer, EdoSettings, EdoAuditLog
├── challenge_type.py              EdoChallengeType — multi-flag via native Flags,
│                                  decay scoring, partial credit
├── daemon_client.py               RPC client (stdlib-only, no signing)
├── scheduler.py                   APScheduler jobs: TTL sweep + reconciler
├── decorators.py                  rate_limited, owner_required
├── api/
│   ├── admin.py                   /plugins/edo_plugin/admin/*   (admins_only)
│   └── user.py                    /plugins/edo_plugin/*         (authed_only, owner_required)
├── assets/                        Served at /plugins/edo_plugin/assets/*
│   ├── create.html / update.html / view.html    challenge-type modals
│   ├── create.js  / update.js  / view.js        CTFd asset shims
│   └── style.css                                difficulty tier colors
├── templates/                     Jinja templates (server-rendered)
│   ├── admin/edo_settings.html
│   └── user/edo_dashboard.html
└── daemon/                        Ships with the plugin but installed on the
    ├── edo_daemon.py              HOST as root — not inside the CTFd container.
    ├── edo_core/                  The daemon's actual logic (see Design notes).
    │   ├── db.py                  SQLite: peers, owner_octets, instances
    │   ├── wireguard.py           WG keygen, config render, live-apply
    │   ├── network.py             Per-owner subnets + iptables isolation
    │   └── containers.py          Per-owner Docker networks + spawn/release
    ├── edo-daemon.service
    ├── daemon.env.example
    └── requirements.txt           Daemon-side deps (docker SDK)
```

## Installation

The plugin folder must be importable as a Python module — hyphens are illegal
in module names, so it must be installed under `CTFd/plugins/edo_plugin/`
(underscore). The daemon runs on the **host** as `root`; CTFd runs in
**Docker**. They talk over a Unix socket that's bind-mounted into the
container.

### 1. Daemon (host, root)

Prereqs — the daemon shells out to `wg`, `docker`, and `iptables`, and needs
a venv because modern Debian/Ubuntu (PEP 668) refuse `pip install` into
system Python:

```bash
sudo apt update
sudo apt install -y wireguard-tools docker.io iptables python3-venv
```

`wireguard-tools` also creates `/etc/wireguard/` which the systemd unit
sandboxes into the service's namespace.

The daemon imports its own `edo_core/` package as a sibling directory, so
the whole `daemon/` folder ships together — not just `edo_daemon.py` on its
own. Clone **directly into** `/opt/edo` so the paths the systemd unit
expects (`/opt/edo/daemon/edo_daemon.py`, `/opt/edo/daemon/edo_core/`)
already exist post-clone — no separate copy step needed.

```bash
sudo mkdir -p /opt/edo && cd /opt/edo
sudo git clone https://github.com/Agentkiller9/edo-plugin.git .

# Dedicated venv — the systemd unit's ExecStart points at its interpreter
# directly, so `pip install` here is enough; no --break-system-packages,
# no polluting system Python.
sudo python3 -m venv /opt/edo/venv
sudo /opt/edo/venv/bin/pip install -r daemon/requirements.txt

sudo install -m 0644 daemon/edo-daemon.service  /etc/systemd/system/
sudo install -d -m 0755 -o root -g root         /etc/edo /run/edo /var/lib/edo

# Create a group with GID 1001 so the container's ctfd user (UID 1001) can
# read the socket. Then tell the daemon to chown the socket to it, and to
# only authenticate RPCs coming from that same UID.
sudo groupadd -g 1001 ctfd_socket

sudo cp daemon/daemon.env.example /etc/edo/daemon.env
sudo chmod 600 /etc/edo/daemon.env

# Fill in the two values that matter — EDO_ALLOWED_UID already defaults to
# 1001 (the stock ctfd/ctfd image's UID; confirm with
# `docker compose exec ctfd id -u` on the CTFd side once it's up) and
# EDO_VPN_ENDPOINT needs this host's real public IP/hostname:
sudo sed -i "s|^EDO_VPN_ENDPOINT=.*|EDO_VPN_ENDPOINT=$(curl -s ifconfig.me):51820|" /etc/edo/daemon.env
# Or edit by hand if you'd rather (don't rely on $EDITOR being set on a
# fresh box — check first, or just name the editor explicitly):
#   sudo nano /etc/edo/daemon.env

sudo systemctl daemon-reload
sudo systemctl enable --now edo-daemon.service

# Sanity check — socket must be root:ctfd_socket 660
ls -l /run/edo/edo.sock
```

If the socket doesn't appear, the daemon exited on startup — check why
before moving on:

```bash
sudo systemctl status edo-daemon --no-pager -l
sudo journalctl -u edo-daemon -n 50 --no-pager
```

Authentication is kernel-level (`SO_PEERCRED`) rather than a shared secret —
there's no key to generate or copy between the two sides.

### 2. CTFd (Docker)

The repo ships a full stack in `docker/`. Bring it up from any directory:

```bash
cd /opt/edo/docker
docker compose up -d --build
```

That's it — no `.env` needed (there's no secret left to inject since
SO_PEERCRED replaced HMAC signing). The custom Dockerfile bakes the plugin
into `ctfd/ctfd:3.7.5`, `docker-compose.yml` bind-mounts `/run/edo` into the
container, and the plugin creates its tables on first boot.

### 3. Verify

Log in as an admin and hit
`http://<host>:8000/plugins/edo_plugin/admin/settings` — the "Ping daemon"
button should return `Daemon OK`. If not:

```bash
# Container can see the socket?
docker compose exec ctfd ls -l /run/edo/edo.sock
# Should be root:ctfd_socket 660 — a numeric GID 1001 also fine

# Container's actual UID matches EDO_ALLOWED_UID in /etc/edo/daemon.env?
docker compose exec ctfd id -u

# Daemon is up?
sudo systemctl status edo-daemon
sudo journalctl -u edo-daemon -f
```

## Configuration

Runtime knobs live in the `edo_settings` table and are editable from the
admin UI. Defaults come from `config.py`:

| Key | Default | Purpose |
|---|---|---|
| `max_containers_per_owner` | 3 | Concurrent cap per owner (team, or user if solo mode) |
| `container_ttl_seconds` | 3600 | Default lifetime |
| `extend_seconds` | 1800 | How much "Extend" adds |
| `extend_threshold_seconds` | 600 | Button unlocks when remaining ≤ this |
| `submit_rate_limit` / `_window` | 10 / 60 | Per-owner-per-challenge attempts / seconds |
| `vpn_server_endpoint` | vpn.example.com:51820 | Written into every .conf |
| `ttl_check_interval_seconds` | 15 | Sweeper cadence |
| `reconcile_interval_seconds` | 60 | Reconciler cadence |

VPN/container subnets (`10.8.0.0/24` for peers, `10.9.0.0/16` subdivided
per owner) are fixed daemon-side infrastructure — not admin-editable, since
they're *actual* infra state, not CTFd *intent*.

## Creating a challenge

In the admin UI, pick type **edo** when creating a challenge. You get:

- Difficulty selector (color-coded)
- Static value or dynamic decay (initial / minimum / decay-slots)
- Optional instance config: build path (a host directory containing a
  Dockerfile — the daemon builds from it per-owner, no registry push step),
  exposed ports, CPU / memory / PIDs limits, read-only rootfs, TTL override
- **Flags**: add/edit/delete from CTFd's own native **Flags** tab (regex vs
  static, case sensitivity — all standard CTFd). This plugin adds a
  **Flag Weights** panel below the instance settings where you assign what
  percentage of the challenge's value each flag is worth; weights should
  sum to 100 (a warning shows if they don't, but it won't block saving
  mid-edit).

## Security notes

- The socket is chmod 660, owned by `root:<ctfd-group>`. Even if the CTFd
  user is compromised, an attacker can only speak the RPC surface, and only
  as the UID the socket lets them connect as.
- Every accepted connection is authenticated via `SO_PEERCRED` — the
  daemon reads the connecting process's real UID at the kernel level and
  rejects anything that isn't `EDO_ALLOWED_UID` or root. This can't be
  forged by anything the client sends, unlike an application-layer token.
- A WireGuard peer can only reach its own owner's container subnet — this
  is enforced by the daemon's iptables rules on specific peer IPs, not by
  the client's `AllowedIPs`, which a participant fully controls and could
  otherwise route around.
- Containers from different owners can never reach each other, even though
  they all run on the same host, via a blanket per-pool DROP rule between
  the isolation and egress-containment rules.
- The daemon runs with `CAP_NET_ADMIN` / `CAP_NET_RAW` only,
  `NoNewPrivileges`, `ProtectSystem=strict`.
- Container spawns drop all caps except what's explicitly opted into,
  set `no-new-privileges`, and support a read-only rootfs — see
  `SecurityProfile` in `daemon/edo_core/containers.py`.
- **Build paths are admin-supplied**, not participant input — `spawn_instance`
  runs `docker build` against whatever path the challenge record has, so
  don't expose challenge creation to non-admins.
- **Every mutating request uses `CTFd.fetch()`, never a bare `fetch()`.**
  CTFd enforces CSRF globally (a `before_request` hook checks a `CSRF-Token`
  header on every POST/PUT/PATCH/DELETE, including plugin blueprint routes —
  there's no automatic exemption by blueprint name). `CTFd.fetch()` attaches
  that header from `window.init.csrfNonce` automatically; a raw `fetch()`
  would get silently rejected with a 403. If you add new admin/user actions,
  keep using `CTFd.fetch()` in the JS.
- **Background jobs are leader-elected, not per-worker.** CTFd typically
  runs multiple gunicorn workers, each of which calls `start_scheduler()` —
  without coordination that's N schedulers all sweeping/reconciling
  independently. `EdoWorkerLease` (models.py) is a DB-backed lease row: each
  tick, a worker wins it via a conditional UPDATE (or an INSERT if the row
  doesn't exist yet) before doing any real work, so exactly one worker acts
  per tick regardless of how many gunicorn processes are running. See
  `scheduler.py`'s `_try_acquire_lease()`.

## Admin dashboard

`/plugins/edo_plugin/admin/settings` is a single page covering:

- Runtime settings (container caps, TTLs, rate limits, VPN endpoint)
- **Live instances** — every tracked container across every owner, with a
  per-row force-stop button
- **Audit log** — the last 100 infrastructure events (spawns, teardowns,
  extends, orphan detections, reconciler drift)
- **Kill switch** — stops every tracked container in one action (leaves VPN
  peers intact)
- **Generate all VPN peers** — bulk-provisions a WireGuard peer for every
  active user that doesn't have one yet

## Development status

The full owner-model rewrite, the daemon (WireGuard, per-owner networks,
iptables isolation, container lifecycle, leader-elected background jobs),
and the CTFd-side models/API/scoring/admin dashboard are all real, working
code — not stubs. Known gaps before calling this production-ready:

- **Only Dockerfile-based challenges**, not docker-compose multi-service
  ones — edo's compose deployment path wasn't ported.
- **Client-side WireGuard keys** (participant generates their own keypair,
  server never sees the private key) are supported by the daemon
  (`wg.ensure_peer` takes an optional public key) but no UI exposes it yet.
- **No automated test suite.** Everything has been verified by direct
  inspection, standalone smoke tests of the daemon's core modules, and a
  from-scratch correctness test of the leader-election algorithm — but
  there's no pytest suite exercising the Flask routes end-to-end yet.

## License

TBD.
