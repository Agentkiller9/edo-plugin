# edo-plugin

CTFd master plugin for VPN, per-team Docker isolation, and advanced scoring.
Named after Edo Tensei — the reanimation protocol.

Companion to [Agentkiller9/edo](https://github.com/Agentkiller9/edo), the CLI
that manages WireGuard, iptables routing, and Docker bridges on the host.

## What it does

- **WireGuard VPN**: Admins bulk-generate peers; participants download their
  `.conf` from the dashboard.
- **Per-team Docker isolation**: One dedicated container per (challenge, team),
  spawned into a team-scoped bridge. iptables rules block Team A from routing
  to Team B's containers.
- **Multi-flag challenges**: A single challenge can have several flags, each
  weighted as a percentage of the total value. Partial credit is tracked
  per flag.
- **Difficulty tiers**: Easy (green) / Medium (yellow) / Hard (red) / Very
  Hard (purple), rendered on challenge cards.
- **Scoring**: Static or dynamic (linear decay).
- **Rate limits**: Per-team, per-challenge submission bucket in-process; hard
  cap enforced by the daemon.
- **Lifecycle**: Configurable TTL, "Extend Time" that unlocks under 10 min
  remaining, live countdown, background sweeper for expiry.
- **Reconciliation**: A worker polls the daemon and heals DB drift when
  containers crash or are killed out-of-band. Everything is audited.

## Architecture

Strict split so the CTFd worker never runs as root.

```
+---------------------+                +--------------------+
|  CTFd worker        |   HMAC-signed  |  edo-daemon        |
|  (unprivileged)     |   JSON over    |  (root)            |
|                     |   Unix socket  |                    |
|  - Blueprint        | -------------> |  - wg genkey       |
|  - SQLAlchemy       |                |  - docker run      |
|  - Scheduler        | <------------- |  - iptables        |
|  - Rate limiter     |    replies     |  - state.json      |
+---------------------+                +--------------------+
```

Wire format: 4-byte big-endian length | JSON payload | 64-byte HMAC-SHA256 hex.
Timestamps rejected outside a 30-second window.

## Layout

```
edo_plugin/                        (folder name when installed under CTFd/plugins/)
├── __init__.py                    CTFd load(app) — tables, blueprint, scheduler
├── config.py                      Env-driven defaults, difficulty tiers
├── models.py                      EdoChallenge, EdoFlag, EdoFlagSolve,
│                                  EdoInstance, EdoVPNPeer, EdoSettings, EdoAuditLog
├── challenge_type.py              EdoChallengeType — multi-flag, decay, partial credit
├── daemon_client.py               RPC client (stdlib-only)
├── scheduler.py                   APScheduler jobs: TTL sweep + reconciler
├── decorators.py                  rate_limited, team_required
├── api/
│   ├── admin.py                   /plugins/edo_plugin/admin/*   (admins_only)
│   └── user.py                    /plugins/edo_plugin/*         (authed_only, team_required)
├── assets/                        Served at /plugins/edo_plugin/assets/*
│   ├── create.html / update.html / view.html    challenge-type modals
│   ├── create.js  / update.js  / view.js        CTFd asset shims
│   └── style.css                                difficulty tier colors
├── templates/                     Jinja templates (server-rendered)
│   ├── admin/edo_settings.html
│   └── user/edo_dashboard.html
└── daemon/                        Ships with the plugin but installed on host,
    ├── edo_daemon.py              not inside the CTFd container.
    ├── edo-daemon.service
    └── daemon.env.example
```

## Installation

The plugin folder must be importable as a Python module — hyphens are illegal
in module names, so it must be installed under `CTFd/plugins/edo_plugin/`
(underscore). The daemon runs on the **host** as `root`; CTFd runs in
**Docker**. They talk over a Unix socket that's bind-mounted into the
container.

### 1. Daemon (host, root)

```bash
# Clone somewhere durable
sudo mkdir -p /opt/edo && cd /opt/edo
sudo git clone https://github.com/Agentkiller9/edo-plugin.git .

sudo install -m 0755 daemon/edo_daemon.py       /usr/local/bin/edo-daemon.py
sudo install -m 0644 daemon/edo-daemon.service  /etc/systemd/system/
sudo install -d -m 0755 -o root -g root         /etc/edo /run/edo /var/lib/edo

# Create a group with GID 1001 so the container's ctfd user (UID 1001) can
# read the socket. Then tell the daemon to chown the socket to it.
sudo groupadd -g 1001 ctfd_socket

sudo cp daemon/daemon.env.example /etc/edo/daemon.env
sudo chmod 600 /etc/edo/daemon.env

# Generate the shared HMAC key ONCE — reused on both sides.
KEY=$(openssl rand -hex 32)
sudo sed -i "s|^EDO_DAEMON_HMAC_KEY=.*|EDO_DAEMON_HMAC_KEY=$KEY|" /etc/edo/daemon.env
sudo sed -i "s|^EDO_SOCKET_OWNER=.*|EDO_SOCKET_OWNER=root:ctfd_socket|" /etc/edo/daemon.env
echo "COPY THIS INTO docker/.env AS EDO_DAEMON_HMAC_KEY: $KEY"

sudo systemctl daemon-reload
sudo systemctl enable --now edo-daemon.service

# Sanity check — socket must be root:ctfd_socket 660
ls -l /run/edo/edo-daemon.sock
```

### 2. CTFd (Docker)

The repo ships a full stack in `docker/`. Bring it up from any directory:

```bash
cd /opt/edo/docker
cp .env.example .env
# paste the HMAC key you generated above:
$EDITOR .env

docker compose up -d --build
```

That's it. The custom Dockerfile bakes the plugin into `ctfd/ctfd:3.7.5`,
`docker-compose.yml` bind-mounts `/run/edo` into the container, and the
plugin creates its tables on first boot.

### 3. Verify

Log in as an admin and hit
`http://<host>:8000/plugins/edo_plugin/admin/settings` — the "Ping daemon"
button should return `Daemon OK`. If not:

```bash
# Container can see the socket?
docker compose exec ctfd ls -l /run/edo/edo-daemon.sock
# Should be root:ctfd_socket 660 — a numeric GID 1001 also fine

# Container has the HMAC key?
docker compose exec ctfd printenv EDO_DAEMON_HMAC_KEY | head -c 8

# Daemon is up?
sudo systemctl status edo-daemon
sudo journalctl -u edo-daemon -f
```

## Configuration

Runtime knobs live in the `edo_settings` table and are editable from the
admin UI. Defaults come from `config.py`:

| Key | Default | Purpose |
|---|---|---|
| `max_containers_per_team` | 3 | Concurrent cap per team |
| `container_ttl_seconds` | 3600 | Default lifetime |
| `extend_seconds` | 1800 | How much "Extend" adds |
| `extend_threshold_seconds` | 600 | Button unlocks when remaining ≤ this |
| `submit_rate_limit` / `_window` | 10 / 60 | Per-team-per-challenge attempts / seconds |
| `vpn_subnet` | 10.9.0.0/24 | WG address pool |
| `vpn_server_endpoint` | vpn.example.com:51820 | Written into every .conf |
| `ttl_check_interval_seconds` | 15 | Sweeper cadence |
| `reconcile_interval_seconds` | 60 | Reconciler cadence |

## Creating a challenge

In the admin UI, pick type **edo** when creating a challenge. You get:

- Difficulty selector (color-coded)
- Static value or dynamic decay (initial / minimum / decay-slots)
- Optional container config: Docker image, exposed ports, CPU / memory /
  PIDs limits, TTL override
- Flag editor with a weight column — weights must sum to 100

Flags are validated in-plugin (not via CTFd's built-in Flags table) so weights
and multi-flag partial credit work.

## Security notes

- The socket is chmod 660 root:ctfd. Even if the CTFd user is compromised,
  attackers can only speak the RPC surface.
- Every request is HMAC-SHA256 signed; the daemon rejects requests older
  than 30 seconds to defeat replays.
- The daemon runs with `CAP_NET_ADMIN` / `CAP_NET_RAW` only, `NoNewPrivileges`,
  `ProtectSystem=strict`.
- Container spawns drop all caps and set `no-new-privileges` — customize
  `handle_container_spawn` in `daemon/edo_daemon.py` if a challenge needs
  more.

## Development status

The plugin and RPC skeleton are complete. The daemon's shell-outs to `wg`,
`docker`, and `iptables` are stubbed with the exact commands as comments — hook
them up to your existing [edo CLI](https://github.com/Agentkiller9/edo) or
call the tools directly.

## License

TBD.
