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
edo-plugin/
├── __init__.py              CTFd load(app) — migrations, blueprint, scheduler
├── config.py                Env-driven defaults, difficulty tiers
├── models.py                EdoChallenge, EdoFlag, EdoFlagSolve, EdoInstance,
│                            EdoVPNPeer, EdoSettings, EdoAuditLog
├── challenge_type.py        EdoChallengeType — multi-flag, decay, partial credit
├── daemon_client.py         RPC client (stdlib-only)
├── scheduler.py             APScheduler jobs: TTL sweep + reconciler
├── decorators.py            rate_limited, team_required
├── api/
│   ├── admin.py             /plugins/edo/admin/*   (admins_only)
│   └── user.py              /plugins/edo/*         (authed_only, team_required)
├── templates/               admin settings, challenge create/update/view,
│                            user dashboard
├── assets/                  CSS, JS shims for CTFd's asset pipeline
└── daemon/
    ├── edo_daemon.py        Root sidecar (stdlib-only)
    ├── edo-daemon.service   systemd unit (hardened caps)
    └── daemon.env.example
```

## Installation

### 1. Plugin (CTFd side)

```bash
cd /opt/CTFd/CTFd/plugins
git clone https://github.com/Agentkiller9/edo-plugin.git edo-plugin
pip install -r edo-plugin/requirements.txt
```

Set the daemon transport in CTFd's environment:

```bash
export EDO_DAEMON_SOCKET=/run/edo/edo-daemon.sock
export EDO_DAEMON_HMAC_KEY=<same-hex-key-as-daemon>
```

Restart CTFd. The plugin creates its tables on first boot and seeds defaults
into `EdoSettings`.

### 2. Daemon (host side, root)

```bash
sudo install -m 0755 edo-plugin/daemon/edo_daemon.py /usr/local/bin/edo-daemon.py
sudo install -m 0644 edo-plugin/daemon/edo-daemon.service /etc/systemd/system/
sudo install -d -m 0755 -o root -g root /etc/edo /run/edo /var/lib/edo
sudo cp edo-plugin/daemon/daemon.env.example /etc/edo/daemon.env
sudo chmod 600 /etc/edo/daemon.env

# generate a shared HMAC key
python3 -c 'import secrets; print(secrets.token_hex(32))' | sudo tee -a /etc/edo/daemon.env
# then edit /etc/edo/daemon.env so EDO_DAEMON_HMAC_KEY= is the generated value
# and set EDO_SOCKET_OWNER=root:<ctfd-unix-user>

sudo systemctl daemon-reload
sudo systemctl enable --now edo-daemon.service
```

Verify from the admin settings page (`/plugins/edo/admin/settings`) — the
"Ping daemon" button should return OK.

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
