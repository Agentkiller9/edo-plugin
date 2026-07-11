"""
edo_core — the daemon's own logic, informed by the real edo CLI
(github.com/Agentkiller9/edo) but NOT a copy of it and NOT importing it.

edo's CLI targets a different deployment shape: one shared container per
challenge, one flat Docker bridge, no owner/team concept, no TTL. This
package reuses edo's *patterns* (atomic SQLite allocation with retry-on-race,
subprocess wrappers around wg/iptables/docker, idempotent firewall rebuilds)
but adds what edo doesn't have: per-owner Docker networks, per-owner
iptables isolation, owner-scoped container naming, and TTL tracking.

The edo repo itself is untouched — this is a from-scratch implementation
inside edo-plugin, adapted to CTFd's per-team/per-user instance model.
"""
