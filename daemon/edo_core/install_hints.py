"""Tiny install-hint table for missing binaries. Not a full preflight/doctor
command — just enough to turn a FileNotFoundError into an actionable message.
"""
from __future__ import annotations

_HINTS = {
    "wg": "apt install wireguard-tools",
    "wg-quick": "apt install wireguard-tools",
    "iptables": "apt install iptables",
    "ip": "apt install iproute2",
    "firewall-cmd": "apt install firewalld",
    "docker": "apt install docker.io  (or see docs.docker.com/engine/install)",
}


def install_hint(binary: str) -> str:
    return _HINTS.get(binary, f"install '{binary}' via your distro's package manager")
