"""Routing and firewall plane for the edo daemon.

Ported from edo's src/network.py (subprocess helpers, firewalld interop,
iptables primitives, chain-hooking strategy) with one structural change:
edo's real rule set only isolates participant-to-participant traffic over
WireGuard — it has a single shared Docker bridge with NO container-to-
container isolation. This module adds that: every owner (team or user) gets
its own /24 out of a 10.9.0.0/16 pool, and the firewall enforces two things
edo doesn't:

  1. A WireGuard peer may only reach the docker subnet of ITS OWN owner —
     enforced per-peer-IP, not just via the client's AllowedIPs (a VPN
     client fully controls its own routing table, so AllowedIPs alone is
     not a security boundary; the server-side ACCEPT/DROP is).
  2. Containers belonging to different owners can never reach each other,
     even though they may all be routed through the same host.

Rules live in a dedicated chain (EDO_FORWARD) hooked at the top of
DOCKER-USER (falling back to FORWARD) — same precedence trick as edo, for
the same reason: it survives `systemctl restart docker` re-inserting its
own chains.
"""
from __future__ import annotations

import ipaddress
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .install_hints import install_hint

logger = logging.getLogger(__name__)

# ---- topology constants -------------------------------------------------
# Matches edo's real constants exactly for the WireGuard side (no reason to
# diverge — this pool is edo's, unchanged). The Docker side is now a /16
# pool subdivided per-owner instead of edo's single flat /24.
WG_SUBNET = ipaddress.IPv4Network("10.8.0.0/24")
WG_SERVER_IP = "10.8.0.1"
WG_INTERFACE = "wg0"

DOCKER_POOL = ipaddress.IPv4Network("10.9.0.0/16")
DOCKER_BRIDGE_PREFIX = "edo_o"  # + octet, e.g. edo_o7

EDO_CHAIN = "EDO_FORWARD"
EDO_INPUT_CHAIN = "EDO_INPUT"


def owner_subnet(octet: int) -> ipaddress.IPv4Network:
    if not (1 <= octet <= 254):
        raise ValueError(f"octet {octet} out of range 1-254")
    return ipaddress.IPv4Network(f"10.9.{octet}.0/24")


def owner_gateway_ip(octet: int) -> str:
    return f"10.9.{octet}.1"


def bridge_name(octet: int) -> str:
    return f"{DOCKER_BRIDGE_PREFIX}{octet}"


@dataclass
class RuleResult:
    success: bool
    rule: List[str]
    stderr: str = ""


@dataclass
class FirewallApplyResult:
    public_interface: str
    rules: List[RuleResult] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return all(r.success for r in self.rules)


# ---- subprocess helper (ported verbatim from edo) -----------------------
def _run(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("exec: %s", " ".join(cmd))
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=check)
    except FileNotFoundError as e:
        raise RuntimeError(
            f"required binary not found: {cmd[0]}\n  install: {install_hint(cmd[0])}"
        ) from e


def get_public_interface() -> Optional[str]:
    try:
        proc = _run(["ip", "-4", "route", "show", "default"])
    except subprocess.CalledProcessError as e:
        logger.error("could not query default route: %s", e.stderr.strip())
        return None
    tokens = proc.stdout.split()
    if "dev" in tokens:
        idx = tokens.index("dev")
        if idx + 1 < len(tokens):
            return tokens[idx + 1]
    return None


# ---- iptables primitives (ported verbatim from edo) ---------------------
def _iptables_check(rule: List[str]) -> bool:
    try:
        proc = subprocess.run(["iptables", "-C", *rule], capture_output=True, text=True)
    except OSError:
        return False
    return proc.returncode == 0


def _iptables_append(rule: List[str]) -> RuleResult:
    if _iptables_check(rule):
        return RuleResult(success=True, rule=rule)
    try:
        _run(["iptables", "-A", *rule])
        return RuleResult(success=True, rule=rule)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()
        logger.error("iptables -A failed: %s -- %s", rule, msg)
        return RuleResult(success=False, rule=rule, stderr=msg)


def _iptables_delete(rule: List[str]) -> RuleResult:
    if not _iptables_check(rule):
        return RuleResult(success=True, rule=rule)
    try:
        _run(["iptables", "-D", *rule])
        return RuleResult(success=True, rule=rule)
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or "").strip()
        return RuleResult(success=False, rule=rule, stderr=msg)


def _chain_exists(chain: str) -> bool:
    try:
        proc = subprocess.run(["iptables", "-L", chain, "-n"], capture_output=True, text=True)
    except OSError:
        return False
    return proc.returncode == 0


# ---- firewalld interop (ported verbatim from edo) ------------------------
def firewalld_active() -> bool:
    if not shutil.which("firewall-cmd"):
        return False
    try:
        proc = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True)
    except OSError:
        return False
    return proc.returncode == 0 and "running" in proc.stdout.lower()


def apply_wg_input_rule(port: int = 51820) -> RuleResult:
    if firewalld_active():
        try:
            _run(["firewall-cmd", f"--add-port={port}/udp", "--permanent"])
            _run(["firewall-cmd", "--reload"])
            return RuleResult(success=True, rule=["firewalld", f"{port}/udp"])
        except subprocess.CalledProcessError as e:
            return RuleResult(
                success=False, rule=["firewalld", f"{port}/udp"],
                stderr=(e.stderr or "").strip(),
            )

    subprocess.run(["iptables", "-N", EDO_INPUT_CHAIN], capture_output=True, text=True)
    hook = ["INPUT", "-j", EDO_INPUT_CHAIN]
    if not _iptables_check(hook):
        try:
            _run(["iptables", "-I", "INPUT", "1", "-j", EDO_INPUT_CHAIN])
        except subprocess.CalledProcessError as e:
            return RuleResult(success=False, rule=hook, stderr=(e.stderr or "").strip())
    try:
        _run(["iptables", "-F", EDO_INPUT_CHAIN])
    except subprocess.CalledProcessError as e:
        return RuleResult(
            success=False, rule=["-F", EDO_INPUT_CHAIN], stderr=(e.stderr or "").strip()
        )
    rule = [
        EDO_INPUT_CHAIN, "-p", "udp", "--dport", str(port),
        "-m", "comment", "--comment", "edo: WireGuard handshake", "-j", "ACCEPT",
    ]
    return _iptables_append(rule)


def remove_wg_input_rule(port: int = 51820) -> RuleResult:
    if firewalld_active():
        try:
            _run(["firewall-cmd", f"--remove-port={port}/udp", "--permanent"])
            _run(["firewall-cmd", "--reload"])
            return RuleResult(success=True, rule=["firewalld", f"{port}/udp"])
        except subprocess.CalledProcessError as e:
            return RuleResult(
                success=False, rule=["firewalld", f"{port}/udp"],
                stderr=(e.stderr or "").strip(),
            )
    hook = ["INPUT", "-j", EDO_INPUT_CHAIN]
    if _iptables_check(hook):
        _iptables_delete(hook)
    if _chain_exists(EDO_INPUT_CHAIN):
        try:
            _run(["iptables", "-F", EDO_INPUT_CHAIN])
            _run(["iptables", "-X", EDO_INPUT_CHAIN])
        except subprocess.CalledProcessError as e:
            return RuleResult(
                success=False, rule=["-X", EDO_INPUT_CHAIN], stderr=(e.stderr or "").strip()
            )
    return RuleResult(success=True, rule=[EDO_INPUT_CHAIN, "removed"])


# Hook precedence, ported from edo: DOCKER-USER survives `systemctl restart
# docker`; FORWARD is the fallback on hosts without Docker's own chains yet.
_FORWARD_HOOK_CANDIDATES = ("DOCKER-USER", "FORWARD")


def _preferred_forward_hook() -> str:
    for chain in _FORWARD_HOOK_CANDIDATES:
        if _chain_exists(chain):
            return chain
    return "FORWARD"


def _unhook_edo_from_all() -> List[RuleResult]:
    results: List[RuleResult] = []
    for chain in _FORWARD_HOOK_CANDIDATES:
        if not _chain_exists(chain):
            continue
        hook = [chain, "-j", EDO_CHAIN]
        guard = 0
        while _iptables_check(hook) and guard < 5:
            results.append(_iptables_delete(hook))
            guard += 1
    return results


# ---- rule set: this is the part that diverges from edo -----------------
def _build_chain_rules(
    public_iface: str, peers_by_owner: Dict[Tuple[str, int], List[str]],
    octets_by_owner: Dict[Tuple[str, int], int],
) -> List[List[str]]:
    """Rules added to EDO_FORWARD, in evaluation order (first match wins).

    peers_by_owner: {(owner_type, owner_id): [wg_ip, ...]}
    octets_by_owner: {(owner_type, owner_id): octet}   (owners with no
        octet yet — i.e. no instance ever spawned for them — are skipped;
        their peers simply can't reach any docker subnet, which is correct.)
    """
    wg = str(WG_SUBNET)
    docker_pool = str(DOCKER_POOL)
    rules: List[List[str]] = [
        # (1) Participant isolation — unchanged from edo: no VPN client can
        #     reach another VPN client.
        [EDO_CHAIN, "-s", wg, "-d", wg, "-j", "DROP"],
    ]

    # (2) Per-owner accept: a peer may reach ONLY its own owner's subnet,
    #     in both directions (the reverse direction lets a container call
    #     back to the participant that deployed it, e.g. reverse shells).
    #     Enforced per peer IP — not per interface — because owners now
    #     share the same physical topology; only the subnet + peer IP
    #     combination tells them apart.
    for key, octet in octets_by_owner.items():
        subnet = str(owner_subnet(octet))
        for ip in peers_by_owner.get(key, []):
            rules.append([EDO_CHAIN, "-s", f"{ip}/32", "-d", subnet, "-j", "ACCEPT"])
            rules.append([EDO_CHAIN, "-s", subnet, "-d", f"{ip}/32", "-j", "ACCEPT"])

    # (3) Cross-owner container isolation — the rule edo doesn't have.
    #     Traffic between two different owners' /24s inside the pool is
    #     dropped. Same-owner traffic never reaches this rule: containers on
    #     the same owner's bridge talk to each other at L2, without being
    #     routed through FORWARD at all.
    rules.append([EDO_CHAIN, "-s", docker_pool, "-d", docker_pool, "-j", "DROP"])

    # (4) Egress containment — unchanged from edo: no container reaches the
    #     public internet via the host's default interface.
    rules.append([EDO_CHAIN, "-s", docker_pool, "-o", public_iface, "-j", "DROP"])

    return rules


def apply_firewall(
    peers_by_owner: Dict[Tuple[str, int], List[str]],
    octets_by_owner: Dict[Tuple[str, int], int],
    wg_port: int = 51820,
) -> FirewallApplyResult:
    """Idempotently rebuild all edo firewall rules from current DB state.

    Called after any peer or instance mutation (add/remove) rather than
    incrementally patching the chain — mirrors edo's own idempotent-rebuild
    philosophy (see _rewrite_server_config in wireguard.py) and keeps the
    rule set impossible to drift out of sync with the DB.
    """
    public_iface = get_public_interface()
    if not public_iface:
        raise RuntimeError("unable to determine public interface; refusing to apply firewall")

    try:
        _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"failed to enable net.ipv4.ip_forward: {(e.stderr or '').strip()}") from e

    subprocess.run(["iptables", "-N", EDO_CHAIN], capture_output=True, text=True)
    _unhook_edo_from_all()
    target = _preferred_forward_hook()
    try:
        _run(["iptables", "-I", target, "1", "-j", EDO_CHAIN])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"failed to hook {EDO_CHAIN} into {target}: {(e.stderr or '').strip()}") from e

    try:
        _run(["iptables", "-F", EDO_CHAIN])
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"failed to flush {EDO_CHAIN}: {(e.stderr or '').strip()}") from e

    result = FirewallApplyResult(public_interface=public_iface)
    for rule in _build_chain_rules(public_iface, peers_by_owner, octets_by_owner):
        res = _iptables_append(rule)
        result.rules.append(res)
        if not res.success:
            logger.error("rolling back firewall after rule failure: %s", rule)
            subprocess.run(["iptables", "-F", EDO_CHAIN], capture_output=True, text=True)
            raise RuntimeError(f"failed to install rule {rule}: {res.stderr}")

    input_result = apply_wg_input_rule(wg_port)
    result.rules.append(input_result)
    if not input_result.success:
        logger.error("could not open %d/udp for WireGuard: %s", wg_port, input_result.stderr)

    logger.info(
        "firewall applied (iface=%s, %d owners, %d rules)",
        public_iface, len(octets_by_owner), len(result.rules),
    )
    return result


def remove_firewall(wg_port: int = 51820) -> List[RuleResult]:
    results: List[RuleResult] = list(_unhook_edo_from_all())
    if _chain_exists(EDO_CHAIN):
        try:
            _run(["iptables", "-F", EDO_CHAIN])
            results.append(RuleResult(success=True, rule=["-F", EDO_CHAIN]))
        except subprocess.CalledProcessError as e:
            results.append(RuleResult(success=False, rule=["-F", EDO_CHAIN], stderr=(e.stderr or "").strip()))
        try:
            _run(["iptables", "-X", EDO_CHAIN])
            results.append(RuleResult(success=True, rule=["-X", EDO_CHAIN]))
        except subprocess.CalledProcessError as e:
            results.append(RuleResult(success=False, rule=["-X", EDO_CHAIN], stderr=(e.stderr or "").strip()))
    results.append(remove_wg_input_rule(wg_port))
    return results


# ---- subnet host iteration (ported verbatim from edo) -------------------
def iter_subnet_hosts(network: ipaddress.IPv4Network, exclude: List[str]) -> str:
    blocked = set(exclude)
    for host in network.hosts():
        candidate = str(host)
        if candidate not in blocked:
            return candidate
    raise RuntimeError(f"subnet {network} is exhausted")


def ordered_subnet_hosts(network: ipaddress.IPv4Network, reserved: List[str]) -> List[str]:
    blocked = set(reserved)
    return [str(h) for h in network.hosts() if str(h) not in blocked]
