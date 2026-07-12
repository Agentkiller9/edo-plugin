"""Docker control plane for the edo daemon.

Ported from edo's src/docker_mgr.py: the security profile, the CLI-based
build (streams full output, falls back to the SDK builder), the retry-on-
address-in-use loop, and the reconcile pattern are all edo's proven
approach and carry over unchanged in spirit.

What's new, because edo's model doesn't have it:
  * Every owner (team or user) gets its OWN Docker network — a routed-mode
    bridge over that owner's /24 (see network.owner_subnet) — instead of
    edo's single shared edo_br0. Container names are owner-scoped
    (`edo_<challenge_ref>_<owner_type>_<owner_id>`) so the same challenge
    can run simultaneously for many owners, which edo's flat
    `edo_<challenge>` naming does not allow.
  * TTL: spawn_instance accepts ttl_seconds and stores expires_at. edo has
    no expiry concept at all — the plugin-side scheduler is what actually
    acts on expires_at (calls release_instance); this module just persists
    and reports it.
"""
from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Tuple

try:
    import docker
    from docker.errors import APIError, BuildError, DockerException, ImageNotFound, NotFound

    _DOCKER_SDK_AVAILABLE = True
except ImportError:
    docker = None  # type: ignore[assignment]
    _DOCKER_SDK_AVAILABLE = False

    class APIError(Exception):  # type: ignore[no-redef]
        pass

    class BuildError(Exception):  # type: ignore[no-redef]
        pass

    class DockerException(Exception):  # type: ignore[no-redef]
        pass

    class ImageNotFound(Exception):  # type: ignore[no-redef]
        pass

    class NotFound(Exception):  # type: ignore[no-redef]
        pass

from .db import DatabaseManager, Instance
from .network import bridge_name, owner_gateway_ip, owner_subnet

logger = logging.getLogger(__name__)

MANAGED_LABEL = "edo.managed"
OWNER_TYPE_LABEL = "edo.owner_type"
OWNER_ID_LABEL = "edo.owner_id"
CHALLENGE_LABEL = "edo.challenge_ref"
EXPIRES_LABEL = "edo.expires_at"
PORTS_LABEL = "edo.ports"

# access_mode="public" challenges (see spawn_instance's publish_ports) get
# host ports from this fixed, narrow range instead of Docker's default
# ephemeral span (32768-60999) — a firewall in front of this host only
# needs one small range opened, not the whole ephemeral space.
PUBLIC_PORT_RANGE_START = int(os.environ.get("EDO_PUBLIC_PORT_RANGE_START", "40000"))
PUBLIC_PORT_RANGE_END = int(os.environ.get("EDO_PUBLIC_PORT_RANGE_END", "41000"))


@dataclass
class SecurityProfile:
    """Ported verbatim from edo — container-level security/resource controls."""

    no_new_privileges: bool = True
    cap_drop: List[str] = field(default_factory=lambda: ["NET_RAW"])
    cap_add: List[str] = field(default_factory=list)
    read_only_rootfs: bool = False
    memory: Optional[str] = None
    cpus: Optional[float] = None
    pids_limit: Optional[int] = None
    restart_policy: str = "unless-stopped"

    def summary(self) -> str:
        bits: List[str] = []
        if self.no_new_privileges:
            bits.append("no-new-privs")
        if self.cap_drop:
            bits.append(f"cap-drop={'+'.join(self.cap_drop)}")
        if self.cap_add:
            bits.append(f"cap-add={'+'.join(self.cap_add)}")
        if self.read_only_rootfs:
            bits.append("read-only")
        if self.memory:
            bits.append(f"mem={self.memory}")
        if self.cpus is not None:
            bits.append(f"cpus={self.cpus}")
        if self.pids_limit is not None:
            bits.append(f"pids={self.pids_limit}")
        bits.append(f"restart={self.restart_policy}")
        return " ".join(bits)


def _build_secure_host_config(
    client: "docker.DockerClient",
    profile: SecurityProfile,
    publish_ports: Optional[dict] = None,
) -> dict:
    """
    By default never sets port_bindings. Docker's host-port publishing
    installs its own NAT/DNAT rules in the `nat` table's DOCKER chain,
    which are evaluated on PREROUTING — *before* our EDO_FORWARD isolation
    rules in the `filter` table ever see the packet. A published port would
    be reachable from the entire public internet via <host-ip>:<port>,
    completely bypassing per-owner VPN isolation. Participants normally
    reach a container via its own routed IP over the VPN (see network.py).

    publish_ports is the deliberate, explicit exception: for a challenge an
    admin has opted into access_mode="public" (see EdoChallenge.access_mode
    / models.py), bypassing that isolation is the intended behavior, not a
    regression of it — the whole point is reachability without a VPN, same
    as a normal public web challenge. It's a {container_port: host_port}
    mapping — explicit host ports (from PUBLIC_PORT_RANGE_START/_END, see
    _allocate_public_ports), not Docker's own random-ephemeral-port
    behavior, so a firewall in front of this host only needs one small
    range opened rather than the whole ephemeral span.
    """
    kwargs: dict = {"restart_policy": {"Name": profile.restart_policy}}
    security_opt: List[str] = []
    if profile.no_new_privileges:
        security_opt.append("no-new-privileges:true")
    if security_opt:
        kwargs["security_opt"] = security_opt
    if profile.cap_drop:
        kwargs["cap_drop"] = list(profile.cap_drop)
    if profile.cap_add:
        kwargs["cap_add"] = list(profile.cap_add)
    if profile.memory:
        kwargs["mem_limit"] = profile.memory
    if profile.cpus is not None:
        kwargs["nano_cpus"] = int(profile.cpus * 1_000_000_000)
    if profile.pids_limit is not None:
        kwargs["pids_limit"] = profile.pids_limit
    if profile.read_only_rootfs:
        kwargs["read_only"] = True
        kwargs["tmpfs"] = {"/tmp": "rw,size=64m,exec"}
    if publish_ports:
        kwargs["port_bindings"] = dict(publish_ports)
    return client.api.create_host_config(**kwargs)


@dataclass
class SpawnResult:
    success: bool
    instance: Optional[Instance] = None
    error: Optional[str] = None


def _run(cmd: List[str], cwd: Optional[Path] = None, check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("exec: %s (cwd=%s)", " ".join(cmd), cwd)
    return subprocess.run(cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, check=check)


def _require_docker() -> None:
    if not _DOCKER_SDK_AVAILABLE:
        raise RuntimeError("docker python SDK not installed (pip install docker)")


_client_cache: Optional["docker.DockerClient"] = None


def _client() -> "docker.DockerClient":
    global _client_cache
    if _client_cache is not None:
        return _client_cache
    _require_docker()
    try:
        client = docker.from_env()
        client.ping()
    except DockerException as e:
        raise RuntimeError(f"docker unavailable: {e}") from e
    _client_cache = client
    return client


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def container_name_for(challenge_ref: str, owner_type: str, owner_id: int) -> str:
    """Owner-scoped container name — edo's naming has no owner component,
    which is exactly why it can only run one instance of a challenge at a
    time, globally. This lets the same challenge run for every owner at
    once.
    """
    return f"edo_{_slug(challenge_ref)}_{owner_type}_{owner_id}"


def image_tag_for(challenge_ref: str) -> str:
    """Images are built once and shared across owners — only the running
    container is owner-scoped, not the image."""
    return f"edo/{_slug(challenge_ref)}:latest"


def _detect_exposed_ports(client: "docker.DockerClient", image_tag: str) -> List[str]:
    """Read the built image's EXPOSE directive(s) instead of asking admins
    to duplicate that information in the challenge form. Docker containers
    inherit ExposedPorts from the image automatically at create time — we
    only need this list ourselves to tell participants which port to
    connect to. Returns e.g. ["1337/tcp"]; empty if the Dockerfile has no
    EXPOSE at all (still valid — some challenges are pure reverse-shell).
    """
    try:
        img = client.images.get(image_tag)
        exposed = img.attrs.get("Config", {}).get("ExposedPorts") or {}
        return sorted(exposed.keys())
    except (APIError, ImageNotFound):
        return []


_buildkit_ok: Optional[bool] = None


def _buildkit_available() -> bool:
    global _buildkit_ok
    if _buildkit_ok is not None:
        return _buildkit_ok
    try:
        proc = subprocess.run(["docker", "buildx", "version"], capture_output=True, text=True, check=False)
        _buildkit_ok = proc.returncode == 0
    except OSError:
        _buildkit_ok = False
    return _buildkit_ok


def build_image(image_tag: str, path: Path) -> Tuple[bool, str]:
    """Ported from edo: shell out to `docker build` (streams the real
    error on failure, unlike the SDK's legacy builder), falling back to the
    SDK if the CLI isn't on PATH.
    """
    if shutil.which("docker") is None:
        return _build_image_sdk(image_tag, path)
    use_buildkit = _buildkit_available()
    env = {**os.environ, "DOCKER_BUILDKIT": "1" if use_buildkit else "0"}
    try:
        proc = subprocess.run(["docker", "build", "-t", image_tag, str(path)], cwd=str(path), env=env, check=False)
    except FileNotFoundError:
        return _build_image_sdk(image_tag, path)
    if proc.returncode != 0:
        return False, f"docker build failed (exit {proc.returncode})"
    return True, ""


def _build_image_sdk(image_tag: str, path: Path) -> Tuple[bool, str]:
    client = _client()
    try:
        client.images.build(path=str(path), tag=image_tag, rm=True)
        return True, ""
    except (BuildError, APIError) as e:
        return False, f"build failed: {e}"


# ---- per-owner network -----------------------------------------------

def _network_is_routed(net) -> bool:
    opts = net.attrs.get("Options") or {}
    return opts.get("com.docker.network.bridge.gateway_mode_ipv4") == "routed"


def ensure_owner_network(db: DatabaseManager, owner_type: str, owner_id: int) -> int:
    """Idempotently create this owner's dedicated Docker network.

    Returns the octet (also the last thing db.allocate_octet returns, so
    this is safe to call on every spawn — it's a no-op after the first).
    """
    octet = db.allocate_octet(owner_type, owner_id)
    client = _client()
    name = bridge_name(octet)
    subnet = owner_subnet(octet)
    gateway = owner_gateway_ip(octet)

    try:
        existing = client.networks.get(name)
        if _network_is_routed(existing):
            return octet
        raise RuntimeError(
            f"docker network '{name}' exists but is not in routed mode; "
            "remove it manually (docker network rm) and retry"
        )
    except NotFound:
        pass

    ipam_pool = docker.types.IPAMPool(subnet=str(subnet), gateway=gateway)
    ipam_config = docker.types.IPAMConfig(pool_configs=[ipam_pool])
    options = {
        "com.docker.network.bridge.name": name,
        "com.docker.network.bridge.gateway_mode_ipv4": "routed",
    }
    try:
        client.networks.create(
            name=name, driver="bridge", ipam=ipam_config, options=options,
            check_duplicate=True,
            labels={OWNER_TYPE_LABEL: owner_type, OWNER_ID_LABEL: str(owner_id)},
        )
    except APIError as e:
        msg = str(e)
        if "gateway_mode" in msg or "unknown option" in msg.lower():
            raise RuntimeError(
                f"Docker rejected routed-mode networking (needs Docker 24.0+): {msg}"
            ) from e
        raise
    logger.info("created owner network %s (%s) for %s:%s", name, subnet, owner_type, owner_id)
    return octet


def release_owner_network_if_idle(db: DatabaseManager, owner_type: str, owner_id: int) -> None:
    """Tear down an owner's network + free their octet once they have zero
    instances left. The next spawn recreates it (possibly with a different
    octet) — cheap, and keeps the firewall rule set free of stale owners.
    """
    if db.count_instances_for_owner(owner_type, owner_id) > 0:
        return
    octet = db.get_octet(owner_type, owner_id)
    if octet is None:
        return
    client = _client()
    name = bridge_name(octet)
    try:
        client.networks.get(name).remove()
    except (NotFound, APIError) as e:
        logger.debug("owner network %s already gone or busy: %s", name, e)
        return
    db.free_octet(owner_type, owner_id)
    logger.info("released owner network %s for %s:%s", name, owner_type, owner_id)


def find_next_owner_ip(db: DatabaseManager, owner_type: str, owner_id: int, octet: int) -> str:
    from .network import iter_subnet_hosts

    blocked = list(db.get_used_instance_ips(owner_type, owner_id)) + [owner_gateway_ip(octet)]
    return iter_subnet_hosts(owner_subnet(octet), blocked)


def _is_resource_conflict(err) -> bool:
    """Matches both an IP-allocation conflict (owner subnet already has
    that address) and a host-port conflict (access_mode="public" — see
    _allocate_public_ports) — Docker's actual wording differs ("address
    already in use" vs "port is already allocated"), but the caller's
    response is identical either way: retry with a fresh IP AND fresh
    ports together, not worth distinguishing which one actually conflicted.
    """
    msg = str(err).lower()
    return (
        "address already in use" in msg or "is already in use" in msg
        or "no available" in msg or "overlaps" in msg
        or "already allocated" in msg
    )


def _used_public_ports(db: DatabaseManager) -> set:
    """Every host port currently published across all tracked instances —
    scanned fresh each call (small N, an owner's whole instance list) same
    as find_next_owner_ip does for IPs."""
    used: set = set()
    for inst in db.get_all_instances():
        if not inst.published_ports:
            continue
        try:
            used.update(int(p) for p in json.loads(inst.published_ports).values())
        except (ValueError, TypeError, AttributeError):
            continue
    return used


def _allocate_public_ports(db: DatabaseManager, count: int, exclude: set = frozenset()) -> List[int]:
    """Pick `count` distinct free host ports from the configured public
    range (PUBLIC_PORT_RANGE_START/_END). Raises RuntimeError if the range
    is exhausted — a real operational limit an admin needs to widen the
    range for, not something to retry past.
    """
    used = _used_public_ports(db) | {int(p) for p in exclude}
    chosen: List[int] = []
    for port in range(PUBLIC_PORT_RANGE_START, PUBLIC_PORT_RANGE_END + 1):
        if port not in used:
            chosen.append(port)
            if len(chosen) == count:
                return chosen
    raise RuntimeError(
        f"no free ports left in range {PUBLIC_PORT_RANGE_START}-{PUBLIC_PORT_RANGE_END}"
    )


def _live_container_ip(container, network_name: str) -> Optional[str]:
    try:
        container.reload()
    except APIError:
        return None
    net = container.attrs.get("NetworkSettings", {}).get("Networks", {}).get(network_name, {})
    return net.get("IPAddress") or None


def _live_published_ports(container) -> dict:
    """Read back the actual host ports Docker bound for this container
    (access_mode="public" challenges only — see spawn_instance's
    publish_ports). {} if none are published."""
    live_ports = container.attrs.get("NetworkSettings", {}).get("Ports") or {}
    return {
        container_port: int(bindings[0]["HostPort"])
        for container_port, bindings in live_ports.items()
        if bindings
    }


# ---- spawn / release ----------------------------------------------------

def spawn_instance(
    db: DatabaseManager,
    owner_type: str,
    owner_id: int,
    challenge_ref: str,
    build_path: Path,
    security: Optional[SecurityProfile] = None,
    ttl_seconds: Optional[int] = None,
    publish_ports: bool = False,
) -> SpawnResult:
    """Build (if needed) and run one owner-scoped container.

    Idempotent: if this (owner, challenge_ref) already has a tracked
    instance, returns it rather than spawning a duplicate — mirrors the DB
    unique constraint on (owner_type, owner_id, challenge_ref).

    By default no port is ever published to the host (see
    _build_secure_host_config) — participants reach the container directly
    at its own routed IP over the VPN, so the ports the container listens
    on are read straight from the Dockerfile's EXPOSE metadata after
    build. publish_ports=True is the explicit per-challenge opt-out (see
    EdoChallenge.access_mode): each exposed port gets bound to a
    dynamically-allocated host port instead, read back after the container
    starts and returned as part of the Instance.
    """
    existing = db.find_instance(owner_type, owner_id, challenge_ref)
    if existing is not None:
        return SpawnResult(success=True, instance=existing)

    if not (build_path / "Dockerfile").is_file():
        return SpawnResult(success=False, error=f"no Dockerfile in {build_path}")

    profile = security or SecurityProfile()
    octet = ensure_owner_network(db, owner_type, owner_id)
    network_name = bridge_name(octet)
    client = _client()
    image_tag = image_tag_for(challenge_ref)

    ok, build_error = build_image(image_tag, build_path)
    if not ok:
        return SpawnResult(success=False, error=build_error)

    exposed_ports = _detect_exposed_ports(client, image_tag)

    name = container_name_for(challenge_ref, owner_type, owner_id)
    expires_at = None
    if ttl_seconds is not None:
        expires_at = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()

    container = None
    assigned_ip: Optional[str] = None
    tried_ips: List[str] = []
    tried_ports: set = set()
    last_error = ""
    for _ in range(8):
        assigned_ip = find_next_owner_ip(db, owner_type, owner_id, octet)
        if assigned_ip in tried_ips:
            continue

        port_map: Optional[dict] = None
        if publish_ports and exposed_ports:
            try:
                host_ports = _allocate_public_ports(db, len(exposed_ports), exclude=tried_ports)
            except RuntimeError as e:
                return SpawnResult(success=False, error=str(e))
            port_map = dict(zip(exposed_ports, host_ports))
        host_cfg = _build_secure_host_config(client, profile, publish_ports=port_map)

        try:
            endpoint_cfg = client.api.create_endpoint_config(ipv4_address=assigned_ip)
            networking_cfg = client.api.create_networking_config({network_name: endpoint_cfg})
            created = client.api.create_container(
                image=image_tag,
                name=name,
                networking_config=networking_cfg,
                host_config=host_cfg,
                labels={
                    MANAGED_LABEL: "true",
                    OWNER_TYPE_LABEL: owner_type,
                    OWNER_ID_LABEL: str(owner_id),
                    CHALLENGE_LABEL: challenge_ref,
                    EXPIRES_LABEL: expires_at or "",
                    PORTS_LABEL: ",".join(exposed_ports),
                },
            )
            client.api.start(created["Id"])
            container = client.containers.get(created["Id"])
            break
        except APIError as e:
            last_error = str(e)
            try:
                client.containers.get(name).remove(force=True)
            except (APIError, NotFound):
                pass
            if _is_resource_conflict(e):
                tried_ips.append(assigned_ip)
                if port_map:
                    tried_ports.update(port_map.values())
                continue
            return SpawnResult(success=False, error=f"run failed: {last_error}")

    if container is None:
        return SpawnResult(success=False, error=f"could not allocate a free IP: {last_error}")

    assigned_ip = _live_container_ip(container, network_name) or assigned_ip
    container.reload()

    published_port_map = _live_published_ports(container) if publish_ports else {}

    try:
        instance = db.add_instance(
            container_id=container.id,
            container_name=name,
            owner_type=owner_type,
            owner_id=owner_id,
            challenge_ref=challenge_ref,
            assigned_ip=assigned_ip,
            ports=json.dumps(exposed_ports),
            published_ports=json.dumps(published_port_map) if published_port_map else None,
            expires_at=expires_at,
        )
    except Exception as e:
        logger.exception("DB logging failed, tearing down container")
        try:
            container.remove(force=True)
        except APIError:
            pass
        return SpawnResult(success=False, error=f"db logging failed: {e}")

    logger.info(
        "spawned %s for %s:%s @ %s [%s]",
        challenge_ref, owner_type, owner_id, assigned_ip, profile.summary(),
    )
    return SpawnResult(success=True, instance=instance)


def release_instance(db: DatabaseManager, container_id: str) -> bool:
    client = _client()
    inst = None
    for row in db.get_all_instances():
        if row.container_id == container_id:
            inst = row
            break

    try:
        c = client.containers.get(container_id)
        c.stop(timeout=10)
        c.remove(force=True)
    except NotFound:
        logger.warning("container %s not in docker; clearing DB record anyway", container_id[:12])
    except APIError as e:
        logger.error("teardown failed for %s: %s", container_id[:12], e)
        return False

    removed = db.remove_instance(container_id)
    if inst is not None:
        release_owner_network_if_idle(db, inst.owner_type, inst.owner_id)
    return removed


def teardown_all(db: DatabaseManager) -> int:
    count = 0
    for inst in db.get_active_instances():
        if release_instance(db, inst.container_id):
            count += 1
    return count


# ---- reconciliation + startup adoption -----------------------------------

def reconcile(db: DatabaseManager) -> int:
    """Sync DB instance records with reality. Returns rows pruned."""
    client = _client()
    pruned = 0
    for inst in db.get_active_instances():
        try:
            c = client.containers.get(inst.container_id)
            if c.status != inst.status:
                db.update_instance_status(inst.container_id, c.status)
        except NotFound:
            db.remove_instance(inst.container_id)
            release_owner_network_if_idle(db, inst.owner_type, inst.owner_id)
            pruned += 1
        except APIError as e:
            logger.debug("reconcile skip %s: %s", inst.container_id[:12], e)
    return pruned


def adopt_untracked(db: DatabaseManager) -> int:
    """At daemon startup, find edo-managed containers the DB doesn't know
    about (daemon restarted, state.db was lost/rotated, etc.) and adopt
    them back in rather than orphaning them silently.
    """
    client = _client()
    known_ids = {i.container_id for i in db.get_all_instances()}
    adopted = 0
    try:
        containers = client.containers.list(all=True, filters={"label": MANAGED_LABEL})
    except APIError:
        return 0
    for c in containers:
        if c.id in known_ids:
            continue
        labels = c.labels or {}
        owner_type = labels.get(OWNER_TYPE_LABEL)
        owner_id = labels.get(OWNER_ID_LABEL)
        challenge_ref = labels.get(CHALLENGE_LABEL)
        if not (owner_type and owner_id and challenge_ref):
            continue
        octet = db.get_octet(owner_type, int(owner_id))
        network_name = bridge_name(octet) if octet else ""
        ip = _live_container_ip(c, network_name) or ""
        expires = labels.get(EXPIRES_LABEL) or None
        ports = [p for p in (labels.get(PORTS_LABEL) or "").split(",") if p]
        published = _live_published_ports(c)
        try:
            db.add_instance(
                container_id=c.id, container_name=c.name,
                owner_type=owner_type, owner_id=int(owner_id),
                challenge_ref=challenge_ref, assigned_ip=ip,
                ports=json.dumps(ports),
                published_ports=json.dumps(published) if published else None,
                expires_at=expires, status=c.status,
            )
            adopted += 1
        except ValueError:
            continue  # already tracked under a different key; leave it
    if adopted:
        logger.info("adopted %d untracked container(s) at startup", adopted)
    return adopted
