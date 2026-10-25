"""DNS Response Policy Zone (RPZ) adapter.

Maintains one RPZ zone file for a resolver (BIND, Unbound, PowerDNS Recursor,
Knot Resolver all load RPZ). The adapter's source of truth is a JSON state file
next to the zone (``<zone>.state.json``) holding one entry per action; the zone
file is fully re-rendered from it on every change, written atomically
(temp file + fsync + rename) with a strictly increasing SOA serial.

Policy records written:

* ``DNS_SINKHOLE``: QNAME trigger ``<name> CNAME .`` (NXDOMAIN), ``CNAME *.``
  (NODATA) or ``CNAME <walled-garden host>.`` (sinkhole), plus ``*.<name>`` when
  the action scope sets ``include_subdomains``;
* ``IP_BLOCK``: response-IP trigger ``32.<reversed octets>.rpz-ip`` (IPv4) or
  ``128.<reversed groups, zz for ::>.rpz-ip`` (IPv6), which blocks any answer
  containing that address.

Each block of records is preceded by a comment with the action id, case id and
expiry, and each record carries a TTL no longer than the time left before the
action expires, so resolvers never cache a policy beyond its authorization.
Expired entries are omitted whenever the zone is rendered.

Owner names are written relative to the zone origin, as RPZ requires. Targets are
strictly validated before they reach the file, so a hostile target string can
never inject zone syntax.
"""
from __future__ import annotations

import contextlib
import hashlib
import ipaddress
import json
import os
import subprocess
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Literal, Sequence

from aegis.contracts.models import ActionType, ProposedAction
from aegis.mirror.base import (
    AdapterError,
    AdapterResult,
    EnforcementAdapter,
    InvalidTargetError,
    normalize_domain,
    normalize_ip,
)

try:  # POSIX advisory lock so two processes never interleave zone writes
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms fall back to the thread lock
    _fcntl = None  # type: ignore[assignment]

PolicyAction = Literal["nxdomain", "nodata", "sinkhole"]

STATE_VERSION = 1


def rpz_ip_owner(ip: str) -> str:
    """RPZ response-IP trigger owner name (relative) for a single host address."""
    addr = ipaddress.ip_address(normalize_ip(ip))
    if isinstance(addr, ipaddress.IPv4Address):
        return "32." + ".".join(reversed(addr.compressed.split("."))) + ".rpz-ip"
    comp = addr.compressed
    if "::" in comp:
        left, right = comp.split("::", 1)
        groups = (left.split(":") if left else []) + ["zz"] + (right.split(":") if right else [])
    else:
        groups = comp.split(":")
    return "128." + ".".join(reversed(groups)) + ".rpz-ip"


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def _parse_ts(value: str | None) -> datetime | None:
    return _utc(datetime.fromisoformat(value)) if value else None


class RPZAdapter(EnforcementAdapter):
    """Writes DNS sinkhole / IP block policies into an RPZ zone file."""

    name = "rpz"
    dry_run = False
    supported_actions = frozenset({ActionType.DNS_SINKHOLE, ActionType.IP_BLOCK})

    def __init__(self, zone_path: str | Path, *, origin: str = "rpz.aegis.local",
                 policy_action: PolicyAction = "nxdomain", sinkhole_host: str | None = None,
                 default_ttl: int = 300, soa_mname: str = "localhost.",
                 soa_rname: str = "hostmaster.localhost.",
                 reload_command: Sequence[str] | None = None, reload_timeout_s: float = 30.0):
        if default_ttl < 1 or default_ttl > 86400:
            raise ValueError("default_ttl must be in [1, 86400] seconds")
        if policy_action not in ("nxdomain", "nodata", "sinkhole"):
            raise ValueError("policy_action must be nxdomain, nodata or sinkhole")
        if policy_action == "sinkhole":
            if not sinkhole_host:
                raise ValueError("sinkhole policy requires sinkhole_host")
            sinkhole_host = normalize_domain(sinkhole_host)
        self.origin = normalize_domain(origin)
        self.zone_path = Path(zone_path)
        self.state_path = self.zone_path.with_name(self.zone_path.name + ".state.json")
        self.policy_action: PolicyAction = policy_action
        self.sinkhole_host = sinkhole_host
        self.default_ttl = default_ttl
        self.soa_mname = self._abs_name(soa_mname)
        self.soa_rname = self._abs_name(soa_rname)
        self.reload_command = list(reload_command) if reload_command else None
        self.reload_timeout_s = reload_timeout_s
        self._lock = threading.Lock()

    @staticmethod
    def _abs_name(name: str) -> str:
        n = name.strip()
        if n in (".", "localhost."):
            return n
        return normalize_domain(n) + "."

    # ------------------------------------------------------------------ public API
    def apply(self, action: ProposedAction, *, now: datetime) -> AdapterResult:
        self.check_supported(action)
        if action.expires_at is None:
            raise AdapterError("RPZ entries must carry an expiry")
        records = self._records_for(action)
        entry = {
            "case_id": action.case_id,
            "action_type": action.action_type.value,
            "expires_at": _utc(action.expires_at).isoformat(),
            "created_at": _utc(now).isoformat(),
            "records": records,
        }
        with self._locked():
            state = self._load_state()
            before_sha = self._zone_sha()
            prior = state["entries"].get(action.action_id)
            state["entries"][action.action_id] = entry
            serial = self._commit(state, now)
        return AdapterResult(
            adapter=self.name, operation="apply",
            prior_state={"entry": prior, "zone_sha256_before": before_sha},
            details={"zone": str(self.zone_path), "origin": self.origin, "serial": serial,
                     "records": records})

    def revert(self, action: ProposedAction, prior_state: dict[str, Any], *,
               now: datetime) -> AdapterResult:
        prior = prior_state.get("entry") if isinstance(prior_state, dict) else None
        with self._locked():
            state = self._load_state()
            removed = state["entries"].pop(action.action_id, None)
            if isinstance(prior, dict):
                state["entries"][action.action_id] = prior
            serial = self._commit(state, now)
        return AdapterResult(
            adapter=self.name, operation="revert",
            details={"zone": str(self.zone_path), "serial": serial,
                     "removed_records": (removed or {}).get("records", []),
                     "restored_entry": prior is not None})

    def records(self, now: datetime | None = None) -> list[tuple[str, str]]:
        """Active ``(owner, rdata)`` policy records as they appear in the zone."""
        ref = _utc(now) if now is not None else datetime.now(timezone.utc)
        with self._locked():
            state = self._load_state()
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        for _aid, entry in self._active(state, ref):
            for r in entry["records"]:
                if r["owner"] not in seen:
                    seen.add(r["owner"])
                    out.append((r["owner"], r["rdata"]))
        return out

    def entries(self) -> dict[str, dict[str, Any]]:
        """Raw per-action state (including expired entries not yet removed)."""
        with self._locked():
            return json.loads(json.dumps(self._load_state()["entries"]))

    def refresh(self, now: datetime) -> int:
        """Re-render the zone (dropping expired entries from the file); returns the serial."""
        with self._locked():
            return self._commit(self._load_state(), now)

    def render(self, now: datetime) -> str:
        with self._locked():
            state = self._load_state()
        return self._render(state, now, int(state.get("serial", 0)))

    # ------------------------------------------------------------------ internals
    def _rdata(self) -> str:
        if self.policy_action == "nxdomain":
            return "."
        if self.policy_action == "nodata":
            return "*."
        return f"{self.sinkhole_host}."

    def _records_for(self, action: ProposedAction) -> list[dict[str, str]]:
        rdata = self._rdata()
        out: list[dict[str, str]] = []
        if action.action_type is ActionType.DNS_SINKHOLE:
            wildcard = bool(action.scope.get("include_subdomains", False))
            for t in action.targets:
                d = normalize_domain(t)
                if d == self.origin or d.endswith("." + self.origin):
                    raise InvalidTargetError(f"target {d!r} lies inside the RPZ origin")
                out.append({"owner": d, "rdata": rdata})
                if wildcard:
                    out.append({"owner": f"*.{d}", "rdata": rdata})
        else:
            for t in action.targets:
                out.append({"owner": rpz_ip_owner(t), "rdata": rdata})
        if not out:
            raise InvalidTargetError("action has no targets")
        dedup: dict[str, dict[str, str]] = {}
        for r in out:
            dedup.setdefault(r["owner"], r)
        return list(dedup.values())

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        with self._lock:
            self.zone_path.parent.mkdir(parents=True, exist_ok=True)
            if _fcntl is None:
                yield
                return
            lock_path = self.zone_path.with_name(self.zone_path.name + ".lock")
            with open(lock_path, "a+") as fh:
                _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"version": STATE_VERSION, "origin": self.origin, "serial": 0, "entries": {}}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise AdapterError(f"RPZ state file unreadable: {exc}") from exc
        if not isinstance(data, dict) or not isinstance(data.get("entries"), dict):
            raise AdapterError("RPZ state file is malformed")
        if data.get("origin") != self.origin:
            raise AdapterError(f"RPZ state file belongs to origin {data.get('origin')!r}")
        return data

    def _zone_sha(self) -> str | None:
        if not self.zone_path.exists():
            return None
        return hashlib.sha256(self.zone_path.read_bytes()).hexdigest()

    @staticmethod
    def _active(state: dict[str, Any], now: datetime) -> list[tuple[str, dict[str, Any]]]:
        out = []
        for aid, entry in state["entries"].items():
            exp = _parse_ts(entry.get("expires_at"))
            if exp is not None and exp > now:
                out.append((aid, entry))
        return out

    def _render(self, state: dict[str, Any], now: datetime, serial: int) -> str:
        now = _utc(now)
        lines = [
            "; AEGIS OMEGA SHIELD response policy zone - generated file, do not edit by hand.",
            f"; origin={self.origin} serial={serial} generated={now.isoformat()}",
            f"$ORIGIN {self.origin}.",
            f"$TTL {self.default_ttl}",
            (f"@ IN SOA {self.soa_mname} {self.soa_rname} ( {serial} 3600 600 86400 "
            f"{self.default_ttl} )"),
            f"@ IN NS {self.soa_mname}",
        ]
        seen: set[str] = set()
        for aid, entry in self._active(state, now):
            exp = _parse_ts(entry["expires_at"])
            assert exp is not None
            remaining = int((exp - now).total_seconds())
            ttl = max(1, min(self.default_ttl, remaining))
            lines.append("")
            lines.append(f"; action={aid} case={entry.get('case_id', '')} "
                         f"type={entry.get('action_type', '')} expires={exp.isoformat()} "
                         f"ttl={ttl}")
            for r in entry["records"]:
                if r["owner"] in seen:
                    lines.append(f"; {r['owner']} already listed by an earlier action")
                    continue
                seen.add(r["owner"])
                lines.append(f"{r['owner']} {ttl} IN CNAME {r['rdata']}")
        return "\n".join(lines) + "\n"

    def _commit(self, state: dict[str, Any], now: datetime) -> int:
        """Write state + zone atomically, reload the resolver; restore files on failure."""
        old_state = self.state_path.read_bytes() if self.state_path.exists() else None
        old_zone = self.zone_path.read_bytes() if self.zone_path.exists() else None
        serial = max(int(state.get("serial", 0)) + 1, int(_utc(now).timestamp()))
        if serial >= 2 ** 32:
            raise AdapterError("RPZ serial overflow")
        state = dict(state, serial=serial, version=STATE_VERSION, origin=self.origin)
        zone_text = self._render(state, now, serial)
        try:
            self._atomic_write(self.state_path,
                               json.dumps(state, indent=2, sort_keys=False).encode("utf-8"))
            self._atomic_write(self.zone_path, zone_text.encode("utf-8"))
            self._reload()
        except Exception as exc:
            self._restore(self.state_path, old_state)
            self._restore(self.zone_path, old_zone)
            if isinstance(exc, AdapterError):
                raise
            raise AdapterError(f"RPZ write failed: {exc}") from exc
        return serial

    @staticmethod
    def _atomic_write(path: Path, data: bytes) -> None:
        fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise

    def _restore(self, path: Path, data: bytes | None) -> None:
        with contextlib.suppress(OSError):
            if data is None:
                path.unlink(missing_ok=True)
            else:
                self._atomic_write(path, data)

    def _reload(self) -> None:
        if not self.reload_command:
            return
        try:
            proc = subprocess.run(self.reload_command, capture_output=True,
                                  timeout=self.reload_timeout_s, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AdapterError(f"resolver reload failed: {exc}") from exc
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", "replace").strip()[:500]
            raise AdapterError(f"resolver reload exited {proc.returncode}: {err}")
