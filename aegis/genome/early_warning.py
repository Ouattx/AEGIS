"""Early warning: new C2 infrastructure seen first on Box Farm lab devices.

When a lab box infected with a known family starts checking in to destinations that
are not in the family's genome yet, with timing that matches the genome, those
destinations are candidate new infrastructure. They are published as an
``aegis.ioc_bundle/1`` bundle (the format :func:`aegis.sentinel.rules.load_bundle`
verifies), signed, every indicator tagged ``lab-observed`` and
``not-yet-seen-in-tenant`` until a tenant actually contacts it.

Exposure checks run per tenant (:func:`tenant_exposure`, one tenant's event table at a
time, under that tenant's authorization). :func:`exposure_summary` only combines results
the caller already obtained tenant by tenant; there is no cross-tenant query path.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

import numpy as np

from aegis.genome.capture import LabCapture
from aegis.genome.detector import GenomeConfig, MatchedFilter
from aegis.genome.extract import capture_keys
from aegis.genome.models import Genome
from aegis.lab.iocs import sign_bundle
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.events import EventTable, build_event_table, prepare_series

BUNDLE_SCHEMA = "aegis.ioc_bundle/1"
LAB_SOURCE = "lab:boxfarm-genome"
LAB_GROUP = "grp:boxfarm-lab"
TAG_LAB = "lab-observed"
TAG_UNSEEN = "not-yet-seen-in-tenant"
STATUS_UNSEEN = "lab-observed, not yet seen in tenant"
STATUS_SEEN = "seen in tenant"


@dataclass
class NewInfraCandidate:
    key: str                              # d:<domain> or ip:<addr>
    genome_id: str
    family: str | None
    capture_id: str
    match_z: float
    n_events: int
    first_seen: datetime
    last_seen: datetime
    related_keys: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {"key": self.key, "genome_id": self.genome_id, "family": self.family, "capture_id": self.capture_id,
                "match_z": round(self.match_z, 3), "n_events": self.n_events,
                "first_seen": self.first_seen.isoformat(), "last_seen": self.last_seen.isoformat(),
                "related_keys": self.related_keys}


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def detect_new_infrastructure(genome: Genome, capture: LabCapture, *, known_keys: Iterable[str] = (),
                              clean_reference: Iterable[LabCapture] = (), z_min: float = 6.0,
                              min_events: int = 8, cfg: GenomeConfig | None = None) -> list[NewInfraCandidate]:
    """Destinations of ``capture`` whose timing matches ``genome`` and that are not yet known.

    Destinations the clean reference box contacts (its own benign behavior) are never candidates.
    """
    cfg = cfg or GenomeConfig()
    benign: set[str] = set()
    for rc in clean_reference:
        benign |= capture_keys(rc)
    known = set(known_keys) | set(genome.c2_keys)
    flows, dns = capture.frames_with_line()
    tb = build_event_table(flows if len(flows) else None, dns if len(dns) else None,
                           start=capture.start.timestamp(), end=capture.end.timestamp())
    if len(tb) == 0:
        return []
    rcfg = ResonanceConfig(series_cap=100_000)
    S = prepare_series(tb, rcfg)
    rows = np.flatnonzero(S.counts >= min_events)
    if len(rows) == 0:
        return []
    z = MatchedFilter.score(genome, cfg, S, rows).max(axis=1)
    out: list[NewInfraCandidate] = []
    for i, r in enumerate(rows):
        key = tb.keys.items[int(S.key[r])]
        if key in known or key in benign or z[i] < z_min:
            continue
        related = sorted({"ip:" + ip for ip in tb.key_ips.get(int(S.key[r]), set())} - {key})
        if key.startswith("d:") and related and all(k in benign for k in related):
            continue
        tt = S.times(int(r))
        out.append(NewInfraCandidate(
            key=key, genome_id=genome.genome_id, family=genome.family, capture_id=capture.capture_id,
            match_z=float(z[i]), n_events=int(len(tt)),
            first_seen=datetime.fromtimestamp(float(tt.min()), tz=timezone.utc),
            last_seen=datetime.fromtimestamp(float(tt.max()), tz=timezone.utc), related_keys=related))
    # an IP that a new domain resolved to is new infrastructure too (when not benign)
    keys_present = {c.key for c in out}
    extra: list[NewInfraCandidate] = []
    for c in out:
        for rk in c.related_keys:
            if rk not in keys_present and rk not in known and rk not in benign:
                keys_present.add(rk)
                extra.append(NewInfraCandidate(rk, c.genome_id, c.family, c.capture_id, c.match_z, c.n_events,
                                               c.first_seen, c.last_seen, [c.key]))
    return sorted(out + extra, key=lambda c: (-c.match_z, c.key))


def build_early_warning_bundle(candidates: Iterable[NewInfraCandidate], genome: Genome, signer: Any, *,
                               issued_at: datetime, validity_days: float = 14.0, issuer: str = "aegis-genome-lab",
                               max_confidence: float = 0.7) -> dict[str, Any]:
    """Signed ``aegis.ioc_bundle/1`` bundle of lab-observed new infrastructure."""
    if issued_at.tzinfo is None:
        raise ValueError("issued_at must be timezone-aware")
    cands = list(candidates)
    exp = issued_at + timedelta(days=validity_days)
    conf = round(min(max_confidence, max(0.3, genome.confidence * 0.75)), 3)
    inds: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for c in cands:
        typ = "domain" if c.key.startswith("d:") else "ip"
        value = c.key.split(":", 1)[1]
        iid = "ind-" + hashlib.sha256(f"{LAB_SOURCE}|{typ}|{value}|{genome.genome_id}".encode()).hexdigest()[:16]
        inds.append({
            "indicator_id": iid, "type": typ, "value": value, "verdict": "malicious",
            "threat_label": "c2_beaconing", "malware_family": genome.family, "confidence": conf,
            "first_seen": _iso(c.first_seen), "last_seen": _iso(c.last_seen), "expires_at": _iso(exp),
            "source": LAB_SOURCE, "source_group": LAB_GROUP,
            "tags": [TAG_LAB, TAG_UNSEEN, f"genome:{genome.genome_id}"],
            "description": (f"{STATUS_UNSEEN}: Box Farm device check-ins match genome {genome.genome_id} "
                            f"({genome.family or 'unlabeled'}, matched-filter z={c.match_z:.1f}, "
                            f"{c.n_events} events, capture {c.capture_id})"),
        })
        evidence.append({"indicator_id": iid, **c.as_dict()})
    body = {
        "schema": BUNDLE_SCHEMA,
        "bundle_id": "ew-" + hashlib.sha256(("|".join(sorted(i["indicator_id"] for i in inds)) + issued_at.isoformat())
                                            .encode()).hexdigest()[:16],
        "version": issued_at.strftime("%Y%m%dT%H%M%SZ"),
        "issuer": issuer, "issued_at": _iso(issued_at), "indicators": inds,
        "x_genome": {"genome_id": genome.genome_id, "family": genome.family,
                     "genome_sha256": genome.content_sha256, "status": STATUS_UNSEEN, "evidence": evidence,
                     "note": "lab observation only; promote to tenant findings only after a tenant match"},
    }
    return sign_bundle(body, signer)


def tenant_exposure(bundle: Mapping[str, Any], tenant_id: str, table: EventTable) -> dict[str, Any]:
    """Which indicators of an early-warning bundle one tenant's lines already contact (tenant-scoped)."""
    vals = {}
    for ind in bundle.get("indicators", []):
        key = ("d:" if ind["type"] == "domain" else "ip:") + str(ind["value"]).lower()
        vals[key] = ind["indicator_id"]
    hits: dict[str, dict[str, Any]] = {}
    key_ids = {}
    for k, name in enumerate(table.keys.items):
        if name in vals:
            key_ids[k] = name
        elif name.startswith("d:"):
            for ip in table.key_ips.get(k, ()):
                if ("ip:" + ip) in vals:
                    key_ids[k] = "ip:" + ip
    if key_ids:
        m = np.isin(table.key, list(key_ids))
        for k in np.unique(table.key[m]):
            sel = table.key == k
            ind_key = key_ids[int(k)]
            h = hits.setdefault(ind_key, {"indicator_id": vals[ind_key], "lines": set(), "first": np.inf,
                                          "last": -np.inf})
            h["lines"].update(table.lines.items[int(x)] for x in np.unique(table.line[sel]))
            h["first"] = min(h["first"], float(table.t[sel].min()))
            h["last"] = max(h["last"], float(table.t[sel].max()))
    per = []
    for key, iid in sorted(vals.items()):
        h = hits.get(key)
        per.append({"indicator_id": iid, "key": key, "status": STATUS_SEEN if h else STATUS_UNSEEN,
                    "n_lines": len(h["lines"]) if h else 0,
                    "first_contact": datetime.fromtimestamp(h["first"], tz=timezone.utc).isoformat() if h else None,
                    "last_contact": datetime.fromtimestamp(h["last"], tz=timezone.utc).isoformat() if h else None})
    return {"tenant_id": tenant_id, "bundle_id": bundle.get("bundle_id"), "indicators": per,
            "contacted": any(p["status"] == STATUS_SEEN for p in per)}


def exposure_summary(results: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Combine per-tenant exposure results (each obtained under that tenant's own authorization)."""
    out: dict[str, list[str]] = {}
    for r in results:
        for p in r["indicators"]:
            if p["status"] == STATUS_SEEN:
                out.setdefault(p["indicator_id"], []).append(r["tenant_id"])
    return {"tenants_by_indicator": {k: sorted(v) for k, v in sorted(out.items())}}
