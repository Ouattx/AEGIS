"""Frozen evaluation datasets (spec section 14).

A dataset is a deterministic lab corpus identified by its :class:`ScenarioSpec`. It is
*frozen* by a content digest over every event (id, integrity hash, observation time)
and every device-day label; ``eval/frozen/manifest.json`` records the digests, and a
benchmark run refuses to report on a dataset whose content differs from the manifest.

Dataset roles follow the spec: **A** = confirmed malicious device activity (positive
device-days), **B** = representative legitimate traffic (benign device-days, including
hard negatives such as busy licensed-IPTV boxes). Dataset **C** (legally verified
infringement) belongs to RIGHTS, which is out of scope for SHIELD v1.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aegis.lab.corpus import Corpus, generate_corpus

FROZEN_MANIFEST = Path(__file__).resolve().parent / "frozen" / "manifest.json"
MANIFEST_SCHEMA = "aegis.eval.frozen/1"


class FrozenDatasetMismatch(RuntimeError):
    """A dataset's content differs from its frozen digest."""


@dataclass(frozen=True)
class ScenarioSpec:
    """A deployment scenario evaluated on one frozen lab corpus."""
    name: str
    seed: int
    n_devices: int
    days: int
    malicious_fraction: float
    start: str                      # ISO-8601 UTC
    tenant_id: str = "bench"
    description: str = ""
    #: telemetry degradation applied after generation (harder, more realistic scenarios):
    #: keep each flow record with this probability (sampled NetFlow), drop reverse
    #: counters (unidirectional export) and lose this fraction of DNS records
    flow_sampling: float = 1.0
    uniflow: bool = False
    dns_loss: float = 0.0

    def __post_init__(self) -> None:
        if not 0.0 < self.flow_sampling <= 1.0 or not 0.0 <= self.dns_loss < 1.0:
            raise ValueError(f"scenario {self.name}: flow_sampling must be in (0, 1] and dns_loss in [0, 1)")

    @property
    def start_dt(self) -> datetime:
        dt = datetime.fromisoformat(self.start)
        if dt.tzinfo is None:
            raise ValueError(f"scenario {self.name}: start must include a UTC offset")
        return dt.astimezone(timezone.utc)

    @property
    def end_dt(self) -> datetime:
        return self.start_dt + timedelta(days=self.days)

    def identity(self) -> dict[str, Any]:
        """Fields that determine the content (description excluded)."""
        d = asdict(self)
        d.pop("description")
        # degradation fields only enter the identity when used (older frozen entries stay valid)
        for k, default in (("flow_sampling", 1.0), ("uniflow", False), ("dns_loss", 0.0)):
            if d[k] == default:
                d.pop(k)
        return d

    @property
    def degraded(self) -> bool:
        return self.flow_sampling < 1.0 or self.uniflow or self.dns_loss > 0.0


def generate(spec: ScenarioSpec) -> Corpus:
    corpus = generate_corpus(seed=spec.seed, days=spec.days, n_devices=spec.n_devices,
                             malicious_fraction=spec.malicious_fraction, tenant_id=spec.tenant_id,
                             start=spec.start_dt)
    return degrade(corpus, spec) if spec.degraded else corpus


def degrade(corpus: Corpus, spec: ScenarioSpec) -> Corpus:
    """Deterministically degrade telemetry the way real exports are degraded.

    Flow records are kept with probability ``flow_sampling`` (1-in-N sampled NetFlow),
    ``uniflow`` removes reverse byte/packet counters (missing, not zero: v5/v9 exports
    without bi-flow) and ``dns_loss`` drops resolver records (partial resolver logging).
    Labels are unchanged: a compromised device-day stays compromised even when little of
    its traffic survives, which is what makes the scenario hard.
    """
    import random

    rng = random.Random(f"degrade:{spec.seed}:{spec.flow_sampling}:{spec.uniflow}:{spec.dns_loss}")
    kept = []
    for ev in corpus.events:
        if ev.flow is not None:
            if rng.random() >= spec.flow_sampling:
                continue
            if spec.uniflow:
                ev = ev.model_copy(update={"flow": ev.flow.model_copy(update={"bytes_in": None,
                                                                             "packets_in": None})})
        elif ev.dns is not None and rng.random() < spec.dns_loss:
            continue
        kept.append(ev)
    corpus.events = kept
    return corpus


def corpus_digest(corpus: Corpus) -> str:
    """SHA-256 over every event (id, integrity hash, time) and every device-day label."""
    h = hashlib.sha256()
    for ev in corpus.events:
        h.update(f"{ev.event_id}|{ev.integrity_sha256}|{ev.observed_at.isoformat()}\n".encode())
    for (ent, day), label in sorted(corpus.labels.items()):
        h.update(f"L|{ent}|{day.isoformat()}|{label}\n".encode())
    return h.hexdigest()


def dataset_summary(corpus: Corpus) -> dict[str, Any]:
    pos = sum(1 for v in corpus.labels.values() if v != "benign")
    hard = {d.entity_pseudonym for d in corpus.hard_negatives()}
    return {
        "events": len(corpus.events), "devices": len(corpus.devices),
        "malicious_devices": len(corpus.malicious_devices()), "hard_negative_devices": len(hard),
        "device_days": len(corpus.labels),
        "A_malicious_device_days": pos,
        "B_legitimate_device_days": len(corpus.labels) - pos,
        "B_hard_negative_device_days": sum(1 for (e, _d) in corpus.labels if e in hard),
        "base_rate": pos / len(corpus.labels) if corpus.labels else None,
    }


def load_manifest(path: Path = FROZEN_MANIFEST) -> dict[str, Any]:
    if not path.exists():
        return {"schema": MANIFEST_SCHEMA, "datasets": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != MANIFEST_SCHEMA:
        raise FrozenDatasetMismatch(f"unsupported frozen manifest schema in {path}")
    return data


def check_frozen(spec: ScenarioSpec, digest: str, manifest: dict[str, Any]) -> str:
    """``"verified"`` when the digest matches the manifest, ``"unfrozen"`` when the manifest
    has no entry for this exact spec; raises :class:`FrozenDatasetMismatch` on a mismatch."""
    entry = manifest.get("datasets", {}).get(spec.name)
    if entry is None or entry.get("spec") != spec.identity():
        return "unfrozen"
    if entry.get("digest") != digest:
        raise FrozenDatasetMismatch(
            f"dataset {spec.name!r} does not match its frozen digest ({digest[:16]} != {str(entry.get('digest'))[:16]}); "
            "the generator or its inputs changed. Re-freeze deliberately with --freeze after review.")
    return "verified"


def freeze(entries: dict[str, tuple[ScenarioSpec, str, dict[str, Any]]], path: Path = FROZEN_MANIFEST) -> Path:
    """Record (or update) frozen digests for the given datasets."""
    data = load_manifest(path)
    for name, (spec, digest, summary) in entries.items():
        data["datasets"][name] = {"spec": spec.identity(), "digest": digest, "summary": summary,
                                  "description": spec.description}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return path


__all__ = ["FROZEN_MANIFEST", "FrozenDatasetMismatch", "MANIFEST_SCHEMA", "ScenarioSpec", "check_frozen",
           "corpus_digest", "dataset_summary", "degrade", "freeze", "generate", "load_manifest"]
