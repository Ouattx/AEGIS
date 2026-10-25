"""Shared builders for the detengine unit tests (no tests are defined here)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any

from aegis.contracts.models import Case, CaseDecision, CaseState, Evidence, EvidenceKind, FeatureVector
from aegis.detengine import BacktestDataset, Contacts
from aegis.provenance.evidence import EvidenceStore
from aegis.provenance.ledger import Ledger
from aegis.provenance.signing import KeyRing, Signer
from aegis.sentinel.features import FEATURE_NAMES
from aegis.storage.db import DocStore, init_db, make_engine, make_session_factory

T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
TENANT = "acme"


def fv(entity: str = "p_dev1", end: datetime = T0 + timedelta(days=1), *, device_class: str = "android_tv",
       tenant_id: str = TENANT, window: str = "24h", **values: float | None) -> FeatureVector:
    """A feature vector with every feature missing except ``values``."""
    vals: dict[str, float | None] = {k: None for k in FEATURE_NAMES}
    vals.update(values)
    return FeatureVector(tenant_id=tenant_id, entity_pseudonym=entity, device_class=device_class,
                         window=window, window_end=end, values=vals,
                         missing={k: v is None for k, v in vals.items()}, event_count=100)


def contacts(ips: tuple[str, ...] = (), names: tuple[str, ...] = (),
             answers: dict[str, tuple[str, ...]] | None = None) -> Contacts:
    return Contacts(dst_ips=frozenset(ips), qnames=frozenset(names),
                    answers={k: frozenset(v) for k, v in (answers or {}).items()},
                    source_ids=frozenset({"sensor-1"}), authorization_ids=frozenset({"auth-1"}))


def synthetic_dataset(*, n_benign: int = 40, n_malicious: int = 6, days: int = 3, hard_negative_hits: int = 1,
                      name: str = "synthetic", tenant_id: str = "bench") -> BacktestDataset:
    """One 24h window per device per day (ending at midnight).

    Malicious devices are infected from day 1 on (day 0 is clean) and show a high NXDOMAIN
    rate once infected; ``hard_negative_hits`` benign devices show it every day (false alerts).
    Benign devices with index 0 have the rate missing on every day (abstentions).
    """
    windows: list[FeatureVector] = []
    labels: dict[tuple[str, date], str] = {}
    classes: dict[str, str] = {}
    hard: set[str] = set()
    for i in range(n_benign + n_malicious):
        malicious = i >= n_benign
        ent = f"p_{'m' if malicious else 'b'}{i:03d}"
        klass = "android_tv" if i % 2 else "phone"
        classes[ent] = klass
        hard_neg = (not malicious) and 1 <= i <= hard_negative_hits
        if hard_neg:
            hard.add(ent)
        for d in range(days):
            day = (T0 + timedelta(days=d)).date()
            infected = malicious and d >= 1
            labels[(ent, day)] = "dga_activity" if infected else "benign"
            rate: float | None = 0.9 if (infected or hard_neg) else 0.05
            if i == 0:
                rate = None
            windows.append(fv(ent, T0 + timedelta(days=d + 1), device_class=klass, tenant_id=tenant_id,
                              nxdomain_rate=rate, nx_unique=150.0 if infected else 3.0,
                              coverage_h=24.0))
    return BacktestDataset(name=name, tenant_id=tenant_id, windows=windows, contacts=[None] * len(windows),
                           labels=labels, device_classes=classes, hard_negatives=frozenset(hard), start=T0,
                           end=T0 + timedelta(days=days), digest="synthetic-test", synthetic=True, frozen=False)


@dataclass
class Clock:
    now: datetime = field(default_factory=lambda: datetime(2026, 10, 20, 12, tzinfo=timezone.utc))

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: Any) -> None:
        self.now = self.now + timedelta(**kw)


@dataclass
class Stores:
    docs: DocStore
    ledger: Ledger
    evidence: EvidenceStore
    keyring: KeyRing
    alice: Signer
    bob: Signer
    mallory: Signer


def make_stores(tmp_path: Any) -> Stores:
    engine = make_engine(f"sqlite:///{tmp_path}/detengine.db")
    init_db(engine)
    sf = make_session_factory(engine)
    docs = DocStore(sf)
    ledger = Ledger(sf, signer=Signer.generate("ledger-test"))
    ring = KeyRing()
    alice, bob, mallory = Signer.generate("alice"), Signer.generate("bob"), Signer.generate("mallory")
    ring.add_signer(alice)
    ring.add_signer(bob)
    return Stores(docs, ledger, EvidenceStore(docs, ledger), ring, alice, bob, mallory)


def ioc_evidence(value: str = "cfg.badbox.example", *, typ: str = "domain", tenant_id: str = TENANT,
                 verified: bool = True, contradicted: bool = False, confidence: float = 0.9) -> Evidence:
    return Evidence(tenant_id=tenant_id, kind=EvidenceKind.IOC_MATCH, origin_source="feed:test",
                    source_independence_group="feed-group-a", collected_at=T0 + timedelta(days=1),
                    summary=f"contacted {value}", authorization_id="auth-1",
                    payload={"entity_pseudonym": "p_case", "indicator_type": typ, "indicator_value": value,
                             "verified_contact": verified, "contradicted": contradicted,
                             "confidence": confidence, "effective_confidence": confidence,
                             "threat_labels": ["c2_beaconing"]})


def verified_case(evidences: list[Evidence], *, state: CaseState = CaseState.VERIFIED, tenant_id: str = TENANT,
                  title: str = "c2_beaconing on android_tv device p_case") -> Case:
    now = T0 + timedelta(days=2)
    decisions = []
    if state != CaseState.VERIFIED and state not in (CaseState.REJECTED, CaseState.INCONCLUSIVE, CaseState.NEW):
        decisions.append(CaseDecision(from_state=CaseState.INVESTIGATING, to_state=CaseState.VERIFIED,
                                      actor="analyst-1", reason="two witnesses", at=now))
    return Case(tenant_id=tenant_id, title=title, hypothesis="device beacons to C2",
                evidence_ids=[e.evidence_id for e in evidences], state=state, decisions=decisions,
                created_at=now, updated_at=now)
