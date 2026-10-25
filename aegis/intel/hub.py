"""``ThreatIntelHub``: the one object the composition root wires in.

It owns one :class:`~aegis.intel.store.IntelStore` per tenant, the per-tenant
:class:`~aegis.intel.sharing.SharingPolicy`, the DP
:class:`~aegis.intel.dp.PrivacyAccountant` and the optional
:class:`~aegis.intel.fetch.FeedFetcher`, and writes a provenance-ledger entry for
every import, bundle build, share and release. Every method takes ``tenant_id``
and touches only that tenant's state.
"""
from __future__ import annotations

import hashlib
import threading
from collections.abc import Iterable, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol

from aegis.contracts.models import ObservationEvent
from aegis.intel.bundle import BundleBuildReport, SignerLike, build_ioc_bundle
from aegis.intel.catalog import FeedSpec, get_spec
from aegis.intel.dp import PrivacyAccountant, RandomSource
from aegis.intel.fetch import FeedFetcher, FetchDisabled
from aegis.intel.formats import PseudonymizerLike, parse_feed
from aegis.intel.reconcile import ReconciliationReport, reconcile
from aegis.intel.sharing import (
    AggregateRelease,
    ConsortiumKey,
    SharedIndicatorPackage,
    ShareReport,
    SharingPolicy,
    build_indicator_package,
    campaign_indicators,
    release_campaign_counts,
)
from aegis.intel.store import ImportReport, IntelStore
from aegis.resonance.models import Campaign

LEDGER_IMPORT = "intel_feed_import"
LEDGER_BUNDLE = "intel_bundle_built"
LEDGER_SHARE = "intel_share"
LEDGER_RELEASE = "intel_dp_release"


class LedgerLike(Protocol):
    def append(self, tenant_id: str, entry_type: str, subject_id: str, payload: dict[str, Any],
               recorded_at: datetime | None = None) -> Any: ...


class ThreatIntelHub:
    def __init__(self, *, ledger: LedgerLike | None = None, fetcher: FeedFetcher | None = None,
                 accountant: PrivacyAccountant | None = None):
        self.ledger = ledger
        self.fetcher = fetcher
        self.accountant = accountant or PrivacyAccountant(ledger=ledger)
        self._stores: dict[str, IntelStore] = {}
        self._policies: dict[str, SharingPolicy] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ state
    def store(self, tenant_id: str) -> IntelStore:
        with self._lock:
            st = self._stores.get(tenant_id)
            if st is None:
                st = self._stores[tenant_id] = IntelStore(tenant_id)
            return st

    def restore(self, tenant_id: str, snapshot: dict[str, Any]) -> IntelStore:
        st = IntelStore.from_snapshot(snapshot, tenant_id=tenant_id)
        with self._lock:
            self._stores[tenant_id] = st
        return st

    def set_policy(self, policy: SharingPolicy, *, actor: str) -> None:
        with self._lock:
            self._policies[policy.tenant_id] = policy
        if self.ledger is not None:
            self.ledger.append(policy.tenant_id, "intel_sharing_policy", policy.tenant_id,
                               {"actor": actor, "enabled": policy.enabled,
                                "share_indicators": policy.share_indicators,
                                "share_aggregates": policy.share_aggregates, "mechanism": policy.mechanism,
                                "epsilon_per_release": policy.epsilon_per_release, "k_min": policy.k_min,
                                "own_networks": len(policy.own_networks)})

    def policy(self, tenant_id: str) -> SharingPolicy:
        """The tenant's policy; tenants that never opted in get the share-nothing default."""
        with self._lock:
            return self._policies.get(tenant_id) or SharingPolicy(tenant_id=tenant_id)

    # ------------------------------------------------------------------ import
    def import_feed(self, tenant_id: str, feed: str | FeedSpec, data: str | bytes | Path, *, now: datetime,
                    actor: str, report_type: str | None = None, pseudonymizer: PseudonymizerLike | None = None,
                    extra_shared_platforms: Iterable[str] = ()) -> ImportReport:
        spec = get_spec(feed) if isinstance(feed, str) else feed
        raw = data.read_bytes() if isinstance(data, Path) else data
        body_sha = hashlib.sha256(raw if isinstance(raw, bytes) else raw.encode()).hexdigest()
        result = parse_feed(raw, spec, now, report_type=report_type, pseudonymizer=pseudonymizer,
                            extra_shared_platforms=extra_shared_platforms)
        report = self.store(tenant_id).ingest(result, spec, now)
        if self.ledger is not None:
            self.ledger.append(tenant_id, LEDGER_IMPORT, spec.feed_id,
                               {"actor": actor, "body_sha256": body_sha, "as_of": now.isoformat(),
                                "license": spec.license,
                                "source_group": spec.source_group, **report.to_dict()})
        return report

    def fetch_and_import(self, tenant_id: str, feed_id: str, *, now: datetime, actor: str,
                         force: bool = False) -> ImportReport:
        if self.fetcher is None:
            raise FetchDisabled("no feed fetcher configured")
        spec = get_spec(feed_id)
        res = self.fetcher.fetch(spec, force=force)
        return self.import_feed(tenant_id, spec, res.body, now=now, actor=actor)

    def allowlist(self, tenant_id: str, values: Iterable[str], *, reason: str, now: datetime, actor: str) -> int:
        n = self.store(tenant_id).add_allowlist(values, reason=reason, now=now)
        if self.ledger is not None:
            self.ledger.append(tenant_id, "intel_allowlist", f"allowlist:{tenant_id}",
                               {"actor": actor, "entries": n, "reason": reason[:200]})
        return n

    # ------------------------------------------------------------------ outputs
    def build_bundle(self, tenant_id: str, signer: SignerLike, *, now: datetime, issuer: str, actor: str,
                     **kwargs: Any) -> tuple[dict[str, Any], BundleBuildReport]:
        bundle, report = build_ioc_bundle(self.store(tenant_id), signer, now=now, issuer=issuer, **kwargs)
        if self.ledger is not None:
            self.ledger.append(tenant_id, LEDGER_BUNDLE, report.bundle_id, {"actor": actor, **report.to_dict()})
        return bundle, report

    def reconcile(self, tenant_id: str, observations: Iterable[ObservationEvent], *, now: datetime,
                  campaigns: Sequence[Campaign] = (), include_pseudonyms: bool = False) -> ReconciliationReport:
        return reconcile(self.store(tenant_id), observations, now=now, campaigns=campaigns,
                         include_pseudonyms=include_pseudonyms)

    def add_campaign_indicators(self, tenant_id: str, campaigns: Sequence[Campaign], *, now: datetime) -> int:
        return self.store(tenant_id).add_indicators(campaign_indicators(campaigns, tenant_id, now=now))

    def share_indicators(self, tenant_id: str, key: ConsortiumKey, signer: SignerLike, *, now: datetime,
                         actor: str, verified_local: Iterable[tuple[str, str]] = ()
                         ) -> tuple[SharedIndicatorPackage, ShareReport]:
        pkg, rep = build_indicator_package(self.store(tenant_id), self.policy(tenant_id), key, signer, now=now,
                                           verified_local=verified_local)
        if self.ledger is not None:
            self.ledger.append(tenant_id, LEDGER_SHARE, pkg.package_id,
                               {"actor": actor, "entries": rep.shared, "withheld": rep.withheld,
                                "consortium_key_id": key.key_id, "epoch": key.epoch})
        return pkg, rep

    def release_campaign_counts(self, tenant_id: str, campaigns: Sequence[Campaign], key: ConsortiumKey,
                                signer: SignerLike, *, now: datetime, actor: str,
                                rng: RandomSource | None = None) -> AggregateRelease:
        rel = release_campaign_counts(campaigns, self.policy(tenant_id), self.accountant, key, signer, now=now,
                                      rng=rng)
        if self.ledger is not None:
            self.ledger.append(tenant_id, LEDGER_RELEASE, rel.release_id,
                               {"actor": actor, "entries": len(rel.entries), "epsilon": rel.epsilon,
                                "delta": rel.delta, "mechanism": rel.mechanism, "k_min": rel.k_min})
        return rel

    def status(self, tenant_id: str, now: datetime) -> dict[str, Any]:
        eps, delta = self.accountant.remaining(tenant_id)
        pol = self.policy(tenant_id)
        return {**self.store(tenant_id).status(now),
                "sharing": {"enabled": pol.enabled, "indicators": pol.share_indicators,
                            "aggregates": pol.share_aggregates},
                "dp_budget_remaining": {"epsilon": eps, "delta": delta},
                "fetching_enabled": bool(self.fetcher and self.fetcher.enabled)}


__all__ = ["LEDGER_BUNDLE", "LEDGER_IMPORT", "LEDGER_RELEASE", "LEDGER_SHARE", "ThreatIntelHub"]
