"""AEGIS INTEL: threat-feed ingestion, feed-versus-traffic reconciliation, privacy-preserving sharing.

Public API::

    from aegis.intel import (ThreatIntelHub, CATALOG, get_spec, parse_feed, IntelStore,
                             build_ioc_bundle, reconcile, SharingPolicy, ConsortiumKey,
                             ConsortiumIndex, PrivacyAccountant, PSIParty, FeedFetcher)

    hub = ThreatIntelHub(ledger=ledger)
    hub.import_feed(tenant, "feed:urlhaus", Path("urlhaus.csv"), now=now, actor="analyst@op")
    bundle, report = hub.build_bundle(tenant, ioc_signer, now=now, issuer="operator-intel", actor="system")
    # bundle is accepted by aegis.sentinel.rules.load_bundle(bundle, ioc_keyring)
    rec = hub.reconcile(tenant, observations, now=now, campaigns=resonance_report.campaigns)

See aegis/intel/INTEGRATION.md for wiring into the service, API and CLI.
"""
from aegis.intel.bundle import BundleBuildReport, build_ioc_bundle, indicator_id
from aegis.intel.catalog import CATALOG, FeedSpec, get_spec
from aegis.intel.dp import (
    BudgetExceeded,
    DocStoreBudgetStore,
    InMemoryBudgetStore,
    PrivacyAccountant,
    PrivacyBudgetDoc,
    SecureRandom,
    SeededRandom,
)
from aegis.intel.fetch import FeedFetcher, FetchDisabled, FetchError, FetchResult
from aegis.intel.formats import FeedParseError, parse_feed
from aegis.intel.hub import ThreatIntelHub
from aegis.intel.models import Contradiction, IntelIndicator, ParseResult, VictimReport
from aegis.intel.psi import PSIError, PSIParty
from aegis.intel.reconcile import CampaignCoverage, IndicatorSighting, ReconciliationReport, reconcile
from aegis.intel.sharing import (
    AggregateRelease,
    ConsortiumIndex,
    ConsortiumKey,
    ConsortiumSighting,
    SharedIndicatorPackage,
    SharingDisabled,
    SharingError,
    SharingPolicy,
    build_indicator_package,
    campaign_indicators,
    release_campaign_counts,
    release_counts,
    verify_package,
    verify_release,
)
from aegis.intel.store import ImportReport, IntelStore, IntelStoreDoc, load_store, save_store

__all__ = [
    "AggregateRelease", "BudgetExceeded", "BundleBuildReport", "CATALOG", "CampaignCoverage", "ConsortiumIndex",
    "ConsortiumKey", "ConsortiumSighting", "Contradiction", "DocStoreBudgetStore", "FeedFetcher", "FeedParseError",
    "FeedSpec", "FetchDisabled", "FetchError", "FetchResult", "ImportReport", "InMemoryBudgetStore",
    "IndicatorSighting", "IntelIndicator", "IntelStore", "IntelStoreDoc", "PSIError", "PSIParty", "ParseResult",
    "PrivacyAccountant",
    "PrivacyBudgetDoc", "ReconciliationReport", "SecureRandom", "SeededRandom", "SharedIndicatorPackage",
    "SharingDisabled", "SharingError", "SharingPolicy", "ThreatIntelHub", "VictimReport", "build_indicator_package",
    "build_ioc_bundle", "campaign_indicators", "get_spec", "indicator_id", "load_store", "parse_feed", "reconcile",
    "release_campaign_counts", "release_counts", "save_store", "verify_package", "verify_release",
]
