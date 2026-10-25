# AEGIS INTEL: integration guide

`aegis/intel/` is self-contained. It is not yet wired into the service, API, CLI or console.
This page lists the exact calls an integrator needs. No new dependency: it uses `httpx`
(already installed), `cryptography`, `pydantic` and the standard library.

## What the package does

| area | module | entry points |
|---|---|---|
| feed parsing (offline) | `formats.py`, `catalog.py` | `parse_feed(data, get_spec(feed_id), now, report_type=, pseudonymizer=)` |
| merged indicator view | `store.py` | `IntelStore(tenant_id)`, `.ingest`, `.add_allowlist`, `.contradictions`, `.snapshot`, `save_store`/`load_store` |
| SENTINEL bundles | `bundle.py` | `build_ioc_bundle(store, signer, now=, issuer=)` -> dict accepted by `aegis.sentinel.rules.load_bundle` |
| reconciliation | `reconcile.py` | `reconcile(store, observations, now=, campaigns=)` -> `ReconciliationReport` |
| sharing | `sharing.py` | `SharingPolicy`, `ConsortiumKey`, `build_indicator_package`, `ConsortiumIndex`, `release_campaign_counts` |
| DP budgets | `dp.py` | `PrivacyAccountant(store=DocStoreBudgetStore(docs), ledger=ledger)` |
| two-party PSI | `psi.py` | `PSIParty` |
| HTTP fetch (off by default) | `fetch.py` | `FeedFetcher(cache_dir, enabled=False)` |
| facade | `hub.py` | `ThreatIntelHub` (one object for the composition root) |

Feeds supported: abuse.ch URLhaus (CSV), ThreatFox (JSON export and API format), Feodo
Tracker (CSV and plain text), Spamhaus DROP/EDROP (text and JSON lines), Shadowserver
report CSVs (`event4_sinkhole*`, `botnet_drone`, `scan_*`, ...).

## 1. Composition root (`aegis/service.py`)

```python
from aegis.intel import (ThreatIntelHub, FeedFetcher, PrivacyAccountant, DocStoreBudgetStore,
                         load_store, save_store)

# in AegisService.__init__, after self.docs and self.ledger exist:
fetcher = None
if settings.intel_fetch_enabled:                       # new setting, default False
    fetcher = FeedFetcher(settings.data_dir / "intel-cache", enabled=True,
                          auth_keys={"feed:urlhaus": os.environ.get("AEGIS_ABUSECH_AUTH_KEY", ""),
                                     "feed:threatfox": os.environ.get("AEGIS_ABUSECH_AUTH_KEY", "")},
                          verify=os.environ.get("SSL_CERT_FILE") or True)
self.intel = ThreatIntelHub(ledger=self.ledger, fetcher=fetcher,
                            accountant=PrivacyAccountant(store=DocStoreBudgetStore(self.docs), ledger=self.ledger))

# in the rebuild-from-storage path (where IOC bundles are reloaded), per tenant:
st = load_store(self.docs, tenant_id)
if st is not None:
    self.intel.restore(tenant_id, st.snapshot())
```

After every mutation (`import_feed`, `allowlist`, `add_campaign_indicators`) persist with
`save_store(self.docs, self.intel.store(tenant_id))`.

Suggested service methods (all tenant-scoped, all ledgered by the hub):

```python
def intel_import(self, tenant_id, feed_id, body: bytes, *, actor, report_type=None):
    pz = self.pseudonyms.pseudonymizer(tenant_id)       # same pseudonymizer as ingest
    rep = self.intel.import_feed(tenant_id, feed_id, body, now=self._now(), actor=actor,
                                 report_type=report_type, pseudonymizer=pz)
    save_store(self.docs, self.intel.store(tenant_id))
    return rep.to_dict()

def intel_publish_bundle(self, tenant_id, *, actor):
    bundle, report = self.intel.build_bundle(tenant_id, self.ioc_signer, now=self._now(),
                                             issuer=f"aegis-intel:{tenant_id}", actor=actor)
    self.load_ioc_bundle(tenant_id, actor, bundle)      # existing method: verifies against trusted/ioc keys
    return report.to_dict()

def intel_reconcile(self, tenant_id, *, since, campaigns=()):
    events = ...  # tenant's ObservationEvents in the window (existing tenant-scoped read path)
    return self.intel.reconcile(tenant_id, events, now=self._now(), campaigns=campaigns).model_dump(mode="json")
```

* `self.ioc_signer` must be a `Signer` whose public key is installed under
  `<data_dir>/trusted/ioc/<key_id>.pem`, otherwise `load_ioc_bundle` rejects the bundle
  (fail closed, as intended). The service currently only *verifies* IOC bundles; a signing
  key for locally built bundles has to be provisioned like the policy key.
* The bundle schema has no CIDR type: Spamhaus DROP ranges are excluded from bundles
  (counted in `BundleBuildReport.excluded["cidr_not_representable"]`) unless
  `cidr_expand_max=N` is passed. Reconciliation matches CIDRs natively. Adding a `cidr`
  indicator type to `aegis/sentinel/rules.py` would remove this gap.
* RESONANCE campaigns: pass `resonance_report.campaigns` to `reconcile(...)`. To turn
  analyst-verified campaigns into shareable indicators, call
  `self.intel.add_campaign_indicators(tenant_id, campaigns, now=...)` and list the
  verified `(type, value)` pairs in `share_indicators(..., verified_local=...)`.
* Campaign-derived (operator-originated, `grp:operator*`) malicious indicators are **excluded from
  SENTINEL bundles by default** (`BundleBuildReport.excluded["operator_detection"]`): fed back as IOCs
  they would let one telemetry observation corroborate itself. `include_operator_detections=True`
  emits them in the `operator-telemetry` independence group (same origin as SENTINEL/RESONANCE), so
  they never count as an independent witness. Operator allowlist (benign) entries are always kept.
* Campaign IP destinations inside `SharingPolicy.own_networks` (subscriber space) are never released in
  DP aggregates, even blinded; with `own_networks` unset, aggregate IP destinations are withheld.

## 2. Sharing (opt-in, per tenant)

```python
from aegis.intel import SharingPolicy, ConsortiumKey

self.intel.set_policy(SharingPolicy(
    tenant_id=t, enabled=True, share_indicators=True, share_aggregates=True,
    member_id="op-fr-01",                       # consortium-facing id, never a pseudonym
    own_networks=("198.18.0.0/15",),            # subscriber space: never shared (required for IP sharing)
    mechanism="laplace", epsilon_per_release=0.5, k_min=10), actor=admin)
self.intel.accountant.configure(t, epsilon_total=4.0, delta_total=1e-5)   # e.g. per quarter

key = ConsortiumKey(os.environ["AEGIS_CONSORTIUM_KEY_ID"], bytes.fromhex(os.environ["AEGIS_CONSORTIUM_SECRET"]),
                    epoch="2026-Q4")
pkg, report = self.intel.share_indicators(t, key, self.member_signer, now=now, actor=analyst,
                                          verified_local=verified_pairs)
rel = self.intel.release_campaign_counts(t, verified_campaigns, key, self.member_signer, now=now, actor=analyst)
```

Receiving side:

```python
from aegis.intel import ConsortiumIndex, verify_package
idx = ConsortiumIndex(key, own_member_id="op-fr-01")
idx.add(verify_package(received_json, consortium_keyring, key))   # raises SharingError if unsigned/tampered
idx.match_indicators(self.intel.store(t), now)                     # which of *our* indicators others hold
idx.match_observations(events, t)                                   # which of *our* destinations others flagged
```

Without an explicit policy, `ThreatIntelHub.policy(t)` returns the share-nothing default
and every share/release raises `SharingDisabled`. Budgets are persisted (DocStore doc
`<tenant>:intel_dp_budget`), so a restart never resets them; raising a budget needs
`allow_increase=True` and is ledgered.

## 3. API (`aegis/api/routes.py`), suggested routes

| method & path | role | call |
|---|---|---|
| `GET /api/v1/intel/status` | viewer | `service.intel.status(tenant, now)` |
| `POST /api/v1/intel/feeds/{feed_id}/import` (body = file, `?report_type=`) | analyst | `service.intel_import(...)` |
| `POST /api/v1/intel/allowlist` | admin | `service.intel.allowlist(...)` |
| `POST /api/v1/intel/bundle` | admin | `service.intel_publish_bundle(...)` |
| `GET /api/v1/intel/reconcile?hours=24` | analyst | `service.intel_reconcile(...)` |
| `PUT /api/v1/intel/sharing/policy` | admin | `service.intel.set_policy(...)` |
| `POST /api/v1/intel/sharing/indicators` | approver | `service.intel.share_indicators(...)` |
| `POST /api/v1/intel/sharing/release` | approver | `service.intel.release_campaign_counts(...)` |
| `POST /api/v1/intel/consortium/packages` | integration | `verify_package` + `ConsortiumIndex.add` |

Map `SharingDisabled` and `BudgetExceeded` to 403, `SharingError`/`FeedParseError` to 400,
`FetchDisabled` to 409.

## 4. CLI (`aegis/cli.py`), suggested commands

```
aegis intel import <file> --feed feed:urlhaus --tenant T [--report-type event4_sinkhole_http]
aegis intel bundle --tenant T --out bundle.json
aegis intel reconcile --tenant T --hours 24
aegis intel feeds                 # prints aegis.intel.CATALOG (id, format, license, group)
```

## 5. Ledger entry types written

`intel_feed_import`, `intel_allowlist`, `intel_bundle_built`, `intel_sharing_policy`,
`intel_share`, `intel_dp_charge`, `intel_dp_budget_change`, `intel_dp_release`.
None contains a pseudonym or a raw subscriber address.

## 6. Honest limitations

* Feed licenses are recorded as stated in `catalog.py` (conservative reading); legal review
  per deployment is still required before redistributing anything.
* All three abuse.ch platforms count as **one** independence group. Content-based
  syndication detection needs a shared reference and first_seen within 60 s; other
  republishing must be declared with `FeedSpec(..., source_group=<upstream group>)`.
* Shadowserver victim pseudonyms join with ingest pseudonyms only when ingest keys lines by
  source IP and the address-to-line mapping is stable (DHCP churn and CGNAT break the join).
* HMAC tokens protect against outsiders, not against a dishonest consortium member (IPv4 is
  enumerable). `psi.py` gives semi-honest two-party PSI for member-to-member checks; it is
  pure Python (a few ms per exponentiation), suitable for thousands of items, not full feeds.
* DP accounting uses basic sequential composition (conservative). The k-anonymity gate is
  applied on top of DP and its cost is charged as `threshold_beta` in δ.
* Fixtures are synthetic; no parser has been run against a live feed in this environment.
