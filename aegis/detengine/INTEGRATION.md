# Detection engineering (`aegis.detengine`): integration guide

This package is self-contained. It does not change `aegis/service.py`, the API, the web console or the CLI.
This guide lists the calls an integrator makes to wire it in.

## What it does

1. **Rule language** (`language.py`). Declarative, JSON or YAML, frozen dataclasses. A rule has conditions over
   `FeatureVector.values`, destination patterns (exact domain, domain suffix, IP, CIDR), a periodicity
   constraint, and a device-class *baseline selector*. It has no code, regexes or loops. Evaluation
   is three-valued: a missing feature or missing contacts make the rule **abstain**. A missing value is never read as zero.
2. **Validation** (`validation.py`) runs on every draft, from any author, and `RuleRegistry.submit_draft` calls it,
   so it cannot be skipped. A rule is refused when:
   - it is device-class-only, or has no behavioral element;
   - it contains a tautology or contradiction;
   - it targets a shared-hosting IP or CIDR, or an IP the topology does not know (fail closed);
   - it targets a reserved address, a public suffix or an allowlisted value;
   - its only behavioral element is a timer with no rarity bound;
   - it exceeds the complexity bounds.
3. **Drafting** (`drafting.py`) works only on cases that reached VERIFIED. `RuleDrafter(llm)` asks the LLM first
   when one is configured. If it is absent or fails, the deterministic generator takes over. It builds destination rules
   from uncontradicted IOC evidence, periodicity rules from the case's periodic channel, and behavior-envelope rules
   from the gap between the case and an unlabelled population reference. Case text goes to the LLM fenced as
   untrusted data. Its reply passes through the strict parser, and the drafter assigns the rule ids, so a model
   cannot target an existing rule.
4. **Backtesting** (`backtest.py`) runs on frozen lab datasets, with the same digest as `eval/frozen/manifest.json`.
   The split is time-forward: drafters may see only the windows before the split, metrics count only post-split
   device-days, and the case's own entities are excluded. Reports give precision, recall and false alerts per
   10k device-days. Each metric comes with exact Clopper-Pearson CIs and device-cluster bootstrap CIs, plus
   hard-negative alerts, per-class and per-label breakdowns, and overlap with existing detectors (Jaccard,
   novel true positives). Every report carries the label `synthetic`.
5. **Lifecycle** (`registry.py`):
   - `draft -> backtested`.
   - `-> approved` needs an Ed25519-signed human approval, from someone other than the drafter.
   - `-> shadow` is a human step.
   - `-> promoted` needs a passing, fresh `RulePromotionGate` evaluation and a second signed human approval,
     by default from a different person.
   - `-> retired` is open to a human or the platform.
   - LLM, agent, system and generator actors can never approve, start shadow or promote. Nothing auto-promotes.
   - Every step is written to the ledger (entry type `detection_rule`).
6. **Execution** (`engine.py`). `RuleRegistry.active_rules(tenant)` loads only shadow and promoted rules whose spec
   hash, approval signatures and latest ledger record agree. It can also re-validate them against the current
   topology. Promoted rules emit `Finding`s with verdict `suspicious`, `requires_review=True`, no calibration,
   and `detector_version="detengine:<rule_id>@v<version>"`. Shadow rules emit only `RuleShadowFinding`
   documents, never `Finding` documents.
   Rule evidence uses the `operator-telemetry` independence group, so a rule never counts as a second
   independent witness.

## Storage and ledger

| DocStore kind | id | content |
|---|---|---|
| `RuleRecord` | `rule_id@vN` | spec, spec hash, state, history, backtest/approval ids |
| `RuleBacktestReport` | uuid | one backtest of one version on one dataset |
| `RuleApproval` | uuid | signed approval (`purpose` = `approve` or `promote`) |
| `RulePromotionEvaluation` | uuid | gate result (checks, shadow stats, pooled metrics) |
| `RuleShadowFinding` | finding id | shadow finding + sealed evidence |
| `RuleShadowReview` | finding id | analyst verdict on a shadow finding |

Ledger entry types: `detection_rule` (lifecycle, reviews, gate evaluations; subject = `rule_id@vN`),
`detection_rule_shadow` (one per shadow finding), and `finding` (promoted findings). Payloads carry
`rule_bundle_version = "detengine:rule_id@vN"`, so `aegis.provenance.snapshot.replay` picks up the rule versions.
No new tables. Everything goes through `DocStore` and the existing ledger.

## Service wiring (`aegis/service.py`)

```python
from aegis.detengine import (DetectionEngineering, RuleDrafter, RuleRegistry, RulePromotionGate,
                             BacktestConfig, load_frozen_lab_dataset)

# trust anchors for human approvers, installed on disk like the policy/IOC keys:
#   <data_dir>/trusted/approver/<key_id>.pem   (key_id == approver user id, or pass key_owners={key_id: user})
self.approver_keyring = KeyRing()          # load like policy_keyring / ioc_keyring
self.rules = RuleRegistry(self.docs, self.ledger, approver_keyring=self.approver_keyring,
                          gate=RulePromotionGate(), clock=self.clock)
self.detengine = DetectionEngineering(
    self.rules, drafter=RuleDrafter(self.llm),                       # self.llm may be None
    datasets=[load_frozen_lab_dataset(n, Path("eval/frozen/manifest.json"))
              for n in ("high_prevalence", "low_prevalence")],
    backtest_config=BacktestConfig())
```

`load_frozen_lab_dataset` regenerates the corpus. The shipped manifests take about 0.5 to 1.5 minutes each.
Build the datasets once at startup in a background thread, or lazily on the first draft request, and cache them.

### Detection path (`_detect` / per-tenant Sentinel)

Run the engine on the same windows SENTINEL closes. The contacts come from the sentinel's window store:

```python
engine = self.rules.active_rules(tenant_id, evidence_store=self.evidence,
                                 hosting=self._topology(tenant_id))        # cache; rebuild after lifecycle changes
for fv in closed_windows:
    res = engine.process(fv, sentinel.windows.contacts_for(fv))
    for f in res.findings:            # promoted: same handling as sentinel findings (store, open case)
        self.docs.put(f); self.cases.open_case(f)
    # res.shadow_findings are already persisted as RuleShadowFinding + ledger; never open cases from them
```

`engine.rejected` lists the rules that failed integrity checks. Expose it on `/readyz` or in the metrics summary.

### Analyst and approver steps

```python
from aegis.detengine import material_from_case, sign_approval
case = self.cases.require(tenant_id, case_id)
evidence = self.evidence.list_for(tenant_id, case.evidence_ids)
out = self.detengine.draft_from_case(tenant_id, material_from_case(case, evidence),
                                     hosting=self._topology(tenant_id), allowlist=benign_values)
out.as_dict()                                                         # JSON for the API

req = self.rules.approval_request(tenant_id, ref, purpose="approve", approver=user, reason=text)
# the approver signs req client-side; dev only: sign_approval(req, Signer.from_private_pem(...))
self.rules.approve(tenant_id, signed_req)
self.rules.start_shadow(tenant_id, ref, actor=user, reason=text)
self.rules.record_shadow_review(tenant_id, ref, finding_id, outcome="true_positive", reviewer=user)
ev = self.rules.evaluate_promotion(tenant_id, ref, actor=user)
req = self.rules.approval_request(tenant_id, ref, purpose="promote", approver=other_user, reason=text,
                                  promotion_evaluation_id=ev.doc_id)
self.rules.promote(tenant_id, signed_req)
self.rules.retire(tenant_id, ref, actor=user, reason=text)
```

Approval signing bytes are the RFC 8785 canonical JSON of the `RuleApproval` without `signature`, with
`signer_key_id` set: `aegis.provenance.signing.sign_model` / `verify_model`. Approver private keys should stay
with the approver (browser/CLI), never on the server.

`RuleLifecycleError.failed`, `RuleValidationError.errors` and `DraftingError.failed` hold machine-readable
reasons. Map them to HTTP 409/422 the way `GuardError` is mapped today.

## Suggested API routes (`/api/v1`)

| route | role | call |
|---|---|---|
| `POST cases/{id}/rules/draft` | analyst | `detengine.draft_from_case` |
| `GET rules`, `GET rules/{ref}` | viewer | `rules.list_rules`, `rules.require`, `rules.backtests`, `rules.history` |
| `POST rules/{ref}/approval-request` | approver | `rules.approval_request` (returns the unsigned approval) |
| `POST rules/{ref}/approve` | approver | `rules.approve(signed)` |
| `POST rules/{ref}/shadow` | approver | `rules.start_shadow` |
| `GET rules/{ref}/shadow-findings` | analyst | `rules.shadow_findings` |
| `POST rules/{ref}/shadow-reviews` | analyst | `rules.record_shadow_review` |
| `POST rules/{ref}/promotion-evaluation` | approver | `rules.evaluate_promotion` |
| `POST rules/{ref}/promote` | approver | `rules.promote(signed)` |
| `POST rules/{ref}/retire` | approver/admin | `rules.retire` |

Web: show shadow findings in a separate tab, show `synthetic` on every backtest metric, and show CIs next to every rate.

## Limitations

- Backtests run on synthetic lab corpora. They show the logic works, not production precision. Production evidence
  comes from shadow mode and analyst reviews, which the gate requires (`min_shadow_reviews`,
  `max_shadow_false_positive_share`). `RulePromotionGate(allow_synthetic_only=False)` refuses promotion until a
  non-synthetic labelled dataset backs the rule. No such dataset ships today.
- A rule drafted from one case usually catches that campaign and little else, so its recall on a mixed corpus
  is low by design. Overlap and novel-TP numbers show whether it adds anything over SENTINEL.
- Windows rebuilt from stored evidence (`material_from_case`) carry only SENTINEL's summary features. A
  periodicity rule is drafted only when the caller supplies full windows, for example from a replay through
  `WindowStore`.
- Destination patterns need window contacts. Without them, those rules abstain.
- Clopper-Pearson intervals treat device-days as independent. The bootstrap intervals cluster by device. On small
  holdouts both are wide, and the gate checks the bounds, not the point estimates.
- The approver-to-key binding is either key id == user id, or an explicit `key_owners` map. Key distribution and
  revocation follow the existing trusted-key directory process.
- PyYAML is optional, for YAML rule text. JSON always works. No new dependency is required.
