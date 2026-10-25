# RESONANCE — cross-subscriber harmonic resonance

*Module `aegis/resonance/` · detector label `c2_beaconing_campaign` · status: shadow-mode detector, synthetic evaluation only*

## 1. The problem

ISPs see subscriber lines, not devices. Behind each line sits a home NAT with several
devices, sometimes a carrier-grade NAT merging several homes. Flow telemetry is usually
**packet-sampled** NetFlow/IPFIX (1:100 to 1:1000), so a beacon of 4 to 12 packets is
exported only 0.4 % to 11 % of the time. Resolver DNS logs are usually unsampled.

Pre-infected Android TV boxes (BadBox 2.0 / Vo1d style) check in with command-and-control
(C2) on jittered timers and are rented out as residential proxies. The usual detectors
miss them for different reasons:

| approach | why it misses or overwhelms |
|---|---|
| static blocklists | C2 infrastructure is fresh or rotates; feeds also list shared CDN IPs (collateral) |
| volumetric / anomaly | a beacon every 15 to 60 minutes is far below any volume threshold |
| per-line periodicity (RITA-style) | sampling deletes most beacons; NAT mixes processes; **benign apps poll too** (NTP, push, TV telemetry, IPTV heartbeats), so every line looks periodic |

Operators fear false positives more than misses. A detector has to say how often it is wrong.

## 2. The idea

One infected line is noise. Fifty unrelated lines whose traffic to the same *rare, fresh,
non-shared* destination beats on the **same timer** form a signal no single line contains.
RESONANCE pools weak per-line timing evidence across subscribers, per destination and per
infrastructure cluster. It tests that pooled coherence against a permutation null built
from the same lines' traffic to other destinations, and controls the false discovery rate
across all destinations tested.

## 3. Method

Input: per line pseudonym, timestamps of contacts with a **destination key**. The key is
`d:<domain>` when the flow's IP was returned to that line by the resolver within 1 h (a DNS
answer join), and also for every resolver query; otherwise it is `ip:<address>`. Flow
records that continue a long-lived connection (exporter active-timeout splits) are removed.
Bursts within 5 s are merged. Series longer than 600 events are thinned at random
(random thinning preserves periodicity; regular decimation would alias it).

### 3.1 Line-level timer recovery: known-phase difference folding

A malware timer is a renewal process, `t[k+1] = t[k] + P(1+u_k)`. Its absolute phase
random-walks, so the classical Lomb–Scargle or Rayleigh power of absolute times washes out
within hours for realistic jitter. RESONANCE folds **pair differences** instead. For each
candidate period `P` (log grid, 50 s to 2 h, 3 % steps), it takes every pair of events on
the series whose separation is `d ∈ [0.5P, 4.5P]`, with weights `w_k` decreasing with the
multiple `k`:

```
C(P) = Σ w_k cos(2π d/P)        Z(P) = C(P) / sqrt(Σ w_k² / 2)        R(P) = C(P) / Σ w_k
```

* **Sampling** only removes events. The surviving pairs still sit near integer multiples of `P`.
* **NAT mixing**: pairs within one device's process are concentrated; pairs across devices add uniform noise.
* **Known phase**: true pairs have phase 0. Using only the cosine part matters for more
  than the factor-2 noise reduction. Human sessions make short separations more common
  than long ones on *every* line. With the full Rayleigh vector, that density slope leaks
  into the sine component with the same sign on all lines and adds up as spurious
  cross-line "resonance" (we measured this on the simulator). The cosine statistic is
  first-order immune and zero-mean for unstructured series of any length.
* **Cost**: differences are histogrammed into log bins per series, and `Z` for all series and
  periods is one dense matrix product with a precomputed (bins × periods) kernel.

Per pair the module reports the period, the strength `R` and `z`, a *nominal*
look-elsewhere-corrected p-value (`pair_periodicities`, labelled uncalibrated), and the
absolute-phase Rayleigh coherence. `lomb_scargle_power` (scipy) is provided for
comparison with classical tools.

### 3.2 Destination population model (gates and weights)

Resonance only says "these lines share a timer". NTP, push keepalives and TV telemetry
are shared timers too. Before testing, a pre-registered population model decides
eligibility and a weight `w ∈ (0, 1]`:

| factor | rule |
|---|---|
| rarity | reached by more than 20 % of active lines → never a target; weight `1 − 0.5·pop/0.2` |
| hosting | IP key on heavy shared hosting (CDN kind, or more than 3 co-hosted names) → never a target. Domain on shared hosting → testable at weight 0.5, flagged *domain-only*. Unknown topology → not enforcement-eligible (fail closed) |
| newness | first seen more than 14 days ago with a stable line population → *standing timer*, not tested, unless its line count surges (more than 2× typical + 5). New (under 7 days) = 1.0, older = 0.8, no history = 0.7 |
| shape | median bytes per line-day above 2 GB, or more than 60 % long-lived flows → ineligible (streaming, IPTV); log-linear down-weight from 20 MB |
| operator allowlist | known services (e.g. the operator's own IPTV middleware) → never a target |
| clustering | domains linked to the IPs they resolve to (if not heavily shared), dedicated-hosting IPs linked by /24; a cluster is tested in addition to its member keys (catches rotating domains) |

Device class, vendor, IPTV app usage and geography are **never** read. A test checks that
rewriting every event's device class leaves the report byte-identical.

### 3.3 Resonance statistics

For hypothesis `H` (a key or a cluster) with member lines `l = 1..m`, let
`g_l(P) = clip(Z_l(P), −8, 8) · persistence_l`. Persistence is the fraction of hourly
blocks with activity relative to what the same number of events would cover if spread
uniformly. Around-the-clock timers score about 1; session-gated app timers score lower.

* **period lock**: `T_lock = max_P (Σ_l g_l(P) − μ₀(P)) / σ₀(P)`. This is a *studentized*
  max-T. `μ₀` and `σ₀` come from a separate pilot batch of 64 null draws, so periods that
  are common under the null (for example the 3600 s DNS-cache refresh shared by countless
  apps) cannot dominate the maximum.
* **free periodicity** (desynchronized bots): `T_free = Σ_l max_P g_l(P)`, counting only
  lines with at least 8 events (below that, the per-line maximum measures whether a pair
  exists, not periodicity).

### 3.4 Null distribution and p-values

**Destination-label permutation within lines.** Each member line's series for `H` is
replaced by that same line's series to another destination outside `H`'s cluster, chosen
from the nearest event counts (exact for 1–2 events, never beyond 2×). The set **includes
the line's own series**, i.e. the identity permutation; without it, the null support
excludes the observed configuration and calibration fails (we measured 34 % of null
p-values ≤ 0.05 before this fix). Lines with fewer than two matching series borrow
nearest-count series from a seeded sample of reference lines. This preserves each line's
sampling rate, NAT mixture, activity hours and benign timers. It breaks only the
association "these lines' periodic traffic goes to the same place".

Draws are sequential (Besag–Clifford: stop after 10 exceedances, at least 100 draws,
at most 1000), giving `p = (e+1)/(B+1)` for `e` exceedances in `B` draws (Phipson & Smyth 2010). When an observation exceeds almost every draw,
a generalized Pareto tail is fitted to the top 10 % (Knijnenburg et al. 2009). If the fitted
tail is bounded, the heavier exponential tail is used instead, so `p` is never reported
as about 0 beyond an endpoint. The final `p = min(1, 2·min(p_lock, p_free))`.

**Abstention.** RESONANCE abstains in four cases, and an abstention is never a campaign:

* the window is shorter than 6 h;
* fewer than 5 active lines;
* a destination has fewer than 5 lines;
* fewer than 5 member lines carry *any* pair information (e.g. hard-coded IP at 1:1000).

### 3.5 Multiple testing

Weighted Benjamini–Hochberg (Genovese, Roeder & Wasserman 2006) runs over all eligible
hypotheses with the population weights (each ≤ 1, so `Σw ≤ m`). A hypothesis is rejected
when its weighted q-value is ≤ q (default **0.01**). When both a cluster and its member
keys are rejected, they are reported as one campaign.

### 3.6 Outputs

* `Campaign` contains:
  * `campaign_id` (stable hash of tenant and destinations), the destination keys and IPs, and ASNs;
  * member and supporting lines;
  * period and period agreement, phase-locking (cross-line PLV), onset time and onset synchrony;
  * the resonance statistic standardized against its null, `p_lock`, `p_free`, `p`, `q`, the p method and the number of permutations;
  * weight parts, enforcement eligibility (domain-only flag, fail-closed on unknown topology);
  * per-line support and a human-readable explanation.
* `to_findings` writes evidence through the provenance layer and returns one `Finding` per member line:
  * evidence records: campaign evidence (`ANOMALY`), line evidence (`OBSERVATION`), and counter-evidence (`BENIGN_BASELINE`, `supports=False`) when infrastructure is shared or unknown;
  * a `resonance_campaign` ledger entry and per-finding ledger entries;
  * verdict `MALICIOUS` when q ≤ 0.001 and the line individually supports the timer (z ≥ 2 at the campaign period), otherwise `SUSPICIOUS`;
  * `requires_review=True`, and a score in [0, 1] that is a ranking, not a probability (`calibration_id=None`).
* The evidence independence group is `operator-telemetry`, the same as SENTINEL's: RESONANCE is not independent corroboration of a SENTINEL finding.

### 3.7 Streaming

`ResonanceStream` ingests chunks (frames, canonical observations or tables). It keeps a 24 h
sliding horizon and DNS answers for the join TTL only, and re-runs detection every step
(default 1 h). Memory is bounded: beyond `max_events`, popular keys keep one event per line
(enough for popularity), and the rest is thinned uniformly at random. Campaign identity is
stable across windows: campaigns sharing any destination are one canonical campaign, so a
rotating-domain cluster that grows is not re-announced.

Memory of one detection run: per-period matrices (Z, R, the capped statistic G) are held only
for informative (line, destination) series, those with at least one event pair in the
difference window; the many one-off contacts of a day share one zero row. Peak RAM still grows
linearly with the lines of the population tested together (measured in `eval/load/report`), so
the per-run bound for a large tenant comes from testing independent sub-populations (region,
BNG, CGNAT pool) separately, see `aegis/scale/INTEGRATION.md`.

## 4. What is guaranteed, and under which assumptions

* **FDR ≤ q for *resonance*** under these assumptions:
  1. destination labels are exchangeable within count-matched sets of each line's series under H₀ (approximate: the set is centred on the observed count);
  2. the per-hypothesis p-values are independent or PRDS (BH's standard condition; hypotheses sharing lines are positively dependent in practice; Benjamini–Yekutieli would be the conservative alternative at a cost of about log m);
  3. the weights are fixed by the pre-registered population model, not by the timing statistic;
  4. empirical p-values are exact; GPD tail p-values are approximations.
* **Measured calibration.** On an exact-null world (periodic and bursty series assigned to
  destinations at random, 6 seeds × 300 hypotheses = 1,800 p-values): 5.3 % were ≤ 0.05,
  20.6 % ≤ 0.2 and 1.6 % ≤ 0.01. The last figure is slightly liberal in the far tail, which
  is where count-matching and tail approximations matter. Runs with any discovery: 0 of 6
  at q = 0.1 and 0 of 6 at q = 0.01. The test suite asserts at most 2 of 6 at q = 0.1.
* **Not guaranteed: maliciousness.** A q-value certifies that unrelated lines share a timer
  toward this destination more than their traffic to other destinations does. Benign shared
  timers satisfy that too. They are excluded by the population model (popularity, history,
  hosting, shape, allowlist), which is heuristic and is logged in every evidence payload.
* **Never** based on device class, vendor, IPTV usage or geography. Shadow mode only: findings
  require review, and enforcement stays behind MIRROR and `authorize()`.

## 5. Limitations (honest list)

1. **Cold start.** Without history, niche benign shared timers *are* resonances: smart-TV
   ACR telemetry, console presence, widget polling, and the DNS TTL-refresh cadence of
   heavily used sites. Measured: about 8 false campaigns per 3,000-line day (25 in 3 runs),
   and 8 at 10,000 lines. Never on IPTV middleware or CDN edges.
   **Deploy with at least 7 days of warm-up history** (a paid shadow pilot does this naturally)
   and an operator allowlist.
2. **New benign app rollouts** (a new destination polled on a timer by about 1 % of lines)
   are indistinguishable from a new botnet by timing alone. They will be reported as
   campaigns (benchmark below); analyst review or an allowlist resolves them.
3. **Desynchronized, rotating campaigns** (each bot draws its own 15–60 min period, domains
   rotate, half the bots use hard-coded IPs) are the hardest case and are missed in most
   configurations (benchmark below). The free-periodicity statistic needs at least 8 events
   per line, which sampling and rotation deny.
4. **Heavy sampling plus no DNS**: at 1:1000 a hard-coded-IP beacon of 4 packets leaves
   about 0–1 events per line-day. RESONANCE abstains instead of guessing. DoH or DoT
   to third-party resolvers removes the unsampled DNS channel and has the same effect.
5. **Detection delay** is at least the 6 h minimum window (by design, to limit false alarms).
6. **Synthetic evaluation only.** All numbers come from `aegis.resonance.sim`, which shares
   its author with the detector. Real traffic has more diverse benign timers, other
   resolver behaviors and real CGNAT. A shadow pilot on operator data is the real test.
7. **Scale.** Cost is dominated by periodograms for involved lines and permutations of
   eligible hypotheses. With history: 2.7 s for 10,000 lines × 24 h (5.5 M events, 4 cores).
   Cold start: about 50 s (about 400 hypotheses). Peak RSS is about 2–4 GB including the
   simulator. Millions of lines need sharding by destination (embarrassingly parallel) and
   a streaming key-stats store. Neither is built yet.

## 6. Evasion analysis

| evasion | effect on RESONANCE | residual signal |
|---|---|---|
| heavier jitter (±40 %) | per-line concentration falls (k=1 pairs keep about 20 %) | still detected when about 20 lines share it (slow campaign) |
| per-bot random periods | period lock fails | free periodicity if lines have ≥ 8 events; otherwise missed |
| domain rotation on the same infrastructure | per-domain line counts split | co-resolution and /24 clustering re-merge them |
| rotation across providers / ASNs | clustering cannot link | each domain must clear `min_lines` alone |
| hosting on a shared CDN | IP never a target; domain down-weighted ×0.5 | domain-level resonance still testable |
| hard-coded IPs + low packet count + heavy sampling | no timing information | abstention (by design) |
| DoH / DoT to an outside resolver | loses the unsampled DNS channel | flows only: needs light sampling |
| mimic popular destinations (reach > 20 % of lines) | never a target | implausible for an unobtrusive botnet |
| session-gate the beacon to human hours | persistence weight falls | period lock still applies |
| slow onset spread over days | weaker onset synchrony (reported only, not in the test) | none lost; onset is evidence, not a criterion |
| very long periods (over 2 h) | outside the default grid | raise `period_max_s` (needs ≥ 4 cycles in the window) |

## 7. Benchmark (synthetic)

`python -m eval.resonance_benchmark` (3,000 lines, 24 h, 3 seeds per cell, q = 0.01, 4 cores,
521 s wall). Each scenario has four campaigns at the stated number of infected lines:

* **standard**: 600 s ±15 %, fresh domain, cached DNS;
* **slow**: 2,400 s ±40 %;
* **evasive**: per-bot 15–60 min, ±30 %, 8 rotating domains on 4 IPs, half the bots on hard-coded IPs, staggered onset;
* **known**: 900 s, C2 listed in the lab IOC feed.

RESONANCE uses one campaign-free warm-up day as history. 95 % CIs come from a percentile
bootstrap over runs, then lines. With only 3 runs per cell, the CIs understate
between-scenario variance.

| sampling | infected lines / campaign | method | precision [95% CI] | recall [95% CI] | false alerts / 10k line-days [95% CI] | campaign FDR | recall: standard / slow / evasive / known |
|---|---|---|---|---|---|---|---|
| 1:1 | 15 | **RESONANCE** | 1.00 [1.00, 1.00] | 0.83 [0.71, 1.00] | 0.0 [0.0, 0.0] | 0.000 | 1.00 / 1.00 / 0.33 / 1.00 |
| 1:1 | 15 | per-line periodicity | 0.02 [0.02, 0.02] | 1.00 [1.00, 1.00] | 10000.0 [10000.0, 10000.0] | – | 1.00 / 1.00 / 1.00 / 1.00 |
| 1:1 | 15 | static blocklist | 0.04 [0.03, 0.15] | 0.39 [0.27, 0.53] | 1739.2 [321.3, 2792.7] | – | 0.18 / 0.16 / 0.22 / 1.00 |
| 1:1 | 60 | **RESONANCE** | 1.00 [1.00, 1.00] | 1.00 [1.00, 1.00] | 0.0 [0.0, 0.0] | 0.000 | 1.00 / 1.00 / 1.00 / 1.00 |
| 1:1 | 60 | per-line periodicity | 0.08 [0.07, 0.08] | 1.00 [1.00, 1.00] | 10000.0 [10000.0, 10000.0] | – | 1.00 / 1.00 / 1.00 / 1.00 |
| 1:1 | 60 | static blocklist | 0.16 [0.12, 0.42] | 0.39 [0.30, 0.47] | 1753.6 [325.0, 2811.5] | – | 0.18 / 0.18 / 0.21 / 1.00 |
| 1:100 | 15 | **RESONANCE** | 1.00 [1.00, 1.00] | 0.67 [0.52, 0.79] | 0.0 [0.0, 0.0] | 0.000 | 0.67 / 1.00 / 0.00 / 1.00 |
| 1:100 | 15 | per-line periodicity | 0.02 [0.02, 0.02] | 0.97 [0.95, 0.99] | 9428.6 [9328.6, 9525.8] | – | 1.00 / 0.96 / 0.93 / 1.00 |
| 1:100 | 15 | static blocklist | 0.04 [0.03, 0.15] | 0.39 [0.27, 0.53] | 1739.2 [321.3, 2792.7] | – | 0.18 / 0.16 / 0.22 / 1.00 |
| 1:100 | 60 | **RESONANCE** | 1.00 [1.00, 1.00] | 0.87 [0.77, 1.00] | 0.0 [0.0, 0.0] | 0.000 | 1.00 / 1.00 / 0.51 / 1.00 |
| 1:100 | 60 | per-line periodicity | 0.08 [0.07, 0.09] | 0.99 [0.98, 1.00] | 9427.9 [9329.4, 9520.6] | – | 1.00 / 0.97 / 0.99 / 1.00 |
| 1:100 | 60 | static blocklist | 0.16 [0.12, 0.42] | 0.39 [0.30, 0.47] | 1753.6 [325.0, 2811.5] | – | 0.18 / 0.18 / 0.21 / 1.00 |
| 1:1000 | 15 | **RESONANCE** | 1.00 [1.00, 1.00] | 0.72 [0.52, 0.90] | 0.0 [0.0, 0.0] | 0.000 | 0.67 / 1.00 / 0.20 / 1.00 |
| 1:1000 | 15 | per-line periodicity | 0.02 [0.02, 0.02] | 0.98 [0.95, 1.00] | 9398.0 [9295.8, 9493.2] | – | 1.00 / 0.98 / 0.93 / 1.00 |
| 1:1000 | 15 | static blocklist | 0.04 [0.03, 0.15] | 0.39 [0.27, 0.53] | 1739.2 [321.3, 2792.7] | – | 0.18 / 0.16 / 0.22 / 1.00 |
| 1:1000 | 60 | **RESONANCE** | 1.00 [1.00, 1.00] | 0.87 [0.77, 0.97] | 0.0 [0.0, 0.0] | 0.000 | 1.00 / 1.00 / 0.48 / 1.00 |
| 1:1000 | 60 | per-line periodicity | 0.08 [0.08, 0.09] | 0.99 [0.98, 1.00] | 9394.2 [9296.2, 9483.2] | – | 1.00 / 0.98 / 0.99 / 1.00 |
| 1:1000 | 60 | static blocklist | 0.16 [0.12, 0.42] | 0.39 [0.30, 0.47] | 1753.6 [325.0, 2811.5] | – | 0.18 / 0.18 / 0.21 / 1.00 |

The table shows four things:

* **Precision and false alarms.** RESONANCE raised no false campaign and flagged no benign
  line in any cell (30 runs with history, including the benign-only and CGNAT runs below). Per-line
  periodicity flags 94–100 % of lines, because benign apps poll. The naive static blocklist
  flags 17–23 % of lines, because the feed also lists a shared CDN edge (the over-broad
  indicator the lab feed contains on purpose). Its non-zero recall on fresh campaigns is
  entirely incidental hits on that indicator.
* **Recall.** The standard, slow and known campaigns are found at 1:1, 1:100 and 1:1000,
  except one 15-line standard campaign at 1:100 and 1:1000 (recall 0.67). Sampling hurts
  less than expected because resolver logs are unsampled. **The evasive campaign is the
  failure mode**: recall 0.00–0.33 at 15 lines and about 0.5 at 60 lines.
* **Detection delay** (streaming, 1 h steps, 60 infected lines):
  * standard, slow and known: median 6.0 h at 1:100 and 1:1000, i.e. the 6 h minimum window;
  * evasive: median 15.0 h at 1:100 (7.9 / 15.0 / 19.0 h) and 6.0 h at 1:1000 (4.0 / 6.0 / 12.9 h).
* **Achieved campaign-level FDR**: 0.000 in every cell (target 0.01).

**Benign-only populations (with history)**: FDR control and IPTV/CDN safety.

| sampling | RESONANCE false campaigns | runs with any false campaign | IPTV/CDN campaigns | per-line periodicity FA/10k | blocklist FA/10k |
|---|---|---|---|---|---|
| 1:1 | 0 | 0/3 | 0 | 10000.0 [10000.0, 10000.0] | 2346.7 [1625.6, 3353.5] |
| 1:100 | 0 | 0/3 | 0 | 9423.3 [9344.4, 9512.2] | 2346.7 [1625.6, 3353.5] |
| 1:1000 | 0 | 0/3 | 0 | 9411.1 [9326.7, 9503.4] | 2346.7 [1625.6, 3353.5] |

**Hard cases (where it fails):**

* **Cold start (no history), benign, 1:100**: **25 false campaigns in 3 runs** (about 8 per
  3,000-line day), none on IPTV or CDN infrastructure. They are genuine shared timers:
  * smart-TV ACR telemetry (`acr.tvvendor-a/b`, about 1,830 s; every run);
  * console presence (121 s);
  * DNS-cache refresh cadence of heavily used sites at multiples of their 300 s TTL (about 290 / 590 / 900 / 1,215 s).

  This is the main deployment caveat: run with warm-up history.
* **New benign app rollout** (a shared 900 s timer to a new destination on about 1.5 % of
  lines): flagged in 3 of 3 runs, as expected (section 5).
* **CGNAT-style merging** (4 lines per observable entity, 1:100, 60 infected lines per campaign):
  * RESONANCE: precision 1.00, recall 0.86 [0.76, 0.99], 0 false alerts, campaign FDR 0;
    evasive recall 0.48, others 1.0.
  * Per-line periodicity: precision 0.28 and the static blocklist 0.28. Both flag nearly
    every merged entity (9,600–10,000 false alerts per 10k entity-days).
* **Performance**:
  * 10,000 lines × 24 h at 1:100 (5.48 M events): 2.7 s detection with history; about 50 s
    cold start (about 400 hypotheses).
  * Event-table build: about 2.5 s. Simulator generation: about 11 s.
  * Measured in this container (4 cores); the opt-in test is `AEGIS_PERF=1`.


## 8. Related work and what is new

* **Beacon detection on a single host or pair.** RITA (Active Countermeasures) scores
  interval and size regularity (Bowley skewness, MAD) per connection pair. BAYWATCH (Hu et
  al., DSN 2016) combines periodicity detection with a universal whitelist, local
  popularity and novelty filters in enterprises. Lomb (1976) / Scargle (1982) periodograms
  and the Rayleigh / Z² tests of pulsar timing are the classical tools for event-time
  periodicity.
* **Spatial-temporal correlation across hosts.** BotSniffer (Gu et al., NDSS 2008)
  correlates similar responses of hosts in the same network. BotMiner (Gu et al., USENIX
  Security 2008) clusters hosts by communication (C-plane) and activity (A-plane)
  patterns. DISCLOSURE (Bilge et al., ACSAC 2012) detects C2 servers from large-scale
  NetFlow features. Segugio (Rahbarinia et al., DSN 2015) propagates labels on the ISP
  DNS machine–domain graph.
* **Statistics.**
  * Benjamini–Hochberg (1995) and Benjamini–Yekutieli (2001);
  * weighted BH (Genovese, Roeder & Wasserman 2006);
  * sequential Monte Carlo p-values (Besag & Clifford 1991) and permutation p-values that are never zero (Phipson & Smyth 2010);
  * GPD tail approximation (Knijnenburg et al. 2009);
  * max-T (Westfall & Young 1993).

**What we believe is new in the combination** (to be confirmed by a prior-art search):

1. folding *pair differences* with a *known-phase* (cosine) statistic, which together are
   robust to jitter accumulation, packet sampling and NAT mixing, and immune to the
   session-density leakage that otherwise produces cross-line false resonance;
2. pooling that per-line evidence *across unrelated subscriber lines* at ISP vantage, mixing
   sampled flows with unsampled resolver events;
3. a destination-label permutation null *within lines* (identity included, count-matched,
   studentized max-T over periods), giving calibrated per-destination p-values;
4. FDR control with population-model weights (rarity, newness, hosting, shape) and
   first-class abstention;
5. testing infrastructure clusters alongside keys, to catch rotating domains.

Individual ingredients are well known. BAYWATCH and BotSniffer/BotMiner are close prior
art for parts of the pipeline. **Patentability requires review by IP counsel**; nothing
here is a legal opinion.

## 9. Reproduce

```bash
pytest -q tests/unit/test_resonance*.py               # 25 tests (+1 opt-in 10k-line perf test: AEGIS_PERF=1)
python -m eval.resonance_benchmark                    # JSON + self-contained HTML in eval/out/resonance/
python -m eval.resonance_benchmark --quick            # smoke run
```

## 10. Integration (for SENTINEL / ORACLE / API)

```python
from aegis.resonance import (ResonanceConfig, Resonance, ResonanceStream, DestinationContext,
                             DestinationHistory, events_from_observations, to_findings)

cfg = ResonanceConfig(q=0.01, authorization_id=collection_authorization_id)
history = DestinationHistory.from_dict(saved) if saved else DestinationHistory()
det = Resonance(cfg, context=DestinationContext(topology), history=history, tenant_id=tenant_id)

table = events_from_observations(events, cfg, start=window_start, end=window_end)
report = det.detect(table)                                   # ResonanceReport: campaigns, tested (p/q), abstentions
findings = to_findings(report, cfg=cfg, evidence_store=evidence_store)   # Finding list; evidence + ledger written
# persist: history.to_dict(); report.model_dump(mode="json")
```
