# GENOME: behavioral fingerprints from the Box Farm

GENOME learns how each family of TV-box malware *behaves on the network* by watching real,
cheap Android TV boxes in an isolated lab (the Box Farm). It turns those observations into
signed fingerprints ("genomes"), and uses them to find the same behavior across an ISP's
subscriber lines, behind home NAT and under heavy NetFlow sampling, with a controlled
false-discovery rate.

Everything GENOME handles is metadata: timestamps, byte counts, destination addresses and
names, resolver lookups. It never sees payloads, never decrypts anything, and holds no
subscriber identity (line pseudonyms only).

## For ISP buyers and investors: the short version

1. **Box Farm.** We buy the inexpensive TV boxes your subscribers buy, run them in a sealed
   lab, and record only their network metadata for days at a time, idle and in use. A clean
   box of the same model, running factory software, is recorded next to them as the reference.
2. **Genome.** From those recordings we extract what is specific to a malware family: how
   often it checks in and how irregular that timer is, how many connections each check-in
   makes and how large they are, how it uses DNS (every check-in, cached, rotating or
   algorithm-generated names, or hard-coded addresses), how fast its servers change, and how
   often it fetches updates. The box's own normal behavior is subtracted using the clean
   reference. The result is versioned, content-hashed, signed and recorded in the provenance
   ledger, with an expiry date.
3. **Matched-filter detection behind NAT.** An ISP sees one line per household and, at scale,
   only 1 in 100 or 1 in 1000 packets. Because the genome tells us exactly which timer to look
   for, we can test for *that* timer instead of searching every possible one. This is a
   matched filter. In our synthetic benchmark it found most families from 3 infected lines
   in 2000, fewer than the generic detector (RESONANCE) needed in 8 of 12 family/sampling
   cases (1 tie), and it says *which* family it is. It did worse in one case (a wide-jitter
   family at 1:1000), and in the remaining two no method could see a family with hard-coded
   addresses under heavy sampling.
   The benchmark section below has the details.
4. **Early warning.** When a lab box starts checking in to new servers with its family's
   timing, we publish those servers as a signed indicator bundle marked "lab-observed, not yet
   seen in tenant", before they show up in your traffic. A check reports which of your
   tenants already contact them.
5. **Closed learning loop.** Every confirmed campaign points back to box models and
   firmware worth buying and recording next. New recordings refine genomes; refined genomes
   find more campaigns with fewer lines; new infrastructure seen in the lab arrives in your
   indicator feed first. The loop compounds: each lab-hour makes every deployed sensor better,
   and every deployed sensor tells the lab what to study next.

What GENOME does **not** do: it never decides on its own that a subscriber is compromised
because of the device they own, the apps they use or where they are. A "likely device model"
appears only as a ranked hypothesis backed by behavioral evidence. Every finding is a
shadow-mode candidate that a human reviews.

## Prior art and what is new

The pieces are known; the combination is ours.

* **Sandboxes and honeypots.** Running malware in instrumented environments to record its
  behavior is decades old (dynamic analysis sandboxes, honeynets, IoT honeypots). GENOME's lab
  is a long-running, metadata-only, per-device-model recording of *real consumer hardware*,
  with clean same-model references for baseline subtraction.
* **Botnet research and takedowns.** Public research and disruption work on TV-box and
  set-top-box botnets, notably HUMAN Security's research on the BADBOX ecosystem with industry
  partners, and coordinated sinkholing efforts, showed that these devices ship or become
  compromised at scale and that their command infrastructure rotates. GENOME is a detection
  and early-warning system for operators. It does not take infrastructure down and does not
  interact with it.
* **Beacon detection and matched filtering.** Periodicity-based beacon detectors (per-flow
  interval statistics, periodograms) and matched filtering (detecting a known template in
  noise, a classical signal-detection result) are well established. RESONANCE, in this
  repository, adds cross-subscriber pooling with permutation nulls and FDR control.
* **What is new here** is the chain: lab-extracted, signed, expiring family genomes; a
  pair-difference matched filter that tolerates jitter, packet thinning and NAT mixing,
  scored against both the check-in timer and the resolver-lookup timer the lab learned;
  population-level permutation testing with FDR control and abstention; likelihood-based
  family attribution; lab-first indicator publication with per-tenant exposure checks; and
  the feedback loop between them.

Patent counsel caveat: the description above is an engineering view of prior art, not a
freedom-to-operate or patentability opinion. Any filing or claim of novelty must be reviewed
by qualified patent counsel, who should run a formal prior-art search covering sandboxing,
honeypots, network beacon detection, matched filtering and botnet attribution.

## How it works

### 1. Extraction (`aegis/genome/extract.py`)

Input: `LabCapture` objects (one lab device, its metadata frames, box model, firmware, family
label when known, licence, and when the box was in use), or canonical `ObservationEvent`s via
`capture_from_observations`.

1. Destinations contacted by the clean reference box of the same model are removed. Without
   a reference, only allowlisted names are removed and the genome's confidence is halved.
2. Remaining destinations are grouped by infrastructure (a name with the addresses it
   resolved to; addresses in one /24).
3. RESONANCE's difference periodogram ranks the groups. The strongest timer (and any group
   with the same period within 5 %) is the family's check-in set.
4. Check-ins are coalesced bursts. Intervals one period apart give the jitter sample
   `u = d / P - 1`. A uniform or normal model is chosen by kurtosis, and empirical quantiles
   are kept too.
5. Burst size (flows per check-in, log-normal byte model), DNS behavior (lookups per check-in,
   distinct names, rotation dwell, per-character entropy, share of uncommon letter pairs, name
   length), infrastructure churn (addresses, /24s, ASNs per day), update-fetch cadence and
   idle versus in-use timer are measured from the same events.
6. A **resolver-lookup timer** is extracted separately when it differs from the check-in
   timer. Under heavy NetFlow sampling the unsampled resolver log is often the only surviving
   channel, and caching changes its rhythm (for example, lookups every third check-in).

Several boxes of one family pool their samples. Captures whose period disagrees by more than
10 % are reported and not pooled.

### 2. Genome object (`aegis/genome/models.py`, `registry.py`)

`Genome` (schema `aegis.genome/1`) holds the timer models, burst, DNS, infrastructure and
activity models, the destination keys seen in the lab, provenance (capture ids, box models,
firmware, lab id, licence, capture window, event count, extractor version), a confidence score
(extraction quality, not a probability of maliciousness), creation and expiry times. `seal`
sets `content_sha256` and `genome_id = "gn-" + hash prefix`. `sign_genome` signs with
`aegis.provenance.signing`. `verify_genome` checks the hash, the id and the signature against
a key ring (revoked keys fail). `load_genomes` keeps only verified, unexpired genomes and
counts the rest by reason. `ledger_genome` writes the genome to the provenance ledger.

### 3. Matched-filter detection (`aegis/genome/detector.py`)

For each (line, destination) series and each genome template (period `P`, jitter `s`):

```
x = d / P'          k = round(x), 1 <= k <= 8          P' = P (1 + delta), |delta| <= 2 %
sigma_k = sqrt(k s^2 + (res / P')^2)
e = exp(-(x - k)^2 / (2 sigma_k^2))
w_k = exp(-2 pi^2 sigma_k^2)          (0 below 0.05: uninformative multiples)
z = sum w_k (e - m_k) / sqrt(sum w_k^2 v_k)
```

`d` runs over pair differences of the series (up to 8 following events), as in RESONANCE. `m_k`
and `v_k` are the mean and variance of `e` when there is no timer. Pair differences survive
thinning and NAT mixing: a deleted event only removes some pairs, and another device's events
add unstructured pairs. A **harmonic veto** subtracts `max(0, z(2P), z(3P) - z(P))`, because a
template at `P` also fits timers whose true period is a multiple of `P`. The series score is
the maximum over the genome's templates.

Population test per (genome, destination unit):
`T = max_delta sum_lines clip(z, -6, 6)`. Null: each member line's series is replaced by the
same line's series to another destination of comparable event count (topped up from other
lines when a line has fewer than 8 alternatives). Draws are sequential (up to 50,000 when the
observation is extreme), with a generalized-Pareto tail estimate and an **exact floor**: a
permutation p-value is never reported below `1 / (distinct null configurations + 1)`.
A second pass removes the series of supported first-pass rejections from every null pool,
because a concurrent campaign at a harmonic period otherwise inflates the null.
Benjamini-Hochberg (weighted with RESONANCE's population weights) runs over all
(genome, unit) tests at the configured `q`.

Eligibility reuses RESONANCE's population model: destinations reached by more than 20 % of
active lines, IPs on shared hosting, streaming-like volume, long-lived flows, destinations
established in the tenant's history and operator-allowlisted names are never tested.

Guards and abstention:

* no valid genome, too short a window, or a window shorter than 4 periods of a genome:
  abstain;
* a unit with too few lines but a genome-like timer on some line: recorded as an
  abstention ("insufficient lines"), never a finding;
* a rejected unit where fewer than 75 % of member lines individually match the genome
  (z >= 2): demoted to an abstention ("weak per-line support"). Shared structure without
  per-device timers is typical of benign services and resolver caching.

Family attribution compares genomes by likelihood. Consecutive gaps follow a thinned renewal
timer (keep rate fitted over a grid, 10 % background) under each template, plus the log-normal
size model. The likelihood is averaged per member line (pairs within a line are dependent), and
shares come from a softmax over genomes. The detection statistic deliberately excludes byte
sizes: sizes depend on destination type and broke exchangeability with the null in testing
(hundreds of false campaigns in a cold-start benign population before the change).

Device-model hypotheses: for each supporting line, box models from the matching genomes'
provenance are ranked by that line's match score, each with its evidence. They are labeled
`basis = behavioral_match` and are never derived from device class, vendor or IPTV usage.
GENOME never reads `device_class`.

### 4. Early warning (`aegis/genome/early_warning.py`)

`detect_new_infrastructure(genome, capture, known_keys=..., clean_reference=...)` scores a new
lab capture's destinations against the genome. Destinations that match (z >= 6), are not in
the genome or known set, and are not contacted by the clean box are candidates, together with
the addresses they resolved to. `build_early_warning_bundle` emits a signed
`aegis.ioc_bundle/1` bundle (verifiable with `aegis.sentinel.rules.load_bundle`). Each
indicator is tagged `lab-observed`, `not-yet-seen-in-tenant` and `genome:<id>`, with confidence
capped at 0.7 and a 14-day expiry by default. Evidence (capture id, match z, event counts) is in
`x_genome`. `tenant_exposure(bundle, tenant_id, table)` runs inside one tenant's scope and
reports per indicator "seen in tenant" or "lab-observed, not yet seen in tenant".
`exposure_summary` combines per-tenant results the caller already holds.

### 5. Findings (`aegis/genome/findings.py`)

Each campaign produces two evidence records: the matched-filter result (group
`operator-telemetry`) and the genome's lab provenance (group `boxfarm-lab`, with the genome's
licence). Each member line gets a `Finding` with label `c2_beaconing_genome_match`:
`MALICIOUS` only when the line's own series matches and the campaign `q <= 0.001`, otherwise
`SUSPICIOUS`. Every finding requires review, has `calibration_id = None` (the score is a
ranking) and `device_class = "unknown"`. Evidence, campaign and finding records are written to
the ledger.

## Benchmark

`python -m eval.genome_benchmark` (outputs `eval/out/genome/genome_benchmark.json` and `.html`).
Four synthetic families on 2000-line populations, 3 seeds, NetFlow sampling 1:1, 1:100 and
1:1000 (resolver logs unsampled), every detector with the same warm-up history and a
minimum-lines gate of 3:

| family | timer | DNS behavior |
|---|---|---|
| alpha | 600 s, uniform +-10 % | lookup every check-in |
| beta | 1500 s, normal 5 % | cached (TTL 1 h), 3 rotating names |
| gamma | 300 s, uniform +-25 %, 3 flows | algorithm-generated names, rotating daily |
| delta | 640 s, normal 3 % (close to alpha) | none: hard-coded addresses |

Results of the run reported here (3 seeds, about 10 minutes; outputs regenerate into the git-ignored `eval/out/genome/`). Minimum infected
lines = smallest N in the grid (3, 4, 5, 6, 8, 12, 16) detected in every seed.

| sampling | method | alpha | beta | gamma | delta |
|---|---|---|---|---|---|
| 1:1 | GENOME | **3** | **3** | **4** | **3** |
| 1:1 | RESONANCE | 6 | 6 | 6 | 6 |
| 1:100 | GENOME | **3** | **3** | 4 | not detected |
| 1:100 | RESONANCE | 4 | 5 | 4 | not detected |
| 1:1000 | GENOME | **3** | **3** | 6 | not detected |
| 1:1000 | RESONANCE | 4 | 5 | **4** | not detected |

* **Where GENOME wins:** alpha and beta at every sampling rate, and all families at 1:1.
* **Where it loses:** gamma at 1:1000 (GENOME detects 67 % of seeds at 4 and 5 lines, versus
  100 % for RESONANCE). Gamma is the hardest case for a matched filter: its jitter is wide
  (+-25 %), so the known template adds little, and its 300 s period coincides with
  resolver-TTL renewals of benign services, which populate the permutation null.
* **Nobody detects delta under sampling:** with hard-coded addresses and 1-2 packet
  check-ins, delta is invisible at 1:100 and 1:1000 for every method.
* **Achieved campaign FDR:** 0.0 for GENOME and RESONANCE at q = 0.01, 0.05 and 0.1
  (bootstrap CI [0, 0]). Benign-only populations gave 0 campaigns in 9 of 9 runs, and no
  campaign ever landed on IPTV, CDN or other popular service destinations.
* **Line recall at N = 8:** 1.00 at 1:1; 0.75 at 1:100 and 1:1000 for both methods (the
  missing quarter is delta).
* **Family attribution:** 201 of 201 detected campaigns attributed correctly (accuracy 1.00,
  bootstrap CI [1.00, 1.00]), including alpha (600 s) versus delta (640 s).
* **Time to detect** (hours of data, 2 h steps from the 6 h minimum window): 6 h for every
  detectable family at every rate. RESONANCE needed 10 h for alpha at 1:1.
* **Per-line periodicity baseline:** it "detects" with 3 lines, but it flags 1862 to 1973 of
  roughly 2000 benign lines per run. It has no population FDR control and is not a usable
  comparison point for alerting.
* **Failure modes (1:100, 8 lines):**
  * Timer shifted by +4 % and drift of +10 % over the day: detected and correctly
    attributed.
  * Timer shifted by +15 % and adversarial uniform +-60 % jitter: detected, but
    **misattributed** to gamma, the widest-jitter genome. Attribution is only as good as the
    genome library; an unknown variant tends to be claimed by the most tolerant genome. The
    attribution share and the per-genome likelihoods in the evidence should be read with that
    in mind.
  * New infrastructure (generation 1, never seen in the lab): detected and attributed by
    timing alone.
  * Cold start (no history): GENOME 0 false campaigns (3 true), RESONANCE 8 false (11 total).
    GENOME's result relies on the per-line support gate; see the limitations below.
* **Cost:** GENOME 2.2 s per 2000-line day for four genomes, RESONANCE 1.1 s, single
  process.

Engineering history worth knowing, because each change was measured on these benchmarks:
byte sizes were removed from the detection statistic (they caused hundreds of cold-start false
campaigns); attribution moved from null-standardized scores to likelihoods (the narrow-jitter
genome was winning by construction); the exact permutation floor was added (earlier 3-line
detections relied on p-values below what the permutation space supports); and null
purification, the DNS-channel timer, the harmonic veto and persistence weighting each fixed a
measured miss or false campaign.

## Box Farm operations and containment design

The Box Farm runs devices that may carry live malware. The design goal: observe what the
device itself does, and let nothing else out.

**Before anything runs**

* Legal review by counsel of the operating entity and the host jurisdiction, covering the
  computer-misuse, telecommunications and privacy statutes that apply, before any infected
  device is powered on. In France, coordinate with CERT-FR (ANSSI) and keep the coordination
  record. Document the purpose, scope and safeguards in a written operating procedure signed
  by counsel and the responsible manager.
* Devices are purchased through ordinary retail channels. No pirate IPTV subscriptions are
  bought or activated. Where a box's own software ships with such apps, they are not
  configured or used.
* No real subscriber data or accounts on any lab device.

**Network isolation**

* The lab is a separate physical network with its own uplink. It has no route to corporate,
  production or customer networks. Management access goes through a separate, one-way
  bastion.
* Each box sits in its own VLAN behind a lab gateway that records metadata only (flow records
  and resolver logs). No payload capture, no TLS interception.
* DNS goes to a lab resolver that logs queries and can sinkhole names.

**Egress policy**

* The default is deny.
* The device's own check-ins to its control servers may be allowed, at the minimum rate
  observed, so that timing and infrastructure can be recorded. This is the only outbound
  traffic permitted, and it is reviewed per family.
* Traffic relayed for third parties is blocked or sinkholed. This covers residential-proxy
  relaying, click or ad fraud, scanning, attack traffic and spam. Proxy-like patterns
  (many unrelated destinations on behalf of a remote controller) trigger automatic blocking
  of that device.
* Per-device rate limits on connections, bytes and new destinations; exceeding them cuts the
  device off.
* Large downloads (updates, payload fetches) are size-capped and logged as metadata.

**Kill switch and monitoring**

* A physical and a software kill switch cut all lab egress at once. Any operator can use it,
  and it is tested on a schedule.
* Automatic cut-off on policy violations, unexpected protocols or rate-limit breaches.
* Every policy change, device power-on and kill-switch event is written to the provenance
  ledger.

**Conduct**

* No interaction with criminal infrastructure beyond what the device does by itself. No
  sending commands, no probing, scanning or logging into control servers.
* No hacking back, no takedown actions, no sinkholing of third-party infrastructure from the
  lab. Those belong to the authorities and coordinated industry efforts.
* Findings about new infrastructure go to CERT-FR and affected providers through responsible
  disclosure. Indicator publication to customers follows the operator agreement.

**Evidence handling**

* Captures are hashed on collection and stored write-once with a chain-of-custody record
  (who, when, which device, which firmware).
* Genomes and bundles are signed. Signing keys live in a hardware or managed key store and are
  rotated, and revocation is honored everywhere (fail closed).
* Retention is limited to what the purpose needs. Captures are metadata only and contain no
  personal data of third parties beyond destination infrastructure.
* Licence and provenance travel with every genome so downstream use respects the source terms.

## Guarantees and limitations (honest)

* **FDR is about timing, not intent.** The guarantee covers "these lines share the genome's
  timer beyond what their own traffic to other destinations shows". Benign services with the
  same period and jitter (a widget polling every 600 s) can match a genome. The population
  model and the tenant's destination history are what keep them out, exactly as for
  RESONANCE.
* **Cold start (no history) is weaker.** Without history, the population test rejects benign
  units with shared structure (in our runs about 20 to 25 per 2000-line benign day, mostly
  resolver-TTL renewals and vendor telemetry). The
  per-line support gate demotes them to abstentions, so no campaign was reported. That gate is
  a heuristic tuned on synthetic data. Deploy with a warm-up history.
* **Hard-coded-address families under heavy sampling.** A family without DNS whose check-ins
  are one or two small packets disappears at 1:1000 packet sampling (delta in the benchmark).
  No timing method can recover events that were never exported.
* **Genome drift, variants and evasion.** The matched filter searches only +-2 % around each
  genome period. In the benchmark, larger shifts and adversarial jitter were still detected,
  but through the most tolerant genome (gamma) and therefore **misattributed**. Treat
  attribution of an unfamiliar timer as a hypothesis. Run RESONANCE alongside, since it
  searches every period. Genomes expire, and the lab loop is expected to refresh them.
* **Small populations hit the permutation floor.** With 3 lines and few alternative
  destinations per line, the smallest attainable p-value can exceed the BH threshold. GENOME
  reports the exact floor instead of extrapolating past it.
* **Byte counts and sampling.** The size model is used only for attribution. Real sampled
  NetFlow exporters report scaled or sampled byte counts; the simulator reports true sizes.
* **Synthetic evaluation.** All numbers come from simulated populations and simulated lab
  boxes. Before any claim to customers, they must be reproduced on real Box Farm captures and
  a consenting operator's shadow-mode data.
