# Demo script: 10 minutes, click by click

Audience: an operator's CISO, SOC lead or network security architect. Goal: they believe three things by
minute 10. (1) SHIELD finds compromised devices in data they already have. (2) Every alert is backed by
evidence they can audit, and SHIELD says "I don't know" instead of guessing. (3) It cannot block anything
by itself, and it stops a dangerous block even when a human asks for one.

Everything shown runs on a **synthetic lab network**. Say it at the start and whenever a number appears.

## Before the call (15 minutes ahead)

1. Start the demo on your laptop:
   `docker compose -f deploy/docker-compose.demo.yml up --build` (or `aegis demo --port 8080` from a source
   checkout). Wait for "AEGIS OMEGA SHIELD demo ready" in the log; it takes 1 to 2 minutes.
2. Window A (normal browser): `http://localhost:8080` -> click **Analyst**.
3. Window B (private window): `http://localhost:8080` -> click **Approver**.
4. In window A open **Cases** and note one **C2 beaconing** case in state **Investigating** with severity
   **Critical**. That is the case for minutes 3 to 7.
5. Close everything else on the screen you share. Zoom the browser to 110%.

If something fails on stage, restart the container: every start rebuilds the same deterministic demo.

## 0:00 to 1:00: frame it

> "Pre-infected Android TV boxes and other cheap devices are being rented out as residential proxies and
> botnet nodes from inside your subscribers' homes. You already collect the telemetry that reveals them:
> NetFlow, resolver logs. What's missing is a way to turn that into findings you can defend, without
> accusing the household that just watches a lot of IPTV. That's what I'll show, on a synthetic lab network
> of 120 devices over three days, including emulated BadBox-style malware and a very busy, legitimate IPTV box."

## 1:00 to 2:30: Overview (window A)

1. Point at the header pills: **SHADOW MODE** and **LEDGER VERIFIED**.
   > "Shadow mode: read-only. And every action in this system is in a signed, hash-chained ledger, verified right now."
2. Point at the red **Synthetic lab demo** banner first: everything on screen comes from the synthetic lab
   corpus and a simulated analyst. Never present these figures as field results.
   KPI row: **Devices monitored**, **Alerts raised** (note the abstained count under it), **False alerts / 10k
   device-days** with its **95% upper bound and n**, **Live enforcements 0**.
   > "We report false alerts per ten thousand device-days, with an upper bound even when we've seen zero, because
   > your NOC cares about how often we're wrong, not about an accuracy percentage."
3. **Alert rate by device class** panel: read the footnote aloud: *"Device class selects a comparison
   baseline only; it is never evidence of compromise."*

## 2:30 to 3:00: Findings

1. Click **Findings** in the left menu. Open the verdict filter and show **Abstain** entries.
   > "When context is too thin, the detector abstains and hands it to a human. Abstain is a first-class outcome."

## 3:00 to 5:30: a case, end to end (window A)

1. Click **Cases** -> the Critical **C2 beaconing** case in **Investigating**.
2. The lifecycle bar shows where the case is. Click the **Evidence trail** tab.
   * **Independent supporting origins**: "two separate origins agree; three feeds copying one report count once."
   * **Signed IOC hits**: "indicators verified against a feed signature you trust."
   * Rows: kind, **SHA-256**, **Integrity: verified**, role **Qualifying** vs **Contradicts**.
   > "Every item is content-hashed. Notes, graph links and AI arguments never count as qualifying evidence."
3. Click **Investigation report**: alternative hypotheses and the tests that discriminate between them.
   > "Before anyone can mark this verified, someone has to look at the benign explanations: push
   > notifications, an update server, an IPTV heartbeat."
4. Click **Graph neighbourhood**: the device pseudonym, the C2 domain, the IP.
   > "No subscriber identity anywhere: only a pseudonym keyed to your tenant. Re-identification stays in your systems."
5. Click **Replay as of** and drag the time slider back towards the moment the case was opened.
   > "This is what we knew at that moment, and only that. Auditors love this: no hindsight."
6. Click **Update review**: add one alternative ("legitimate push service") and a note, submit. The
   **Verified** button is now enabled: click it, enter a reason, **Move to Verified**.

## 5:30 to 7:30: try to block it (both windows)

1. Window A: **Propose action**. Type **DNS sinkhole**, target = the C2 domain suggested, **Expires in (hours)**
   24, write a rollback plan, tick the rollback-verified box, submit.
2. On the action page: **Run simulation**. Point at the result: **SAFE**, affected entities, **Legitimate
   co-tenants: none found**, reversibility.
   > "MIRROR checks who else lives on that infrastructure. If this were a shared CDN address with thousands
   > of legitimate sites, it would say UNSAFE or UNKNOWN, and authorization fails closed."
3. Click **Assess**. The **Authorization checklist** shows **NOT ALLOWED**: *Policy mode is active (shadow
   never enforces)* and *Legal signoff reference recorded* fail; everything else passes.
   > "Seven conditions, all deterministic code, no language model consulted. Your signed policy is in shadow
   > mode, so the answer is no, whatever anyone clicks."
4. Window B (Approver): open **Actions**, the same action. Hover **Approve**: disabled, *"Authorization did
   not allow this action."* And the analyst who proposed it could never approve it: four-eyes is enforced
   by the API, not just the screen.

## 7:30 to 8:30: Ledger (window A)

1. Click **Ledger** -> **Verify chain now**. The newest entries are the review, the verification, the
   proposal, the simulation and the refused assessment you just made, each with **Prev hash** and **Entry hash**.
   > "Change one byte in the database and verification fails at that entry."

## 8:30 to 9:30: Proof-of-value report

1. Click **Reports** -> **Generate report** -> **Open full report**.
2. Scroll the executive summary: devices observed, alerts, verified by analysts, false alerts per 10k with
   the upper bound, **Enforcement executed 0, attested zero**, **Ledger integrity intact**.
3. Point at the **Validation** line: *"against AEGIS lab ground truth (synthetic corpus, simulated analyst)"*.
   > "In your pilot this exact report is produced on your data, with your analysts' dispositions, against
   > success criteria we agree before we start."

## 9:30 to 10:00: close

> "Two to four weeks, read-only, on your premises, on telemetry you already have. At the end you get this
> report on your network, and you decide with numbers. Can we pick the vantage point and the success
> criteria together this week?"

Hand over [SHADOW_PILOT_OFFER.md](SHADOW_PILOT_OFFER.md) and offer the
[security questionnaire answers](SECURITY_QUESTIONNAIRE.md).

## Questions you will get in the room

| Question | Short answer (details in [OBJECTION_HANDLING.md](OBJECTION_HANDLING.md)) |
|---|---|
| "Are these numbers real?" | "They're from a synthetic lab. The pilot produces the real ones on your network." |
| "Where does the AI come in?" | "Detection is deterministic rules plus a calibrated model. An LLM can draft the investigation summary; it can't change any decision. The demo you just saw ran without one." |
| "Does data leave our network?" | "No. It runs on your hosts; the LLM is off by default." |
| "Can it see what people watch?" | "No content, no URLs, no viewing data. Flow and DNS metadata, pseudonymized at ingest." |
