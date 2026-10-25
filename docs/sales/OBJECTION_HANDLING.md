# Objection handling

Principle: agree with what is true in the objection, answer with a fact we can show, and turn it into a
pilot success criterion when possible. Never answer with a claim the [claims guide](CLAIMS_GUIDE.md) forbids.

## Value and fit

**"We already have DDoS protection / a threat-intel feed / an IDS."**
Those see attacks and known indicators. SHIELD looks at the devices inside subscriber homes and asks which
ones behave like rented proxies or botnet nodes, combining your feeds with behaviour over time, and keeps the
evidence trail. It consumes your existing feeds (signed bundles) rather than replacing them.
*Pilot criterion:* "finds what our feed finds on the segment, plus N verified devices it does not."

**"We don't have a compromised-device problem."**
Possibly, and the pilot will show it with numbers either way: a pilot that finds nothing on an agreed
segment, with measured coverage, is a useful result for your risk register. Pre-infected TV boxes sold
through marketplaces are widely reported by vendors and authorities in Europe; your exposure depends on your
subscriber base.

**"What's the ROI?"**
The PoV report measures analyst minutes per case, false alerts per 10,000 device-days and cost per monitored
device-month on your data. We'd rather compute the ROI with your numbers than quote one.

**"Why pay for a pilot?"**
Because it costs your team real hours too, and a paid pilot has a defined scope, deliverables and success
criteria signed upfront. The fee can be credited towards the first year of production ([FOUNDER TO SET production_credit: credit terms]).

## Trust and accuracy

**"AI products produce too many false positives."**
Agreed, that's the main failure mode. SHIELD abstains when context is thin, needs two independent origins or
a signed indicator to verify a case, makes analysts review benign alternatives, and reports false alerts per
10,000 device-days with an upper bound. The false-alert budget is a pilot criterion you set.

**"Your numbers are from a lab."**
Yes, and we say so on every slide. That's why we sell a pilot: the only numbers that matter are measured on
your network, against criteria you set before we start.

**"Will it flag customers who use IPTV apps or Android boxes?"**
No. Device type, brand, IPTV apps and geography are never evidence; it's tested, including a deliberately busy
legitimate IPTV box in the lab. A finding needs behavioural or indicator evidence.

**"How do I know the evidence wasn't changed?"**
Every evidence item is hashed and every decision is in a signed hash chain; your team can run the
verification themselves at any time, and replay any case as it was known at decision time.

## Privacy and legal

**"Our DPO will never accept traffic analysis."**
SHIELD uses metadata your network already produces for operations and security, not content: no payload, no
decryption, no URLs, pseudonymized at ingest, on your premises. We provide the DPIA and data-map templates;
the legal basis is your DPO's and counsel's call (legitimate interest for network security and NIS2
obligations are the usual starting points).

**"ePrivacy / secret des correspondances."**
No content of communications is collected. Traffic-data processing for network security is what the DPIA
must justify; the product is built to make that case easy (minimization, retention per source, no
re-identification inside AEGIS).

**"Net neutrality: we can't block traffic."**
The pilot doesn't block anything. If you later decide to act, every action is simulated for collateral,
time-boxed, reversible, approved by a second person under a policy signed by you with a legal sign-off
reference. Whether a given action fits the open-internet rules is your counsel's decision before any active
policy is signed.

**"Is this anti-piracy?"**
No. SHIELD is a security product and deliberately ignores what people watch. Copyright enforcement follows
separate procedures (Arcom, courts) and is not part of SHIELD.

## Operations and security

**"We can't send data to a startup's cloud."**
You don't: it runs on your host, in your network, with no phone-home. Air-gapped installation works.

**"Another box to run."**
One container plus PostgreSQL, half a day to install, Prometheus metrics and a Grafana dashboard included,
backups and upgrades scripted. During the pilot we support it.

**"Is the vendor itself a supply-chain risk?"**
Signed images, SBOMs for every build, dependency audits in CI, non-root read-only containers, no standing
vendor access. No certification is claimed for v1; an independent penetration test is planned before general
availability.

**"What if you go out of business?"**
The deployment runs on your premises without us; your data and evidence stay with you in PostgreSQL and in a
verifiable ledger. Escrow terms can be discussed for production contracts.

**"Do you integrate with our SIEM / ticketing?"**
v1 exposes a REST API (findings, cases, evidence, ledger) and Prometheus metrics; a SIEM can poll the API.
Native connectors are not in v1: if one is a must-have, name it and we scope it with the production
proposal.
