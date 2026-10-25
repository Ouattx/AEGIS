# AEGIS Founder's Charter

This charter records the convictions AEGIS is built on. It is an internal document for
the founder, the team, and every engineer or AI agent that works on this codebase.

**Usage rule.** Scripture references appear only in this charter. On the website, in the
platform, in the product UI, in sales material, and in system text, the principles are
expressed by their plain sayings only (the "Principle" lines below), never with verses
or citations.

Each principle names the rules in the product that enforce it. If a change would break
one of those rules, the change is wrong, however convenient it looks.

---

## 1. Two independent witnesses

> *"A single witness shall not suffice against a person for any crime or for any wrong
> in connection with any offense that he has committed. Only on the evidence of two
> witnesses or of three witnesses shall a charge be established."* (Deuteronomy 19:15)

**Principle:** No one is judged on a single source.

**Enforced by**
- A case can reach VERIFIED only with qualifying evidence from at least two independent
  origins, or a verified signed indicator, plus a review of the alternative explanation
  (`aegis/oracle/state_machine.py`).
- Feeds that syndicate the same report count as one origin (`source_independence_group`,
  `aegis/provenance/evidence.py`).

## 2. No false witness

> *"You shall not bear false witness against your neighbor."* (Exodus 20:16)

**Principle:** We never accuse without evidence, and we never claim more than we can prove.

**Enforced by**
- Every finding cites evidence ids; every decision is recorded in the signed,
  hash-chained ledger (`aegis/provenance/ledger.py`).
- Counter-evidence and alternative hypotheses are stored alongside the accusation.
- Scores are not called probabilities unless calibrated; no accuracy claim without base
  rate and error cost (spec §14, `docs/sales/` claims guide).

## 3. A just weight

> *"A false balance is an abomination to the LORD, but a just weight is his delight."*
> (Proverbs 11:1)

**Principle:** Honest measures, published limits.

**Enforced by**
- Benchmarks report confidence intervals, false alerts per 10k device-days, and failure
  cases (`eval/`, `docs/RESONANCE.md`).
- Synthetic results are labelled as synthetic wherever they are shown.

## 4. Treat others as you would be treated

> *"So whatever you wish that others would do to you, do also to them…"* (Matthew 7:12)

**Principle:** We protect people's privacy as we would want ours protected.

**Enforced by**
- No payload inspection, no TLS decryption, no viewing-profile inference; pseudonyms
  only, with tenant-controlled re-identification (CLAUDE.md non-negotiables,
  `aegis/ingest/pseudonym.py`).
- Strict tenant isolation on every read.

## 5. Justice, mercy, humility

> *"He has told you, O man, what is good; and what does the LORD require of you but to do
> justice, and to love kindness, and to walk humbly with your God?"* (Micah 6:8)

**Principle:** Act justly, show mercy, admit what we do not know.

**Enforced by**
- Abstain is a first-class outcome; uncertain cases go to a human (`aegis/sentinel/fusion.py`).
- Humans approve consequential actions; AI proposes and never decides.
- Every action is reversible and has a tested rollback; subscribers are notified before
  restriction (`aegis/mirror/`).

## 6. Protect what belongs to others

> *"You shall not steal."* (Exodus 20:15)

**Principle:** We defend people from those who hijack their devices and connections.

**Enforced by**
- The product's purpose: finding and disrupting botnets that steal subscribers'
  bandwidth, identity, and devices.

## 7. Speak for those who cannot

> *"Open your mouth for the mute, for the rights of all who are destitute."* (Proverbs 31:8)

**Principle:** We protect those who do not know they are at risk.

**Enforced by**
- Detection of pre-infected devices whose owners have no way to know they are
  compromised, and subscriber notification paths that explain how to get clean.

## 8. Faithful in little

> *"One who is faithful in a very little is also faithful in much…"* (Luke 16:10)

**Principle:** Integrity in every detail.

**Enforced by**
- Tests for every safety rule in CI, signed builds, an append-only ledger, and no
  shortcuts in code paths that touch people's connections.

---

Scripture quotations are from the ESV.
