"""Crowd mixing: what RESONANCE would see if many homes had this box. MIXED-SYNTHETIC.

RESONANCE works across subscriber lines; one home is one line, so it cannot run on a
home-lab capture alone (it abstains below ``min_lines``). To *demonstrate* it on a real
capture, this module embeds the capture as ``n_copies`` lines into a simulated ISP
population (:mod:`aegis.resonance.sim`, built on the :mod:`aegis.lab` hosting topology):

* each copy is an independent *renewal bootstrap* of the device: per destination, the
  gaps between contacts are resampled with replacement from the capture, starting at a
  random phase. A jittered timer stays a timer and irregular traffic stays irregular,
  but copies do not share the one real event sequence, so structure present only by
  chance in the capture does not add up across copies;
* the simulated population supplies benign traffic, benign shared timers and the
  destination-label permutation null; a campaign-free warm-up day of the same
  population serves as destination history (RESONANCE's recommended deployment);
* RESONANCE then runs unchanged.

How to read the result
    Every copy is the same device, so *every* timer of the box, benign or not, is shared
    by ``n_copies`` lines toward the same destination. A campaign on a capture
    destination means "this timer would be detectable across homes", not "this box is
    malicious": a real network also contains the many other devices that contact benign
    vendor services, which makes popular destinations ineligible. Copies of the capture
    are not independent homes. Real capture destinations are absent from the simulated
    topology, so they are never enforcement-eligible (fail closed).

Results are labelled ``data_class="mixed_synthetic"`` everywhere, are never turned
into :class:`Finding` objects and are never written to the provenance ledger.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Sequence

import numpy as np
import pandas as pd

from aegis.contracts.models import ObservationEvent
from aegis.resonance.config import ResonanceConfig
from aegis.resonance.detector import Resonance
from aegis.resonance.events import build_event_table, observations_to_frames
from aegis.resonance.models import ResonanceReport
from aegis.resonance.population import DestinationContext, DestinationHistory
from aegis.resonance.sim import ScenarioSpec, baseline_history, generate_scenario

DATA_CLASS = "mixed_synthetic"
MIXED_LABEL = ("MIXED-SYNTHETIC: one real home-lab capture replicated into a simulated population. "
               "Not a measurement of any real network; copies are the same device, not independent homes.")
COPY_PREFIX = "p_homelab_copy_"


@dataclass(frozen=True)
class CrowdMixConfig:
    n_copies: int = 20
    n_lines: int = 600                    # simulated background lines
    seed: int = 7
    sampling: int = 1                     # NetFlow packet sampling 1:N applied to the simulated background
    cluster_s: float = 5.0                # rows of one destination closer than this form one contact
    warmup_history: bool = True
    q: float = 0.01
    allowlist: tuple[str, ...] = ()       # operator-style known-service keys/suffixes (never campaign targets)

    def __post_init__(self) -> None:
        if self.n_copies < 5:
            raise ValueError("n_copies must be at least 5 (RESONANCE needs min_lines unrelated lines)")
        if self.n_lines < 50:
            raise ValueError("n_lines must be at least 50")
        if not 0.0 < self.cluster_s <= 60.0:
            raise ValueError("cluster_s must be within (0, 60] seconds")
        if self.n_copies / (self.n_copies + self.n_lines) > 0.2:
            raise ValueError("copies would exceed 20 % of lines: RESONANCE's popularity gate would make every "
                             "capture destination ineligible; add background lines or use fewer copies")


@dataclass
class CrowdCampaign:
    campaign_id: str
    destinations: list[str]
    involves_capture: bool
    capture_copies: int
    member_lines: int
    period_s: float | None
    q_value: float
    statistic: str
    enforcement_eligible: bool
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CrowdMixResult:
    config: CrowdMixConfig
    report: ResonanceReport
    campaigns: list[CrowdCampaign]
    capture_keys_tested: list[dict[str, Any]]
    capture_keys_not_tested: int
    window_start: datetime
    window_end: datetime
    copies: int
    background_lines: int
    notes: list[str] = field(default_factory=list)
    data_class: str = DATA_CLASS
    label: str = MIXED_LABEL

    @property
    def capture_campaigns(self) -> list[CrowdCampaign]:
        return [c for c in self.campaigns if c.involves_capture]

    @property
    def background_campaigns(self) -> list[CrowdCampaign]:
        return [c for c in self.campaigns if not c.involves_capture]

    def to_dict(self) -> dict[str, Any]:
        return {"data_class": self.data_class, "label": self.label, "config": asdict(self.config),
                "status": self.report.status, "abstain_reason": self.report.abstain_reason,
                "window_start": self.window_start.isoformat(), "window_end": self.window_end.isoformat(),
                "copies": self.copies, "background_lines": self.background_lines,
                "campaigns": [c.to_dict() for c in self.campaigns],
                "capture_keys_tested": self.capture_keys_tested,
                "capture_keys_not_tested": self.capture_keys_not_tested, "notes": self.notes,
                "resonance": {"detector_version": self.report.detector_version,
                              "config_hash": self.report.config_hash, "n_tested": self.report.n_tested,
                              "n_ineligible": self.report.n_ineligible,
                              "ineligible_reasons": self.report.ineligible_reasons}}


@dataclass
class _Rows:
    """Rows of one destination grouped by contact: relative times, contact offsets, other columns."""
    rel_t: np.ndarray
    offsets: np.ndarray                     # len n_contacts + 1
    cols: dict[str, np.ndarray]

    def take(self, picks: np.ndarray, starts: np.ndarray) -> dict[str, np.ndarray]:
        cnt = self.offsets[picks + 1] - self.offsets[picks]
        total = int(cnt.sum())
        if total == 0:
            return {"t": np.zeros(0), **{k: v[:0] for k, v in self.cols.items()}}
        base = np.repeat(self.offsets[picks], cnt)
        within = np.arange(total) - np.repeat(np.cumsum(cnt) - cnt, cnt)
        idx = base + within
        return {"t": self.rel_t[idx] + np.repeat(starts, cnt), **{k: v[idx] for k, v in self.cols.items()}}


def _rows(df: pd.DataFrame, contact: np.ndarray, starts: np.ndarray, n_contacts: int, cols: list[str]) -> _Rows:
    order = np.argsort(contact, kind="stable")
    c = contact[order]
    offsets = np.searchsorted(c, np.arange(n_contacts + 1), side="left").astype(np.int64)
    rel = df["t"].to_numpy(dtype=np.float64)[order] - starts[c]
    return _Rows(rel, offsets, {k: df[k].to_numpy(dtype=object)[order] for k in cols})


def _contact_groups(flows: pd.DataFrame, dns: pd.DataFrame, join_ttl_s: float,
                    cluster_s: float) -> list[tuple[np.ndarray, _Rows, _Rows]]:
    """Group the device's rows by destination key and into contacts (a lookup and the flows right after it)."""
    answers: dict[str, list[tuple[float, str]]] = {}
    for t, q, a in zip(dns["t"].to_numpy(), dns["qname"].to_numpy(), dns["answer_ip"].to_numpy()):
        if isinstance(a, str) and a:
            answers.setdefault(a, []).append((float(t), "d:" + str(q).strip().lower().rstrip(".")))
    for lst in answers.values():
        lst.sort()
    dest_f = np.empty(len(flows), dtype=object)
    for i, (t, ip) in enumerate(zip(flows["t"].to_numpy(), flows["dst_ip"].to_numpy())):
        key = "ip:" + str(ip)
        for ta, name in reversed(answers.get(str(ip), [])):
            if ta <= t + 1.0 and t - ta <= join_ttl_s:
                key = name
                break
        dest_f[i] = key
    dest_d = np.array(["d:" + str(q).strip().lower().rstrip(".") for q in dns["qname"].to_numpy()], dtype=object)
    groups = []
    for key in sorted(set(dest_f.tolist()) | set(dest_d.tolist())):
        f = flows[dest_f == key]
        d = dns[dest_d == key]
        times = np.sort(np.concatenate([f["t"].to_numpy(dtype=np.float64), d["t"].to_numpy(dtype=np.float64)]))
        if len(times) == 0:
            continue
        st_list = [times[0]]
        for t in times[1:]:
            if t - st_list[-1] > cluster_s:
                st_list.append(t)
        st = np.asarray(st_list)
        cf = np.searchsorted(st, f["t"].to_numpy(dtype=np.float64), side="right") - 1
        cd = np.searchsorted(st, d["t"].to_numpy(dtype=np.float64), side="right") - 1
        groups.append((st, _rows(f, cf, st, len(st), ["dst_ip", "bytes", "dur_s"]),
                       _rows(d, cd, st, len(st), ["qname", "answer_ip"])))
    return groups


def _smoothed_gaps(gaps: np.ndarray, size: int, rng: np.random.Generator) -> np.ndarray:
    """Smoothed bootstrap of contact gaps on the log scale (Silverman bandwidth).

    Plain resampling of a handful of gaps would give every copy the same few gap values, a
    shared structure that exists only because the capture is small. Kernel smoothing on log
    gaps removes that artifact; for a genuine timer (many similar gaps) the bandwidth, and
    so the added jitter, stays small.
    """
    lg = np.log(np.maximum(gaps, 1e-3))
    n = len(lg)
    sd = float(np.std(lg, ddof=1)) if n > 1 else 0.0
    iqr = float(np.subtract(*np.percentile(lg, [75, 25]))) if n > 1 else 0.0
    spread = min(sd, iqr / 1.34) if iqr > 0 else sd
    h = 0.9 * spread * n ** (-0.2) if spread > 0 else 0.0
    draw = rng.choice(lg, size=size) + (rng.normal(0.0, h, size) if h > 0 else 0.0)
    return np.exp(draw)


def _copies(flows: pd.DataFrame, dns: pd.DataFrame, n: int, s0: float, span: float, join_ttl_s: float,
            cluster_s: float, rng: np.random.Generator) -> tuple[pd.DataFrame, pd.DataFrame]:
    """``n`` independent renewal-bootstrap realizations of the device (see module docstring)."""
    groups = _contact_groups(flows, dns, join_ttl_s, cluster_s)
    fparts: list[dict[str, np.ndarray]] = []
    dparts: list[dict[str, np.ndarray]] = []
    for k in range(n):
        line = f"{COPY_PREFIX}{k:03d}"
        for st, rf, rd in groups:
            gaps = np.diff(st)
            if len(gaps) == 0:
                times = np.array([s0 + float(rng.uniform(0.0, span))])
            else:
                draws = _smoothed_gaps(gaps, int(np.ceil(span / max(float(gaps.min()), 1.0))) + 2, rng)
                first = float(rng.uniform(0.0, float(draws[0])))
                times = s0 + first + np.concatenate([[0.0], np.cumsum(draws[1:])])
                times = times[times < s0 + span]
            picks = rng.integers(0, len(st), size=len(times))
            for rows, parts in ((rf, fparts), (rd, dparts)):
                got = rows.take(picks, times)
                if len(got["t"]):
                    got["line"] = np.full(len(got["t"]), line, dtype=object)
                    parts.append(got)

    def frame(parts: list[dict[str, np.ndarray]], cols: list[str]) -> pd.DataFrame:
        if not parts:
            return pd.DataFrame(columns=cols)
        df = pd.DataFrame({c: np.concatenate([p[c] for p in parts]) for c in cols})
        return df[df["t"] < s0 + span].reset_index(drop=True)

    out_f = frame(fparts, ["t", "line", "dst_ip", "bytes", "dur_s"])
    out_d = frame(dparts, ["t", "line", "qname", "answer_ip"])
    if len(out_f):
        out_f["bytes"] = out_f["bytes"].astype(np.float64)
        out_f["dur_s"] = out_f["dur_s"].astype(np.float64)
    return out_f, out_d


def _plain(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for c in out.columns:
        if isinstance(out[c].dtype, pd.CategoricalDtype):
            out[c] = out[c].astype(object)
    return out


def crowd_mix(device_events: Sequence[ObservationEvent], *, start: datetime, end: datetime,
              cfg: CrowdMixConfig | None = None, tenant_id: str = "homelab-crowd-mix",
              resonance_cfg: ResonanceConfig | None = None) -> CrowdMixResult:
    """Embed one device's capture as ``cfg.n_copies`` lines into a simulated population and run RESONANCE."""
    cfg = cfg or CrowdMixConfig()
    pseudos = {e.entity_pseudonym for e in device_events if e.entity_pseudonym}
    if len(pseudos) != 1:
        raise ValueError("crowd mixing takes the events of exactly one device")
    rcfg = (resonance_cfg or ResonanceConfig()).with_(q=cfg.q, seed=cfg.seed, allowlist=tuple(cfg.allowlist),
                                                      q_malicious=min(cfg.q, ResonanceConfig().q_malicious))
    s0_dt = start.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    hours = max(1, int(np.ceil((end - s0_dt).total_seconds() / 3600.0)))
    s0 = s0_dt.timestamp()
    span = hours * 3600.0
    spec = ScenarioSpec(n_lines=cfg.n_lines, days=hours / 24.0, start=s0_dt, seed=cfg.seed, campaigns=[])
    sc = generate_scenario(spec, sampling=cfg.sampling)
    flows, dns = observations_to_frames(device_events)
    rng = np.random.default_rng([cfg.seed, 99])
    cf, cd = _copies(flows.drop(columns=["line"]), dns.drop(columns=["line"]), cfg.n_copies, s0, span,
                     rcfg.dns_join_ttl_s, cfg.cluster_s, rng)
    all_f = pd.concat([_plain(sc.flows), cf], ignore_index=True)
    all_d = pd.concat([_plain(sc.dns), cd], ignore_index=True)
    table = build_event_table(all_f, all_d, dns_join_ttl_s=rcfg.dns_join_ttl_s, start=s0, end=s0 + span)
    history = baseline_history(spec, rcfg, sampling=cfg.sampling) if cfg.warmup_history else DestinationHistory()
    report = Resonance(rcfg, context=DestinationContext(sc.topology), history=history,
                       tenant_id=tenant_id).detect(table)

    capture_keys = set()
    for ip in flows["dst_ip"].dropna().unique():
        capture_keys.add("ip:" + str(ip))
    for name in dns["qname"].dropna().unique():
        capture_keys.add("d:" + str(name).strip().lower().rstrip("."))
    campaigns = []
    for c in report.campaigns:
        copies = sum(1 for m in c.member_lines if m.startswith(COPY_PREFIX))
        campaigns.append(CrowdCampaign(campaign_id=c.campaign_id, destinations=list(c.destinations),
                                       involves_capture=copies > 0, capture_copies=copies,
                                       member_lines=c.n_lines, period_s=c.period_s, q_value=c.q_value,
                                       statistic=c.statistic, enforcement_eligible=c.enforcement_eligible,
                                       explanation=c.explanation))
    tested: list[dict[str, Any]] = [{"destinations": t.destinations, "n_lines": t.n_lines, "p_value": t.p_value, "q_value": t.q_value,
               "period_s": t.period_s, "rejected": t.rejected, "weight": t.weight}
              for t in report.tested if set(t.destinations) & capture_keys]
    tested_keys = {k for t in report.tested if set(t.destinations) & capture_keys for k in t.destinations}
    notes = [MIXED_LABEL,
             "Capture copies share every timer of the box, benign ones included: a campaign on a capture "
             "destination shows detectability across homes, not maliciousness.",
             "Real capture destinations are not in the simulated topology: not enforcement-eligible (fail closed)."]
    if not cfg.warmup_history:
        notes.append("No warm-up history: benign shared timers of the simulated population may appear as "
                     "campaigns (RESONANCE cold-start limitation).")
    if report.status == "abstain":
        notes.append(f"RESONANCE abstained: {report.abstain_reason}")
    return CrowdMixResult(config=cfg, report=report, campaigns=campaigns, capture_keys_tested=tested,
                          capture_keys_not_tested=len(capture_keys - tested_keys),
                          window_start=s0_dt, window_end=s0_dt + timedelta(seconds=span), copies=cfg.n_copies,
                          background_lines=cfg.n_lines, notes=notes)


__all__ = ["COPY_PREFIX", "CrowdCampaign", "CrowdMixConfig", "CrowdMixResult", "DATA_CLASS", "MIXED_LABEL",
           "crowd_mix"]
