"""Shared builders for the assurance unit tests (contains no tests itself)."""
from __future__ import annotations

import random
from datetime import timedelta
from functools import lru_cache

from aegis.contracts.models import FeatureVector
from aegis.sentinel.model import TrainedModel, train
from test_sentinel_helpers import T0, make_fv

CLASSES = ("android_tv", "smart_tv", "phone", "camera")
FAST = {"num_leaves": 7, "min_data_in_leaf": 10}


def population(n_benign: int = 90, n_mal: int = 24, hours: int = 36, seed: int = 3, prefix: str = "",
               shift: float = 0.0) -> tuple[list[FeatureVector], list[int], dict[str, str]]:
    """Synthetic windows: benign devices plus devices that start beaconing to rare destinations.

    ``shift`` moves the benign flow rate (for drift tests).
    """
    rng = random.Random(seed)
    fvs: list[FeatureVector] = []
    labels: list[int] = []
    groups: dict[str, str] = {}
    for i in range(n_benign + n_mal):
        mal = i >= n_benign
        ent = f"p_{prefix}{'m' if mal else 'b'}{i:03d}"
        if mal:
            groups[ent] = f"campaign-{i % 8}"
        infected_h = rng.randint(0, hours // 2) if mal else None
        for h in range(1, hours + 1):
            on = bool(mal and infected_h is not None and h > infected_h)
            vals = {
                "rare_dst_frac": rng.uniform(0.2, 0.9) if on else max(0.0, rng.gauss(0.02, 0.05)),
                "beacon_dst_prevalence": rng.uniform(0.0, 0.05) if on else rng.uniform(0.03, 0.6),
                "flow_rate_h": rng.uniform(5, 80) + shift,
                "unique_dst_ip": rng.uniform(3, 50),
                "nxdomain_rate": None if rng.random() < 0.2 else rng.uniform(0, 0.05),
                "dst_entropy": rng.uniform(1.0, 4.0),
            }
            fvs.append(make_fv(vals, entity=ent, device_class=CLASSES[i % 4],
                               window_end=T0 + timedelta(hours=h)))
            labels.append(1 if on else 0)
    return fvs, labels, groups


@lru_cache(maxsize=1)
def small_model() -> TrainedModel:
    fvs, labels, groups = population()
    return train(fvs, labels, seed=7, groups=groups, params=FAST, rounds=60, dataset_info={"source": "synthetic"})
