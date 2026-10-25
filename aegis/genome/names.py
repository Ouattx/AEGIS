"""Domain-name statistics used as DGA-likeness features (no lookups, pure string math)."""
from __future__ import annotations

import math
from collections import Counter
from typing import Iterable

# frequent English letter bigrams; DGA labels use many bigrams outside this set
COMMON_BIGRAMS = frozenset(
    "th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi "
    "ri ro ic ne ea ra ce li ch ll be ma si om ur ca el ta la ns di fo ho pe ec pr no ct us ac ot il tr ly nc "
    "et ut ss so rs un lo wa ge ie wh ee wi em ad ol rt po we na ul ni ts mo ow pa im mi ai sh ir su id os iv "
    "ia am fi ci vi pl ig tu ev ld ry mp fe bl ab gh ty op wo sa ay ex ke fr oo av ag if ap gr od bo sp rd do "
    "uc bu ei ov by rm ep tt oc fa ef cu rn sc gi da yo cr cl du ga qu ue ff ba ey ls va um pp ua up lu go ht "
    "ru ug ds lt pi rc rr eg au ck ew mu br bi pt ak pu ui rg ib tl ny ki rk ys ob mm fu ph og ms ye ud mb ip "
    "ub oi rl gu dr hr cc tw ft wn nu af hu nn eo vo rv nf xp gn sm fl iz ok nl my gl aw ju oa eq sy sl ps jo "
    "lf nv je nk kn gs dy hy ze ks xt bs ik dd cy rp sk xi oe oy ws lv dl rf eu dg wr xa yi nm eb rb tm xc eh "
    "tc gy ja hn yp za gg ym sw bj lm cs ii ix xe oh lk dv lp ax ox uf dm iu sf bt ka yt ek pm ya gt wl rh yl "
    "hs ah yc yn rw hm lw hl ae zi az lc py aj iq nj bb nh uo kl lb tn gm sn nr fy mn dw sb yr dn sq ry".split())


def leftmost_label(qname: str) -> str:
    return qname.strip().lower().rstrip(".").split(".")[0]


def entropy_per_char(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def bigram_novelty(s: str) -> float:
    letters = "".join(ch for ch in s if ch.isalpha())
    bg = [letters[i:i + 2] for i in range(len(letters) - 1)]
    if not bg:
        return 1.0 if s else 0.0
    return sum(1 for b in bg if b not in COMMON_BIGRAMS) / len(bg)


def name_stats(names: Iterable[str]) -> dict[str, float | None]:
    labels = [leftmost_label(n) for n in names if n]
    if not labels:
        return {"entropy": None, "novelty": None, "length": None}
    return {"entropy": sum(map(entropy_per_char, labels)) / len(labels),
            "novelty": sum(map(bigram_novelty, labels)) / len(labels),
            "length": sum(map(len, labels)) / len(labels)}
