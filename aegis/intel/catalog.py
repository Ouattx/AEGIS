"""Feed catalog: where each public feed lives, its license, and its independence group.

Independence groups follow the Founder's Charter rule that no one is judged on a
single source: copies of one report count as one origin. The three abuse.ch
platforms (URLhaus, ThreatFox, Feodo Tracker) are run by one organization and
cross-populate each other, so they share **one** group, ``grp:abuse.ch``. A mirror
or aggregator that republishes another feed must be configured with the upstream's
group (``FeedSpec(..., source_group="grp:abuse.ch")``); :class:`aegis.intel.store.IntelStore`
additionally detects probable syndication from content (same value, same reference,
first_seen within a minute).

Licenses are recorded per indicator and gate consortium sharing: only feeds whose
terms allow redistribution are ever shared (``redistributable=True``). Spamhaus DROP
and Shadowserver reports are marked non-redistributable here (conservative reading:
Shadowserver reports are addressed to the network owner only).
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from typing import Literal

FeedFormat = Literal["urlhaus_csv", "threatfox_json", "feodo_csv", "feodo_txt", "spamhaus_drop",
                     "shadowserver_csv"]


@dataclass(frozen=True)
class FeedSpec:
    feed_id: str                       # "feed:urlhaus"
    name: str
    format: FeedFormat
    url: str | None                    # None => delivered out of band (e-mail / report API)
    license: str
    redistributable: bool
    source_group: str
    default_confidence: float
    ttl: timedelta                     # expiry = last_seen + ttl unless the feed states one
    snapshot: bool                     # full-list feed: entries missing from a new import are withdrawn
    auth_header: str | None = None     # HTTP header carrying an API key, when the feed requires one
    auth_env: str | None = None        # environment variable holding that key (read by the caller)

    def with_group(self, source_group: str) -> "FeedSpec":
        return replace(self, source_group=source_group)


ABUSE_CH_GROUP = "grp:abuse.ch"
SPAMHAUS_GROUP = "grp:spamhaus"
SHADOWSERVER_GROUP = "grp:shadowserver"

CATALOG: dict[str, FeedSpec] = {s.feed_id: s for s in (
    FeedSpec("feed:urlhaus", "abuse.ch URLhaus (recent URLs)", "urlhaus_csv",
             "https://urlhaus.abuse.ch/downloads/csv_recent/", "CC0-1.0", True, ABUSE_CH_GROUP,
             0.8, timedelta(days=30), snapshot=False, auth_header="Auth-Key", auth_env="AEGIS_ABUSECH_AUTH_KEY"),
    FeedSpec("feed:threatfox", "abuse.ch ThreatFox (recent IOCs)", "threatfox_json",
             "https://threatfox.abuse.ch/export/json/recent/", "CC0-1.0", True, ABUSE_CH_GROUP,
             0.75, timedelta(days=30), snapshot=False, auth_header="Auth-Key", auth_env="AEGIS_ABUSECH_AUTH_KEY"),
    FeedSpec("feed:feodo", "abuse.ch Feodo Tracker IP blocklist", "feodo_csv",
             "https://feodotracker.abuse.ch/downloads/ipblocklist.csv", "CC0-1.0", True, ABUSE_CH_GROUP,
             0.85, timedelta(days=14), snapshot=True),
    FeedSpec("feed:feodo_txt", "abuse.ch Feodo Tracker IP blocklist (plain)", "feodo_txt",
             "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", "CC0-1.0", True, ABUSE_CH_GROUP,
             0.85, timedelta(days=14), snapshot=True),
    FeedSpec("feed:spamhaus_drop", "Spamhaus DROP (IPv4)", "spamhaus_drop",
             "https://www.spamhaus.org/drop/drop_v4.json", "Spamhaus DROP terms of use", False, SPAMHAUS_GROUP,
             0.7, timedelta(days=30), snapshot=True),
    FeedSpec("feed:spamhaus_drop_v6", "Spamhaus DROP (IPv6)", "spamhaus_drop",
             "https://www.spamhaus.org/drop/drop_v6.json", "Spamhaus DROP terms of use", False, SPAMHAUS_GROUP,
             0.7, timedelta(days=30), snapshot=True),
    FeedSpec("feed:spamhaus_edrop", "Spamhaus EDROP (legacy text format)", "spamhaus_drop",
             "https://www.spamhaus.org/drop/edrop.txt", "Spamhaus DROP terms of use", False, SPAMHAUS_GROUP,
             0.7, timedelta(days=30), snapshot=True),
    FeedSpec("feed:shadowserver", "Shadowserver network reports", "shadowserver_csv", None,
             "Shadowserver report terms (recipient only)", False, SHADOWSERVER_GROUP,
             0.8, timedelta(days=14), snapshot=False),
)}


def get_spec(feed_id: str) -> FeedSpec:
    try:
        return CATALOG[feed_id]
    except KeyError as exc:
        raise KeyError(f"unknown feed {feed_id!r}; known: {', '.join(sorted(CATALOG))}") from exc


__all__ = ["ABUSE_CH_GROUP", "CATALOG", "FeedFormat", "FeedSpec", "SHADOWSERVER_GROUP", "SPAMHAUS_GROUP",
           "get_spec"]
