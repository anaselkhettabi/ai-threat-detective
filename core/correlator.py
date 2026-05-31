import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser

from parsers.base import NormalizedEvent


@dataclass
class Cluster:
    cluster_id: str
    events: list[NormalizedEvent]
    suspicion_score: float
    primary_actor: str
    primary_target: str
    time_span_seconds: float
    tags: list[str] = field(default_factory=list)
    mitre_hints: list[str] = field(default_factory=list)


_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_HIGH_PRIV_ACTORS = {"root", "system", "anonymous", "administrator"}
_FAIL_KEYWORDS = ("fail", "deny", "reject", "error", "invalid", "refused", "blocked")
_BRUTE_ACTIONS = ("failed_login", "authentication_failure", "invalid_credentials")
_LATERAL_KEYWORDS = ("psexec", "wmi", "rdp", "winrm", "dcom", "smb")
_EXFIL_KEYWORDS = ("download", "export", "getobject", "s3:getobject", "copy", "transfer")
_PRIVESC_KEYWORDS = ("sudo", "runas", "attachrolepolicy", "createrolepolicy",
                     "putrolepolicy", "adduser", "addusertogroup")

_TIME_WINDOW_SECS = 15 * 60  # 15 minutes


def _parse_ts(ts: str) -> datetime | None:
    if not ts:
        return None
    try:
        dt = dateutil_parser.parse(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def _short_id() -> str:
    return str(uuid.uuid4())[:8]


def _score_cluster(events: list[NormalizedEvent]) -> tuple[float, list[str], list[str]]:
    score = 0.0
    tags = []
    mitre = []

    severities = {e.severity for e in events}
    if "Critical" in severities:
        score += 3.0
    if "High" in severities:
        score += 2.0

    if len(events) > 10:
        score += 1.5

    if len({e.event_type for e in events}) > 1:
        score += 1.0

    if len({e.source for e in events}) > 1:
        score += 1.0

    actors = {e.actor.lower() for e in events}
    if actors & _HIGH_PRIV_ACTORS or any(_IP_RE.match(a) for a in actors):
        score += 1.0

    actions_lower = [e.action.lower() for e in events]
    if any(kw in a for a in actions_lower for kw in _FAIL_KEYWORDS):
        score += 1.5
        tags.append("failed_auth")

    timestamps = sorted(filter(None, (_parse_ts(e.timestamp) for e in events)))
    if len(timestamps) >= 2:
        span = (timestamps[-1] - timestamps[0]).total_seconds()
        if span < 60 and len(events) > 5:
            score += 2.0
            tags.append("burst")
    else:
        span = 0.0

    countries = set()
    for e in events:
        if e.metadata.get("country"):
            countries.add(e.metadata["country"])
    if len(countries) > 1:
        score += 1.5
        tags.append("geo_anomaly")

    # MITRE hints
    fail_count = sum(1 for a in actions_lower if any(kw in a for kw in _FAIL_KEYWORDS))
    success_actions = [a for a in actions_lower if "success" in a or "accept" in a or "logon" in a]

    if fail_count >= 3:
        mitre.append("T1110")
        tags.append("brute_force")

    if fail_count >= 3 and success_actions:
        if "T1078" not in mitre:
            mitre.append("T1078")
        tags.append("account_compromise")

    all_text = " ".join(
        (e.action + " " + e.target + " " + e.event_type).lower() for e in events
    )

    if any(kw in all_text for kw in _LATERAL_KEYWORDS):
        mitre.append("T1021")
        tags.append("lateral_movement")

    if any(kw in all_text for kw in _EXFIL_KEYWORDS):
        mitre.append("T1030")
        tags.append("data_exfiltration")

    if any(kw in all_text for kw in _PRIVESC_KEYWORDS):
        if "T1078" not in mitre:
            mitre.append("T1078")
        tags.append("privilege_escalation")

    return min(score, 10.0), list(set(tags)), list(set(mitre))


def _build_cluster(events: list[NormalizedEvent]) -> Cluster:
    from collections import Counter
    actors = [e.actor for e in events if e.actor]
    targets = [e.target for e in events if e.target]
    primary_actor = Counter(actors).most_common(1)[0][0] if actors else "unknown"
    primary_target = Counter(targets).most_common(1)[0][0] if targets else ""

    timestamps = sorted(filter(None, (_parse_ts(e.timestamp) for e in events)))
    span = (timestamps[-1] - timestamps[0]).total_seconds() if len(timestamps) >= 2 else 0.0

    score, tags, mitre = _score_cluster(events)

    return Cluster(
        cluster_id=_short_id(),
        events=events,
        suspicion_score=round(score, 2),
        primary_actor=primary_actor,
        primary_target=primary_target,
        time_span_seconds=span,
        tags=tags,
        mitre_hints=mitre,
    )


def correlate(events: list[NormalizedEvent], top_n: int = 5) -> list[Cluster]:
    """Correlate events into suspicious clusters and return top_n by score."""
    if not events:
        return []

    # Pass 1: group by actor
    by_actor: dict[str, list[NormalizedEvent]] = {}
    for e in events:
        key = e.actor or "unknown"
        by_actor.setdefault(key, []).append(e)

    # Pass 2: time-window split within each actor group
    raw_clusters: list[list[NormalizedEvent]] = []
    for actor_events in by_actor.values():
        sorted_events = sorted(
            actor_events,
            key=lambda e: _parse_ts(e.timestamp) or datetime.min.replace(tzinfo=timezone.utc),
        )
        current: list[NormalizedEvent] = [sorted_events[0]]
        for e in sorted_events[1:]:
            prev_ts = _parse_ts(current[-1].timestamp)
            cur_ts = _parse_ts(e.timestamp)
            if prev_ts and cur_ts:
                gap = (cur_ts - prev_ts).total_seconds()
                if gap > _TIME_WINDOW_SECS:
                    raw_clusters.append(current)
                    current = []
            current.append(e)
        raw_clusters.append(current)

    # Pass 3: cross-actor merge on shared target within same time window
    merged: list[list[NormalizedEvent]] = list(raw_clusters)
    i = 0
    while i < len(merged):
        j = i + 1
        while j < len(merged):
            targets_i = {e.target for e in merged[i] if e.target}
            targets_j = {e.target for e in merged[j] if e.target}
            shared_targets = targets_i & targets_j
            if shared_targets:
                ts_i = [_parse_ts(e.timestamp) for e in merged[i] if e.timestamp]
                ts_j = [_parse_ts(e.timestamp) for e in merged[j] if e.timestamp]
                if ts_i and ts_j:
                    overlap = (
                        min(max(ts_i), max(ts_j)) - max(min(ts_i), min(ts_j))
                    ).total_seconds()
                    if overlap > -_TIME_WINDOW_SECS:
                        combined = merged[i] + merged[j]
                        merged[i] = combined
                        merged.pop(j)
                        continue
            j += 1
        i += 1

    clusters = [_build_cluster(group) for group in merged]

    # Tag coordinated attacks (clusters that were merged)
    for c in clusters:
        actors_in_cluster = {e.actor for e in c.events}
        if len(actors_in_cluster) > 1 and "coordinated_attack" not in c.tags:
            c.tags.append("coordinated_attack")

    clusters.sort(key=lambda c: c.suspicion_score, reverse=True)
    return clusters[:top_n]
