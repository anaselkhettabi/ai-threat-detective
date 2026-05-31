import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser

from core.correlator import Cluster
from core.llm import BaseLLMClient
from parsers.base import NormalizedEvent
from prompts.analyst import ANALYST_SYSTEM
from prompts.investigator import build_round1_message, build_followup_message
from prompts.reporter import parse_mitre


@dataclass
class InvestigationResult:
    clusters: list[Cluster]
    rounds_used: int
    final_analysis: str
    focus_events: list[NormalizedEvent]
    mitre_techniques: list[str] = field(default_factory=list)


_ACTION_RE = re.compile(r"ACTION:\s*(REPORT|INVESTIGATE_MORE)", re.IGNORECASE)
_QUERY_RE = re.compile(r"QUERY:\s*(.+)", re.IGNORECASE)


def investigate(
    clusters: list[Cluster],
    all_events: list[NormalizedEvent],
    llm: BaseLLMClient,
    max_rounds: int = 3,
    progress_callback=None,
) -> InvestigationResult:
    """Run the agentic investigation loop and return a structured result."""
    focus_events: list[NormalizedEvent] = []
    final_analysis = ""
    rounds_used = 0

    top_events = clusters[0].events[:30] if clusters else []
    user_message = build_round1_message(clusters, top_events)

    for round_num in range(1, max_rounds + 1):
        rounds_used = round_num
        if progress_callback:
            progress_callback(round_num, max_rounds)

        response = llm.complete(ANALYST_SYSTEM, user_message)
        final_analysis = response

        action_match = _ACTION_RE.search(response)
        if not action_match:
            break

        action = action_match.group(1).upper()

        if action == "REPORT":
            break

        if action == "INVESTIGATE_MORE" and round_num < max_rounds:
            query_match = _QUERY_RE.search(response)
            if query_match:
                query_str = query_match.group(1).strip()
                new_events = _filter_events(query_str, all_events)
                focus_events.extend(new_events)
            user_message = build_followup_message(
                previous_analysis=response,
                new_events=focus_events,
                rounds_remaining=max_rounds - round_num,
            )
        else:
            break

    mitre = parse_mitre(final_analysis)
    if not mitre:
        all_hints = []
        for c in clusters:
            all_hints.extend(c.mitre_hints)
        mitre = list(dict.fromkeys(all_hints))

    return InvestigationResult(
        clusters=clusters,
        rounds_used=rounds_used,
        final_analysis=final_analysis,
        focus_events=focus_events,
        mitre_techniques=mitre,
    )


def _filter_events(query_str: str, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    """Evaluate a simple query expression against all events."""
    query_str = query_str.strip()

    if query_str.startswith("actor="):
        value = query_str[6:].strip().lower()
        return [e for e in events if value in e.actor.lower()]

    if query_str.startswith("target="):
        value = query_str[7:].strip().lower()
        return [e for e in events if value in e.target.lower()]

    if query_str.startswith("event_type="):
        value = query_str[11:].strip().lower()
        return [e for e in events if value in e.event_type.lower()]

    if query_str.startswith("severity="):
        value = query_str[9:].strip().capitalize()
        _order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        threshold = _order.get(value, 0)
        return [e for e in events if _order.get(e.severity, 0) >= threshold]

    if query_str.startswith("time_range="):
        parts = query_str[11:].strip().split(",", 1)
        if len(parts) == 2:
            try:
                start = _parse_ts(parts[0].strip())
                end = _parse_ts(parts[1].strip())
                result = []
                for e in events:
                    ts = _parse_ts(e.timestamp)
                    if ts and start and end and start <= ts <= end:
                        result.append(e)
                return result
            except Exception:
                pass

    return []


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
