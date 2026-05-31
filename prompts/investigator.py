from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.correlator import Cluster
    from parsers.base import NormalizedEvent


def build_round1_message(clusters: list["Cluster"], top_events: list["NormalizedEvent"]) -> str:
    lines = ["## Security Event Clusters for Investigation\n"]

    header = "| Cluster | Score | Actor | Target | Events | MITRE Hints |"
    separator = "|---------|-------|-------|--------|--------|-------------|"
    lines.append(header)
    lines.append(separator)
    for c in clusters:
        hints = ", ".join(c.mitre_hints) or "—"
        target_short = (c.primary_target or "")[:40]
        actor_short = (c.primary_actor or "")[:40]
        lines.append(
            f"| {c.cluster_id} | {c.suspicion_score:.1f} | {actor_short} "
            f"| {target_short} | {len(c.events)} | {hints} |"
        )

    top = clusters[0] if clusters else None
    if top:
        lines.append(f"\n## Top Cluster Events ({top.cluster_id}, Score {top.suspicion_score:.1f})\n")
        lines.append(_event_table(top_events))

    lines.append("\nAnalyze these clusters. Identify the attack scenario and signal your next action.")
    return "\n".join(lines)


def build_followup_message(
    previous_analysis: str,
    new_events: list["NormalizedEvent"],
    rounds_remaining: int,
) -> str:
    lines = [
        "## Previous Analysis\n",
        previous_analysis[:2000],
        "\n## Additional Events Retrieved\n",
        _event_table(new_events),
        f"\n({rounds_remaining} investigation round(s) remaining)\n",
        "Continue your analysis with this new information and signal your next action.",
    ]
    return "\n".join(lines)


def _event_table(events: list["NormalizedEvent"]) -> str:
    if not events:
        return "_No events._"
    header = "| Timestamp | Actor | Action | Target | Severity | Type |"
    sep = "|-----------|-------|--------|--------|----------|------|"
    rows = [header, sep]
    for e in events[:50]:
        ts = (e.timestamp or "")[:19]
        actor = (e.actor or "")[:30]
        action = (e.action or "")[:25]
        target = (e.target or "")[:30]
        rows.append(f"| {ts} | {actor} | {action} | {target} | {e.severity} | {e.event_type} |")
    if len(events) > 50:
        rows.append(f"_... and {len(events) - 50} more events_")
    return "\n".join(rows)
