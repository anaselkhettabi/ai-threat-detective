import json
import uuid
from datetime import datetime, timezone

from core.agent import InvestigationResult
from core.correlator import Cluster
from parsers.base import NormalizedEvent
from prompts.reporter import (
    TEMPLATE_PATH,
    parse_severity,
    parse_remediation,
    enrich_mitre,
)

_SCORE_TO_SEVERITY = [
    (8.0, "Critical"),
    (6.0, "High"),
    (4.0, "Medium"),
    (0.0, "Low"),
]


def _overall_severity(clusters: list[Cluster]) -> str:
    max_score = max((c.suspicion_score for c in clusters), default=0.0)
    for threshold, label in _SCORE_TO_SEVERITY:
        if max_score >= threshold:
            return label
    return "Low"


def _event_to_dict(e: NormalizedEvent) -> dict:
    return {
        "timestamp": e.timestamp,
        "source": e.source,
        "event_type": e.event_type,
        "severity": e.severity,
        "actor": e.actor,
        "action": e.action,
        "target": e.target,
        "metadata": e.metadata,
    }


def _cluster_to_dict(c: Cluster) -> dict:
    return {
        "cluster_id": c.cluster_id,
        "suspicion_score": c.suspicion_score,
        "primary_actor": c.primary_actor,
        "primary_target": c.primary_target,
        "event_count": len(c.events),
        "time_span_seconds": c.time_span_seconds,
        "tags": c.tags,
        "mitre_hints": c.mitre_hints,
        "events": [_event_to_dict(e) for e in c.events],
    }


def _build_json(result: InvestigationResult) -> dict:
    llm_severity = parse_severity(result.final_analysis)
    score_severity = _overall_severity(result.clusters)
    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    severity = (
        llm_severity
        if severity_order.get(llm_severity, 0) >= severity_order.get(score_severity, 0)
        else score_severity
    )

    remediation = parse_remediation(result.final_analysis)
    mitre_enriched = enrich_mitre(result.mitre_techniques)

    summary_lines = result.final_analysis.split("\n")
    summary = " ".join(
        line.strip() for line in summary_lines
        if line.strip() and not line.strip().startswith(("ACTION:", "QUERY:", "SEVERITY:",
                                                          "MITRE:", "REMEDIATION:"))
    )[:600]

    return {
        "report_id": str(uuid.uuid4()),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "summary": summary,
        "clusters": [_cluster_to_dict(c) for c in result.clusters],
        "mitre_techniques": mitre_enriched,
        "remediation_actions": remediation,
        "raw_analysis": result.final_analysis,
    }


def _render_markdown(data: dict) -> str:
    from jinja2 import Environment, FileSystemLoader
    from types import SimpleNamespace

    def make_cluster_ns(c: dict):
        events = [SimpleNamespace(**e) for e in c["events"]]
        return SimpleNamespace(**{**c, "events": events})

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_PATH.parent)),
        autoescape=False,
    )
    template = env.get_template(TEMPLATE_PATH.name)
    clusters_ns = [make_cluster_ns(c) for c in data["clusters"]]

    return template.render(
        report_id=data["report_id"],
        generated_at=data["generated_at"],
        severity=data["severity"],
        summary=data["summary"],
        clusters=clusters_ns,
        mitre_techniques=data["mitre_techniques"],
        remediation_actions=data["remediation_actions"],
        raw_analysis=data["raw_analysis"],
    )


def _write_or_print(content: str, path: str | None) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
    else:
        print(content)


def generate(
    result: InvestigationResult,
    output_format: str = "both",
    output_path: str | None = None,
) -> dict:
    """Generate incident report in the requested format. Returns the JSON data dict."""
    data = _build_json(result)

    if output_format == "json":
        _write_or_print(json.dumps(data, indent=2), output_path)
    elif output_format == "markdown":
        _write_or_print(_render_markdown(data), output_path)
    else:
        _write_or_print(json.dumps(data, indent=2),
                        (output_path + ".json") if output_path else None)
        _write_or_print(_render_markdown(data),
                        (output_path + ".md") if output_path else None)

    return data
