import json
from io import StringIO
from unittest.mock import patch

import pytest

from parsers.base import NormalizedEvent
from core.correlator import correlate
from core.agent import InvestigationResult
from core.reporter import generate, _build_json, _overall_severity, _render_markdown
from core.correlator import Cluster


def _make_result(analysis: str = "", score: float = 7.5) -> InvestigationResult:
    from datetime import datetime, timezone, timedelta
    base = datetime(2024, 3, 15, 2, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(
            timestamp=(base + timedelta(seconds=i * 10)).isoformat(),
            source="test.log",
            event_type="auth",
            severity="High",
            actor="jsmith",
            action="failed_login",
            target="server01",
            metadata={},
        )
        for i in range(5)
    ]
    clusters = correlate(events, top_n=5)
    if clusters:
        clusters[0].suspicion_score = score

    default_analysis = analysis or """\
Brute force attack detected, followed by privilege escalation.

SEVERITY: High
MITRE: T1110, T1078
REMEDIATION:
- Block source IP 203.0.113.42
- Reset credentials for jsmith
ACTION: REPORT
"""
    return InvestigationResult(
        clusters=clusters,
        rounds_used=1,
        final_analysis=default_analysis,
        focus_events=[],
        mitre_techniques=["T1110", "T1078"],
    )


class TestJSONOutput:
    def test_all_required_keys_present(self):
        result = _make_result()
        data = _build_json(result)
        required = {"report_id", "generated_at", "severity", "summary",
                    "clusters", "mitre_techniques", "remediation_actions", "raw_analysis"}
        assert required <= set(data.keys())

    def test_report_id_is_string(self):
        data = _build_json(_make_result())
        assert isinstance(data["report_id"], str) and len(data["report_id"]) > 0

    def test_clusters_is_list(self):
        data = _build_json(_make_result())
        assert isinstance(data["clusters"], list)

    def test_mitre_techniques_enriched(self):
        data = _build_json(_make_result())
        for t in data["mitre_techniques"]:
            assert "id" in t
            assert "name" in t
            assert "url" in t

    def test_remediation_extracted_from_analysis(self):
        result = _make_result()
        data = _build_json(result)
        assert isinstance(data["remediation_actions"], list)
        assert len(data["remediation_actions"]) >= 2

    def test_generate_json_to_stdout(self, capsys):
        result = _make_result()
        generate(result, output_format="json", output_path=None)
        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert "report_id" in parsed

    def test_generate_json_to_file(self, tmp_path):
        result = _make_result()
        out = str(tmp_path / "report.json")
        generate(result, output_format="json", output_path=out)
        with open(out) as f:
            parsed = json.load(f)
        assert "report_id" in parsed


class TestMarkdownOutput:
    def test_markdown_contains_incident_report_header(self):
        data = _build_json(_make_result())
        md = _render_markdown(data)
        assert "# Incident Report" in md

    def test_markdown_contains_mitre_section(self):
        data = _build_json(_make_result())
        md = _render_markdown(data)
        assert "MITRE" in md

    def test_markdown_contains_remediation_section(self):
        data = _build_json(_make_result())
        md = _render_markdown(data)
        assert "Remediation" in md

    def test_generate_markdown_to_stdout(self, capsys):
        result = _make_result()
        generate(result, output_format="markdown", output_path=None)
        captured = capsys.readouterr()
        assert "# Incident Report" in captured.out


class TestSeverityDerivation:
    def test_score_9_gives_critical(self):
        assert _overall_severity([_cluster_with_score(9.0)]) == "Critical"

    def test_score_7_gives_high(self):
        assert _overall_severity([_cluster_with_score(7.0)]) == "High"

    def test_score_5_gives_high(self):
        assert _overall_severity([_cluster_with_score(5.0)]) == "Medium"

    def test_score_2_gives_low(self):
        assert _overall_severity([_cluster_with_score(2.0)]) == "Low"

    def test_highest_cluster_wins(self):
        clusters = [_cluster_with_score(9.0), _cluster_with_score(2.0)]
        assert _overall_severity(clusters) == "Critical"

    def test_empty_clusters_gives_low(self):
        assert _overall_severity([]) == "Low"


class TestRemediationExtraction:
    def test_remediation_list_extracted(self):
        result = _make_result()
        data = _build_json(result)
        assert "Block source IP 203.0.113.42" in data["remediation_actions"]
        assert "Reset credentials for jsmith" in data["remediation_actions"]

    def test_no_remediation_section_returns_empty_list(self):
        result = _make_result(analysis="Just an analysis.\n\nACTION: REPORT\nSEVERITY: Low\nMITRE: T1110\n")
        data = _build_json(result)
        assert isinstance(data["remediation_actions"], list)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cluster_with_score(score: float) -> Cluster:
    from parsers.base import NormalizedEvent
    from datetime import datetime, timezone
    e = NormalizedEvent(
        timestamp=datetime.now(timezone.utc).isoformat(),
        source="test", event_type="auth", severity="Low",
        actor="alice", action="login", target="server", metadata={},
    )
    return Cluster(
        cluster_id="test",
        events=[e],
        suspicion_score=score,
        primary_actor="alice",
        primary_target="server",
        time_span_seconds=0.0,
    )
