from datetime import datetime, timezone, timedelta

import pytest

from parsers.base import NormalizedEvent
from core.correlator import correlate
from core.agent import investigate, _filter_events, InvestigationResult
from core.llm import BaseLLMClient


def _make_event(
    actor: str = "alice",
    target: str = "server01",
    severity: str = "Low",
    action: str = "login",
    event_type: str = "auth",
    ts_offset_minutes: float = 0,
) -> NormalizedEvent:
    base = datetime(2024, 3, 15, 2, 0, 0, tzinfo=timezone.utc)
    ts = (base + timedelta(minutes=ts_offset_minutes)).isoformat()
    return NormalizedEvent(
        timestamp=ts, source="test.log", event_type=event_type,
        severity=severity, actor=actor, action=action, target=target, metadata={},
    )


_REPORT_RESPONSE = """\
The logs show a brute force attack followed by successful login and privilege escalation.

SEVERITY: High
MITRE: T1110, T1078
REMEDIATION:
- Block IP 203.0.113.42
- Reset credentials for jsmith
- Enable MFA on all accounts

ACTION: REPORT
"""

_INVESTIGATE_RESPONSE = """\
Need more context on actor jsmith.

ACTION: INVESTIGATE_MORE
QUERY: actor=jsmith
"""


@pytest.fixture
def mock_llm_report(mocker):
    client = mocker.MagicMock(spec=BaseLLMClient)
    client.complete.return_value = _REPORT_RESPONSE
    return client


@pytest.fixture
def mock_llm_investigate_then_report(mocker):
    client = mocker.MagicMock(spec=BaseLLMClient)
    client.complete.side_effect = [_INVESTIGATE_RESPONSE, _REPORT_RESPONSE]
    return client


@pytest.fixture
def mock_llm_always_investigate(mocker):
    client = mocker.MagicMock(spec=BaseLLMClient)
    client.complete.return_value = _INVESTIGATE_RESPONSE
    return client


@pytest.fixture
def mock_llm_no_action(mocker):
    client = mocker.MagicMock(spec=BaseLLMClient)
    client.complete.return_value = "This is an analysis with no action tag at the end."
    return client


@pytest.fixture
def sample_events():
    return [
        _make_event(actor="jsmith", action="failed_login", severity="High", ts_offset_minutes=i * 0.2)
        for i in range(5)
    ] + [
        _make_event(actor="jsmith", action="successful_login", severity="Low", ts_offset_minutes=2)
    ] + [
        _make_event(actor="alice", action="login", severity="Low", ts_offset_minutes=i * 5)
        for i in range(3)
    ]


class TestSingleRoundReport:
    def test_rounds_used_is_1(self, mock_llm_report, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_report, max_rounds=3)
        assert result.rounds_used == 1

    def test_mitre_parsed_from_response(self, mock_llm_report, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_report, max_rounds=3)
        assert "T1110" in result.mitre_techniques
        assert "T1078" in result.mitre_techniques

    def test_final_analysis_contains_response(self, mock_llm_report, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_report, max_rounds=3)
        assert "brute force" in result.final_analysis.lower()

    def test_returns_investigation_result(self, mock_llm_report, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_report, max_rounds=3)
        assert isinstance(result, InvestigationResult)


class TestInvestigateMoreFlow:
    def test_rounds_used_is_2(self, mock_llm_investigate_then_report, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_investigate_then_report, max_rounds=3)
        assert result.rounds_used == 2

    def test_focus_events_populated_from_query(self, mock_llm_investigate_then_report, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_investigate_then_report, max_rounds=3)
        # QUERY was actor=jsmith — focus_events should contain jsmith's events
        assert len(result.focus_events) > 0
        actors = {e.actor for e in result.focus_events}
        assert "jsmith" in actors

    def test_llm_called_twice(self, mock_llm_investigate_then_report, sample_events):
        clusters = correlate(sample_events, top_n=5)
        investigate(clusters, sample_events, mock_llm_investigate_then_report, max_rounds=3)
        assert mock_llm_investigate_then_report.complete.call_count == 2


class TestMaxRoundsEnforced:
    def test_stops_at_max_rounds(self, mock_llm_always_investigate, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_always_investigate, max_rounds=3)
        assert result.rounds_used == 3

    def test_result_returned_even_at_max(self, mock_llm_always_investigate, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_always_investigate, max_rounds=3)
        assert isinstance(result, InvestigationResult)
        assert result.final_analysis


class TestMalformedActionTag:
    def test_no_action_tag_treated_as_report(self, mock_llm_no_action, sample_events):
        clusters = correlate(sample_events, top_n=5)
        result = investigate(clusters, sample_events, mock_llm_no_action, max_rounds=3)
        assert result.rounds_used == 1
        assert isinstance(result, InvestigationResult)


class TestFilterEvents:
    def test_filter_by_actor(self, sample_events):
        result = _filter_events("actor=jsmith", sample_events)
        assert all("jsmith" in e.actor for e in result)
        assert len(result) > 0

    def test_filter_by_actor_case_insensitive(self, sample_events):
        result = _filter_events("actor=JSMITH", sample_events)
        assert all("jsmith" in e.actor.lower() for e in result)

    def test_filter_by_target(self, sample_events):
        result = _filter_events("target=server01", sample_events)
        assert all("server01" in e.target for e in result)

    def test_filter_by_severity_high(self, sample_events):
        result = _filter_events("severity=High", sample_events)
        assert all(e.severity in ("High", "Critical") for e in result)

    def test_filter_by_time_range(self, sample_events):
        result = _filter_events(
            "time_range=2024-03-15T02:00:00+00:00,2024-03-15T02:01:00+00:00",
            sample_events,
        )
        # Only events within the first minute
        assert len(result) > 0

    def test_filter_by_event_type(self, sample_events):
        result = _filter_events("event_type=auth", sample_events)
        assert all("auth" in e.event_type for e in result)

    def test_unknown_query_returns_empty(self, sample_events):
        result = _filter_events("unknownfield=value", sample_events)
        assert result == []
