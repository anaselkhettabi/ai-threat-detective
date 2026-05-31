from datetime import datetime, timezone, timedelta

import pytest

from parsers.base import NormalizedEvent
from core.correlator import correlate, Cluster


def _make_event(
    actor: str = "alice",
    target: str = "server01",
    severity: str = "Low",
    action: str = "login",
    event_type: str = "auth",
    source: str = "test.log",
    ts_offset_minutes: float = 0,
    base_time: str = "2024-03-15T02:00:00+00:00",
) -> NormalizedEvent:
    base = datetime.fromisoformat(base_time)
    ts = (base + timedelta(minutes=ts_offset_minutes)).isoformat()
    return NormalizedEvent(
        timestamp=ts,
        source=source,
        event_type=event_type,
        severity=severity,
        actor=actor,
        action=action,
        target=target,
        metadata={},
    )


class TestActorGrouping:
    def test_two_actors_produce_two_clusters(self):
        # Use different targets so cross-actor merge doesn't combine them
        events = [
            _make_event(actor="alice", target="server01", ts_offset_minutes=i) for i in range(3)
        ] + [
            _make_event(actor="bob", target="server02", ts_offset_minutes=i) for i in range(3)
        ]
        clusters = correlate(events, top_n=10)
        actors = {c.primary_actor for c in clusters}
        assert "alice" in actors
        assert "bob" in actors

    def test_single_actor_one_cluster(self):
        events = [_make_event(actor="carol", ts_offset_minutes=i) for i in range(5)]
        clusters = correlate(events, top_n=10)
        carol_clusters = [c for c in clusters if c.primary_actor == "carol"]
        assert len(carol_clusters) == 1


class TestTimeWindowSplit:
    def test_20min_gap_splits_into_two_clusters(self):
        events = (
            [_make_event(actor="alice", ts_offset_minutes=i) for i in range(3)]
            + [_make_event(actor="alice", ts_offset_minutes=20 + i) for i in range(3)]
        )
        clusters = correlate(events, top_n=10)
        alice_clusters = [c for c in clusters if c.primary_actor == "alice"]
        assert len(alice_clusters) == 2

    def test_5min_gap_stays_one_cluster(self):
        events = [_make_event(actor="alice", ts_offset_minutes=i * 2) for i in range(5)]
        clusters = correlate(events, top_n=10)
        alice_clusters = [c for c in clusters if c.primary_actor == "alice"]
        assert len(alice_clusters) == 1


class TestSuspicionScoring:
    def test_brute_force_scores_high(self):
        # 12 failed logins in 40 seconds triggers burst (+2.0) + count>10 (+1.5) + High (+2.0) + failed_auth (+1.5)
        events = [
            _make_event(action="failed_login", severity="High",
                        ts_offset_minutes=i * (40 / 60 / 12))
            for i in range(12)
        ] + [
            _make_event(action="successful_login", severity="Low", ts_offset_minutes=0.7)
        ]
        clusters = correlate(events, top_n=5)
        assert clusters[0].suspicion_score >= 6.0

    def test_critical_event_boosts_score(self):
        events = [_make_event(severity="Critical")]
        clusters = correlate(events, top_n=5)
        assert clusters[0].suspicion_score >= 3.0

    def test_benign_cluster_scores_low(self):
        events = [
            _make_event(actor="bob", severity="Low", action="view", ts_offset_minutes=i * 10)
            for i in range(3)
        ]
        clusters = correlate(events, top_n=5)
        bob_cluster = next(c for c in clusters if c.primary_actor == "bob")
        assert bob_cluster.suspicion_score < 4.0


class TestTopN:
    def test_top_n_capped(self):
        actors = [f"user{i}" for i in range(10)]
        events = [_make_event(actor=a, ts_offset_minutes=j) for a in actors for j in range(2)]
        clusters = correlate(events, top_n=5)
        assert len(clusters) <= 5

    def test_top_n_sorted_by_score(self):
        high_events = [
            _make_event(actor="attacker", action="failed_login", severity="High",
                        ts_offset_minutes=i * 0.1)
            for i in range(8)
        ]
        low_events = [_make_event(actor="normal_user", ts_offset_minutes=i * 10) for i in range(2)]
        clusters = correlate(high_events + low_events, top_n=5)
        scores = [c.suspicion_score for c in clusters]
        assert scores == sorted(scores, reverse=True)


class TestMITREHints:
    def test_brute_force_adds_t1110(self):
        events = [
            _make_event(action="failed_login", severity="High", ts_offset_minutes=i * 0.2)
            for i in range(5)
        ]
        clusters = correlate(events, top_n=5)
        assert any("T1110" in c.mitre_hints for c in clusters)

    def test_lateral_movement_adds_t1021(self):
        events = [
            _make_event(action="rdp_connect", target="internal-server"),
            _make_event(action="smb_access", target="file-server"),
        ]
        clusters = correlate(events, top_n=5)
        assert any("T1021" in c.mitre_hints for c in clusters)

    def test_exfil_keywords_add_t1030(self):
        events = [
            _make_event(action="download", target="s3://sensitive-bucket"),
            _make_event(action="export", target="crm://all-customers"),
        ]
        clusters = correlate(events, top_n=5)
        assert any("T1030" in c.mitre_hints for c in clusters)


class TestClusterDataclass:
    def test_cluster_has_expected_fields(self):
        events = [_make_event()]
        clusters = correlate(events, top_n=5)
        c = clusters[0]
        assert isinstance(c.cluster_id, str)
        assert isinstance(c.events, list)
        assert isinstance(c.suspicion_score, float)
        assert isinstance(c.tags, list)
        assert isinstance(c.mitre_hints, list)
        assert isinstance(c.time_span_seconds, float)
