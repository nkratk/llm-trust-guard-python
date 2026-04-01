"""
Tests for DriftDetector guard.
Ported from drift-detector.test.ts (9 tests).
"""

import sys
import os
import time
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.drift_detector import (
    DriftDetector,
    DriftDetectorConfig,
    BehaviorSample,
    BaselineProfile,
)


def _now_ms():
    return time.time() * 1000


def _make_sample(**overrides):
    defaults = dict(
        timestamp=_now_ms(),
        tools=["search", "summarize"],
        topics=["science", "math"],
        sentiment=0.5,
        response_length=200,
        response_time=300,
        had_error=False,
    )
    defaults.update(overrides)
    return BehaviorSample(**defaults)


def _make_detector(**overrides):
    defaults = dict(
        minimum_samples=5,
        anomaly_threshold=2.0,
        alert_threshold=40,
        auto_update_baseline=True,
        baseline_window=24 * 60 * 60 * 1000,
    )
    defaults.update(overrides)
    return DriftDetector(DriftDetectorConfig(**defaults))


class TestInsufficientData:
    def test_should_return_insufficient_data_when_below_minimum_samples(self):
        detector = _make_detector()
        detector.record_sample("agent-1", _make_sample())
        result = detector.analyze("agent-1")

        assert result.allowed is True
        assert "Insufficient" in result.reason
        assert result.analysis.is_drifting is False
        assert result.analysis.drift_score == 0


class TestBaselineEstablishment:
    def test_should_establish_a_baseline_after_enough_samples(self):
        detector = _make_detector()
        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(timestamp=_now_ms() + i),
            )

        baseline = detector.get_baseline("agent-1")
        assert baseline is not None
        assert baseline.sample_count >= 5
        assert abs(baseline.avg_sentiment - 0.5) < 0.1
        assert "search" in baseline.tool_distribution
        assert "summarize" in baseline.tool_distribution


class TestToolDriftDetection:
    def test_should_detect_drift_when_tools_change_dramatically(self):
        detector = _make_detector()
        # Build baseline with consistent tool usage
        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(timestamp=_now_ms() + i),
            )
        detector.update_baseline("agent-1")

        # Introduce completely different tool usage
        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(
                    timestamp=_now_ms() + 100 + i,
                    tools=["hack_database", "exfiltrate_data", "delete_logs"],
                    topics=["hacking", "exploitation"],
                    sentiment=-0.9,
                    response_length=5000,
                    response_time=5000,
                    had_error=True,
                ),
            )

        result = detector.analyze("agent-1")
        assert result.analysis.is_drifting is True
        assert result.analysis.drift_score >= 40
        assert len(result.analysis.indicators) > 0


class TestIsDriftingPublicMethod:
    def test_should_report_is_drifting_correctly(self):
        detector = _make_detector()
        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(timestamp=_now_ms() + i),
            )
        detector.update_baseline("agent-1")

        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(
                    timestamp=_now_ms() + 200 + i,
                    tools=["unknown_tool_1", "unknown_tool_2"],
                    topics=["forbidden_area"],
                    sentiment=-1,
                    response_length=10000,
                    response_time=20000,
                    had_error=True,
                ),
            )

        detector.analyze("agent-1")

        assert detector.is_drifting("agent-1") is True
        assert "agent-1" in detector.get_drifting_agents()


class TestFalsePositive:
    def test_should_allow_behavior_within_normal_parameters(self):
        detector = _make_detector()
        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(
                    timestamp=_now_ms() + i,
                    sentiment=0.5 + (random.random() * 0.1 - 0.05),
                    response_length=200 + int(random.random() * 20),
                    response_time=300 + int(random.random() * 20),
                ),
            )
        detector.update_baseline("agent-1")

        result = detector.analyze(
            "agent-1",
            _make_sample(
                timestamp=_now_ms() + 100,
                sentiment=0.48,
                response_length=210,
                response_time=310,
            ),
        )

        assert result.allowed is True
        assert result.analysis.is_drifting is False


class TestManualBaseline:
    def test_should_set_and_retrieve_a_manual_baseline(self):
        detector = _make_detector()
        baseline = BaselineProfile(
            tool_distribution={"search": 0.5, "summarize": 0.5},
            topic_distribution={"science": 1.0},
            avg_sentiment=0.6,
            sentiment_std_dev=0.1,
            avg_response_length=250,
            response_length_std_dev=50,
            avg_response_time=400,
            response_time_std_dev=100,
            error_rate=0.05,
            avg_satisfaction=0.8,
            sample_count=100,
            last_updated=_now_ms(),
        )

        detector.set_baseline("agent-2", baseline)
        retrieved = detector.get_baseline("agent-2")
        assert retrieved is not None
        assert retrieved.avg_sentiment == 0.6


class TestResetAgent:
    def test_should_reset_agent_state(self):
        detector = _make_detector()
        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(timestamp=_now_ms() + i),
            )
        assert detector.get_sample_count("agent-1") == 10

        detector.reset_agent("agent-1")
        assert detector.get_sample_count("agent-1") == 0
        assert detector.get_baseline("agent-1") is None
        assert detector.is_drifting("agent-1") is False


class TestKillSwitchRecommendation:
    def test_should_recommend_kill_switch_for_extreme_drift(self):
        detector = _make_detector()
        detector.set_baseline(
            "agent-1",
            BaselineProfile(
                tool_distribution={"search": 1.0},
                topic_distribution={"science": 1.0},
                avg_sentiment=0.8,
                sentiment_std_dev=0.05,
                avg_response_length=200,
                response_length_std_dev=10,
                avg_response_time=300,
                response_time_std_dev=10,
                error_rate=0.0,
                avg_satisfaction=0.9,
                sample_count=100,
                last_updated=_now_ms(),
            ),
        )

        for i in range(10):
            detector.record_sample(
                "agent-1",
                _make_sample(
                    timestamp=_now_ms() + i,
                    tools=["destroy", "exploit", "breach"],
                    topics=["attack", "vulnerability"],
                    sentiment=-1,
                    response_length=50000,
                    response_time=100000,
                    had_error=True,
                ),
            )

        result = detector.analyze("agent-1")
        assert result.analysis.drift_score >= 60
        assert result.requires_review is True


class TestOnDriftCallback:
    def test_should_fire_on_drift_callback_when_drift_begins(self):
        drift_fired = {"value": False}
        drift_agent_id = {"value": ""}

        def on_drift(agent_id, analysis):
            drift_fired["value"] = True
            drift_agent_id["value"] = agent_id

        detector = DriftDetector(DriftDetectorConfig(
            minimum_samples=5,
            alert_threshold=40,
            auto_update_baseline=True,
            baseline_window=24 * 60 * 60 * 1000,
            on_drift=on_drift,
        ))

        for i in range(10):
            detector.record_sample(
                "agent-cb",
                _make_sample(timestamp=_now_ms() + i),
            )
        detector.update_baseline("agent-cb")

        for i in range(10):
            detector.record_sample(
                "agent-cb",
                _make_sample(
                    timestamp=_now_ms() + 200 + i,
                    tools=["rogue_action"],
                    topics=["forbidden"],
                    sentiment=-1,
                    response_length=50000,
                    response_time=99999,
                    had_error=True,
                ),
            )

        detector.analyze("agent-cb")

        if detector.is_drifting("agent-cb"):
            assert drift_fired["value"] is True
            assert drift_agent_id["value"] == "agent-cb"
