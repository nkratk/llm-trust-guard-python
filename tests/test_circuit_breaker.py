"""
Tests for CircuitBreaker guard.
Ported from circuit-breaker.test.ts (14 tests).
"""

import sys
import os
import time
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerConfig,
)

CIRCUIT_ID = "test-circuit"


def _make_breaker(**overrides):
    defaults = dict(
        failure_threshold=50,
        minimum_requests=3,
        max_consecutive_failures=3,
        recovery_timeout=1000,  # 1 second for fast tests
        success_threshold=2,
        auto_recover=True,
        window_size=60_000,
    )
    defaults.update(overrides)
    return CircuitBreaker(CircuitBreakerConfig(**defaults))


# ── Circuit Opens After Consecutive Failures ──────────────────────────


class TestCircuitOpensAfterConsecutiveFailures:
    def test_should_open_circuit_after_max_consecutive_failures(self):
        breaker = _make_breaker()
        breaker.record_failure(CIRCUIT_ID, "error 1")
        breaker.record_failure(CIRCUIT_ID, "error 2")
        breaker.record_failure(CIRCUIT_ID, "error 3")

        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is False
        assert result.state == "open"
        assert "open" in result.reason.lower()
        assert result.fallback_recommended is True

    def test_should_report_retry_after_when_circuit_is_open(self):
        breaker = _make_breaker()
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")

        result = breaker.check(CIRCUIT_ID)
        assert result.retry_after is not None
        assert result.retry_after > 0


# ── Closed State Allows Requests ──────────────────────────────────────


class TestClosedStateAllowsRequests:
    def test_should_allow_requests_when_circuit_is_closed(self):
        breaker = _make_breaker()
        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is True
        assert result.state == "closed"
        assert result.fallback_recommended is False

    def test_should_stay_closed_with_mixed_success_and_few_failures(self):
        breaker = _make_breaker()
        breaker.record_success(CIRCUIT_ID)
        breaker.record_success(CIRCUIT_ID)
        breaker.record_failure(CIRCUIT_ID, "occasional error")
        breaker.record_success(CIRCUIT_ID)

        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is True
        assert result.state == "closed"


# ── Half-Open State ───────────────────────────────────────────────────


class TestHalfOpenState:
    def test_should_transition_to_half_open_after_recovery_timeout(self):
        breaker = _make_breaker()
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")

        assert breaker.get_state(CIRCUIT_ID) == "open"

        # Wait for recovery timeout (1 second)
        time.sleep(1.1)

        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is True
        assert result.state == "half-open"
        assert result.fallback_recommended is True

    def test_should_close_circuit_after_enough_successes_in_half_open(self):
        breaker = _make_breaker()
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")

        time.sleep(1.1)
        breaker.check(CIRCUIT_ID)  # triggers transition to half-open

        # Record successes to meet success_threshold (2)
        breaker.record_success(CIRCUIT_ID)
        breaker.record_success(CIRCUIT_ID)

        assert breaker.get_state(CIRCUIT_ID) == "closed"

        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is True
        assert result.state == "closed"

    def test_should_reopen_circuit_on_failure_in_half_open(self):
        breaker = _make_breaker()
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")

        time.sleep(1.1)
        breaker.check(CIRCUIT_ID)  # half-open

        # Fail again in half-open -> should re-open
        breaker.record_failure(CIRCUIT_ID, "still failing")

        state = breaker.get_state(CIRCUIT_ID)
        assert state == "open"


# ── Force Open / Force Close ──────────────────────────────────────────


class TestForceOpenForceClose:
    def test_should_force_open_a_closed_circuit(self):
        breaker = _make_breaker()
        assert breaker.get_state(CIRCUIT_ID) == "closed"

        breaker.force_open(CIRCUIT_ID)
        assert breaker.get_state(CIRCUIT_ID) == "open"

        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is False

    def test_should_force_close_an_open_circuit(self):
        breaker = _make_breaker()
        breaker.force_open(CIRCUIT_ID)
        assert breaker.get_state(CIRCUIT_ID) == "open"

        breaker.force_close(CIRCUIT_ID)
        assert breaker.get_state(CIRCUIT_ID) == "closed"

        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is True


# ── Stats Tracking ────────────────────────────────────────────────────


class TestStatsTracking:
    def test_should_track_request_stats_accurately(self):
        breaker = _make_breaker()
        breaker.record_success(CIRCUIT_ID)
        breaker.record_success(CIRCUIT_ID)
        breaker.record_failure(CIRCUIT_ID, "err")

        stats = breaker.get_stats(CIRCUIT_ID)
        assert stats is not None
        assert stats.total_requests == 3
        assert stats.successful_requests == 2
        assert stats.failed_requests == 1
        assert stats.consecutive_failures == 1
        assert stats.consecutive_successes == 0

    def test_should_return_none_stats_for_unknown_circuit(self):
        breaker = _make_breaker()
        stats = breaker.get_stats("nonexistent")
        assert stats is None


# ── Reset ─────────────────────────────────────────────────────────────


class TestReset:
    def test_should_reset_circuit_to_initial_closed_state(self):
        breaker = _make_breaker()
        breaker.force_open(CIRCUIT_ID)
        assert breaker.get_state(CIRCUIT_ID) == "open"

        breaker.reset(CIRCUIT_ID)
        assert breaker.get_state(CIRCUIT_ID) == "closed"
        assert breaker.get_stats(CIRCUIT_ID) is None


# ── Callbacks ─────────────────────────────────────────────────────────


class TestCallbacks:
    def test_should_call_on_open_callback_when_circuit_opens(self):
        on_open = MagicMock()
        breaker = CircuitBreaker(CircuitBreakerConfig(
            max_consecutive_failures=2,
            on_open=on_open,
        ))

        breaker.record_failure(CIRCUIT_ID, "err")
        breaker.record_failure(CIRCUIT_ID, "err")

        on_open.assert_called_once()
        call_args = on_open.call_args
        assert call_args[0][0] == CIRCUIT_ID
        assert call_args[0][1].consecutive_failures == 2


# ── False Positive - Healthy Service ──────────────────────────────────


class TestFalsePositiveHealthyService:
    def test_should_keep_circuit_closed_for_healthy_service(self):
        breaker = _make_breaker()
        for _ in range(10):
            breaker.record_success(CIRCUIT_ID)
        breaker.record_failure(CIRCUIT_ID, "transient")
        breaker.record_success(CIRCUIT_ID)

        result = breaker.check(CIRCUIT_ID)
        assert result.allowed is True
        assert result.state == "closed"

        health = breaker.health_check()
        assert health["healthy"] is True
        assert health["open_circuits"] == 0
