"""Tests for ExecutionMonitor guard - ported from execution-monitor.test.ts (12 tests)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.execution_monitor import (
    ExecutionMonitor,
    ExecutionMonitorConfig,
)


@pytest.fixture
def monitor():
    return ExecutionMonitor(ExecutionMonitorConfig(
        max_requests_per_minute=5,
        max_requests_per_hour=100,
        max_concurrent_operations=2,
        operation_costs={"generate_report": 10, "simple_query": 1},
        max_cost_per_minute=20,
        max_cost_per_hour=200,
        track_by_user=True,
        track_by_session=True,
    ))


# ---------------------------------------------------------------------------
# Rate Limit Blocking (Per Minute)
# ---------------------------------------------------------------------------

class TestRateLimitBlockingPerMinute:
    def test_should_allow_requests_within_per_minute_limit(self, monitor):
        for _ in range(5):
            result = monitor.check("simple_query", "user-1", "session-1")
            assert result.allowed is True
            monitor.complete_operation("user-1", "session-1")

    def test_should_block_when_per_minute_rate_limit_exceeded(self, monitor):
        for _ in range(5):
            result = monitor.check("simple_query", "user-1", "session-1")
            assert result.allowed is True
            monitor.complete_operation("user-1", "session-1")

        blocked = monitor.check("simple_query", "user-1", "session-1")
        assert blocked.allowed is False
        assert blocked.throttled is True
        assert "RATE_LIMIT_MINUTE_EXCEEDED" in blocked.violations
        assert blocked.retry_after_ms is not None
        assert blocked.retry_after_ms > 0

    def test_should_track_rate_limits_per_session_independently(self, monitor):
        for _ in range(5):
            monitor.check("simple_query", "user-1", "session-1")
            monitor.complete_operation("user-1", "session-1")

        result = monitor.check("simple_query", "user-1", "session-2")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Cost Tracking
# ---------------------------------------------------------------------------

class TestCostTracking:
    def test_should_track_operation_costs_and_block_when_cost_limit_exceeded(self, monitor):
        r1 = monitor.check("generate_report", "user-1", "session-1")
        assert r1.allowed is True
        assert r1.cost_info.operation_cost == 10
        monitor.complete_operation("user-1", "session-1")

        r2 = monitor.check("generate_report", "user-1", "session-1")
        assert r2.allowed is True
        monitor.complete_operation("user-1", "session-1")

        r3 = monitor.check("generate_report", "user-1", "session-1")
        assert r3.allowed is False
        assert "COST_LIMIT_MINUTE_EXCEEDED" in r3.violations

    def test_should_default_cost_to_1_for_unknown_operations(self, monitor):
        result = monitor.check("unknown_tool", "user-1", "session-1")
        assert result.allowed is True
        assert result.cost_info.operation_cost == 1


# ---------------------------------------------------------------------------
# Concurrent Operation Limit
# ---------------------------------------------------------------------------

class TestConcurrentOperationLimit:
    def test_should_block_when_concurrent_operations_exceed_limit(self, monitor):
        r1 = monitor.check("simple_query", "user-1", "session-1")
        assert r1.allowed is True

        r2 = monitor.check("simple_query", "user-1", "session-1")
        assert r2.allowed is True

        r3 = monitor.check("simple_query", "user-1", "session-1")
        assert r3.allowed is False
        assert "MAX_CONCURRENT_OPERATIONS_EXCEEDED" in r3.violations

    def test_should_allow_new_operations_after_completing_previous_ones(self, monitor):
        monitor.check("simple_query", "user-1", "session-1")
        monitor.check("simple_query", "user-1", "session-1")

        monitor.complete_operation("user-1", "session-1")

        result = monitor.check("simple_query", "user-1", "session-1")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Optimistic-Record-Then-Rollback Pattern
# ---------------------------------------------------------------------------

class TestOptimisticRecordThenRollback:
    def test_should_rollback_recorded_request_when_blocked(self, monitor):
        for _ in range(5):
            monitor.check("simple_query", "user-1", "session-1")
            monitor.complete_operation("user-1", "session-1")

        blocked = monitor.check("simple_query", "user-1", "session-1")
        assert blocked.allowed is False

        status = monitor.get_status("user-1", "session-1")
        assert status["requests_per_minute"] == 5


# ---------------------------------------------------------------------------
# Reset Functionality
# ---------------------------------------------------------------------------

class TestResetFunctionality:
    def test_should_reset_session_limits(self, monitor):
        for _ in range(5):
            monitor.check("simple_query", "user-1", "session-1")
            monitor.complete_operation("user-1", "session-1")

        blocked = monitor.check("simple_query", "user-1", "session-1")
        assert blocked.allowed is False

        monitor.reset("user-1", "session-1")

        result = monitor.check("simple_query", "user-1", "session-1")
        assert result.allowed is True

    def test_should_reset_global_limits_when_no_user_session_specified(self):
        global_monitor = ExecutionMonitor(ExecutionMonitorConfig(
            max_requests_per_minute=2,
            track_by_user=False,
            track_by_session=False,
        ))

        global_monitor.check("tool_a")
        global_monitor.complete_operation()
        global_monitor.check("tool_b")
        global_monitor.complete_operation()

        blocked = global_monitor.check("tool_c")
        assert blocked.allowed is False

        global_monitor.reset()

        allowed = global_monitor.check("tool_d")
        assert allowed.allowed is True


# ---------------------------------------------------------------------------
# Rate Limit Info in Response
# ---------------------------------------------------------------------------

class TestRateLimitInfoInResponse:
    def test_should_include_accurate_rate_limit_info_in_result(self, monitor):
        result = monitor.check("simple_query", "user-1", "session-1")
        assert result.rate_limit_info is not None
        assert result.rate_limit_info.requests_this_minute == 1
        assert result.rate_limit_info.max_per_minute == 5
        assert result.rate_limit_info.max_per_hour == 100


# ---------------------------------------------------------------------------
# False Positive - Normal Usage
# ---------------------------------------------------------------------------

class TestFalsePositiveNormalUsage:
    def test_should_allow_steady_normal_usage_without_blocking(self, monitor):
        for _ in range(3):
            result = monitor.check("simple_query", "user-1", "session-1")
            assert result.allowed is True
            assert result.throttled is False
            monitor.complete_operation("user-1", "session-1")
