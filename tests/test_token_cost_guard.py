"""Tests for TokenCostGuard - ported from token-cost-guard.test.ts (13 tests)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.token_cost_guard import (
    TokenCostGuard,
    TokenCostGuardConfig,
)


@pytest.fixture
def guard():
    return TokenCostGuard(TokenCostGuardConfig(
        max_tokens_per_session=10000,
        max_tokens_per_user=50000,
        max_cost_per_session=1.0,
        max_cost_per_user=5.0,
        max_tokens_per_request=5000,
        input_token_cost_per_1k=0.003,
        output_token_cost_per_1k=0.015,
        alert_threshold=0.8,
    ))


# ---------------------------------------------------------------------------
# Token Tracking
# ---------------------------------------------------------------------------

class TestTokenTracking:
    def test_should_allow_usage_within_limits(self, guard):
        result = guard.track_usage("s1", "u1", 100, 50)
        assert result.allowed is True
        assert result.usage.request.total_tokens == 150
        assert result.usage.session.total_tokens == 150

    def test_should_accumulate_usage_across_requests(self, guard):
        guard.track_usage("s1", "u1", 1000, 500)
        guard.track_usage("s1", "u1", 1000, 500)
        result = guard.track_usage("s1", "u1", 1000, 500)
        assert result.usage.session.total_tokens == 4500

    def test_should_block_when_session_token_limit_exceeded(self, guard):
        guard.track_usage("s1", "u1", 2000, 2000)  # 4000
        guard.track_usage("s1", "u1", 2000, 2000)  # 8000
        result = guard.track_usage("s1", "u1", 2000, 1000)  # would be 11000 > 10000
        assert result.allowed is False
        assert "SESSION_TOKEN_LIMIT_EXCEEDED" in result.violations

    def test_should_block_when_per_request_limit_exceeded(self, guard):
        result = guard.track_usage("s1", "u1", 3000, 3000)  # 6000 > 5000
        assert result.allowed is False
        assert "REQUEST_TOKEN_LIMIT_EXCEEDED" in result.violations


# ---------------------------------------------------------------------------
# Cost Tracking
# ---------------------------------------------------------------------------

class TestCostTracking:
    def test_should_calculate_cost_correctly(self, guard):
        result = guard.track_usage("s1", "u1", 1000, 1000)
        # 1000/1000 * 0.003 + 1000/1000 * 0.015 = 0.018
        assert result.usage.request.estimated_cost == pytest.approx(0.018, abs=1e-4)

    def test_should_block_when_session_cost_limit_exceeded(self):
        cost_guard = TokenCostGuard(TokenCostGuardConfig(
            max_tokens_per_session=1000000,
            max_cost_per_session=0.05,
            input_token_cost_per_1k=0.003,
            output_token_cost_per_1k=0.015,
        ))
        cost_guard.track_usage("s1", "u1", 1000, 1000)  # 0.018
        cost_guard.track_usage("s1", "u1", 1000, 1000)  # 0.036
        result = cost_guard.track_usage("s1", "u1", 1000, 1000)  # 0.054 > 0.05
        assert result.allowed is False
        assert "SESSION_COST_LIMIT_EXCEEDED" in result.violations


# ---------------------------------------------------------------------------
# User Budget
# ---------------------------------------------------------------------------

class TestUserBudget:
    def test_should_track_across_sessions_for_same_user(self, guard):
        guard.track_usage("s1", "u1", 3000, 2000)
        guard.track_usage("s2", "u1", 3000, 2000)
        result = guard.track_usage("s3", "u1", 1000, 500)
        assert result.usage.user.total_tokens == 11500

    def test_should_block_when_user_token_limit_exceeded(self):
        small_guard = TokenCostGuard(TokenCostGuardConfig(
            max_tokens_per_user=5000,
            max_tokens_per_session=100000,
        ))
        small_guard.track_usage("s1", "u1", 2000, 1000)
        result = small_guard.track_usage("s2", "u1", 2000, 1000)  # 6000 > 5000
        assert result.allowed is False
        assert "USER_TOKEN_LIMIT_EXCEEDED" in result.violations


# ---------------------------------------------------------------------------
# Alert Threshold
# ---------------------------------------------------------------------------

class TestAlertThreshold:
    def test_should_trigger_alert_at_80_percent_usage(self, guard):
        guard.track_usage("s1", "u1", 2000, 2000)  # 4000
        guard.track_usage("s1", "u1", 2000, 2000)  # 8000 of 10000 = 80%
        result = guard.track_usage("s1", "u1", 100, 50)
        assert result.budget.alert is True
        assert "approaching limit" in result.budget.alert_message

    def test_should_not_alert_below_threshold(self, guard):
        result = guard.track_usage("s1", "u1", 100, 50)
        assert result.budget.alert is False


# ---------------------------------------------------------------------------
# Budget Query
# ---------------------------------------------------------------------------

class TestBudgetQuery:
    def test_should_return_remaining_budget(self, guard):
        guard.track_usage("s1", "u1", 2000, 1000)
        budget = guard.get_budget("s1", "u1")
        assert budget.session_remaining_tokens == 7000

    def test_should_return_full_budget_for_unknown_session(self, guard):
        budget = guard.get_budget("unknown", "unknown")
        assert budget.session_remaining_tokens == 10000


# ---------------------------------------------------------------------------
# Reset
# ---------------------------------------------------------------------------

class TestReset:
    def test_should_reset_session_budget(self, guard):
        guard.track_usage("s1", "u1", 5000, 3000)
        guard.reset_session("s1")
        result = guard.track_usage("s1", "u1", 100, 50)
        assert result.usage.session.total_tokens == 150
