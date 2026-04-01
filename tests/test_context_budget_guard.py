"""
Tests for ContextBudgetGuard.
Ported from context-budget-guard.test.ts (9 tests).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.context_budget_guard import (
    ContextBudgetGuard,
    ContextBudgetGuardConfig,
)


def _make_guard(**overrides):
    defaults = dict(
        max_total_tokens=1000,
        system_prompt_reserve=200,
        max_turns_per_session=10,
        max_similar_messages=3,
    )
    defaults.update(overrides)
    return ContextBudgetGuard(ContextBudgetGuardConfig(**defaults))


# ── Budget Tracking ───────────────────────────────────────────────────


class TestBudgetTracking:
    def test_should_allow_content_within_budget(self):
        guard = _make_guard()
        result = guard.track_context("s1", "user_input", "Hello, how are you?")
        assert result.allowed is True
        assert result.budget.used_tokens > 0
        assert result.budget.remaining_tokens > 0

    def test_should_block_when_budget_exceeded(self):
        guard = _make_guard()
        # Effective budget = 1000 - 200 = 800 tokens ~ 2800 chars
        long_content = "a" * 3000
        result = guard.track_context("s1", "user_input", long_content)
        assert result.allowed is False
        assert "CONTEXT_BUDGET_EXCEEDED" in result.violations

    def test_should_track_across_multiple_sources(self):
        guard = _make_guard()
        guard.track_context("s1", "system_prompt", "You are a helpful assistant.")
        guard.track_context("s1", "user_input", "What is the weather?")
        budget = guard.get_session_budget("s1")
        assert budget is not None
        assert "system_prompt" in budget.sources
        assert "user_input" in budget.sources

    def test_should_track_cumulative_usage(self):
        guard = _make_guard()
        for i in range(5):
            guard.track_context("s1", "user_input", f"Message {i} with some content padding here.")
        budget = guard.get_session_budget("s1")
        assert budget.turn_count == 5


# ── Turn Limits ───────────────────────────────────────────────────────


class TestTurnLimits:
    def test_should_block_when_max_turns_exceeded(self):
        guard = _make_guard()
        last_result = None
        for i in range(12):
            last_result = guard.track_context("s1", "user_input", "hi")
        assert last_result is not None
        assert last_result.allowed is False
        assert "MAX_TURNS_EXCEEDED" in last_result.violations


# ── Many-Shot Detection ──────────────────────────────────────────────


class TestManyShotDetection:
    def test_should_detect_repeated_similar_messages(self):
        guard = _make_guard()
        detected = False
        for i in range(6):
            result = guard.track_context("s1", "user_input", f"Tell me about topic number {i}")
            if result.many_shot_detected:
                detected = True
        assert detected is True

    def test_should_not_flag_diverse_messages(self):
        guard = _make_guard()
        messages = [
            "What is the weather today?",
            "Can you help me with my order?",
            "I need to reset my password",
            "Tell me about your return policy",
        ]
        detected = False
        for msg in messages:
            result = guard.track_context("s1", "user_input", msg)
            if result.many_shot_detected:
                detected = True
        assert detected is False


# ── Session Management ────────────────────────────────────────────────


class TestSessionManagement:
    def test_should_track_sessions_independently(self):
        guard = _make_guard()
        guard.track_context("s1", "user_input", "a" * 2500)
        result = guard.track_context("s2", "user_input", "Hello")
        assert result.allowed is True

    def test_should_reset_session_correctly(self):
        guard = _make_guard()
        guard.track_context("s1", "user_input", "Some content")
        guard.reset_session("s1")
        assert guard.get_session_budget("s1") is None
