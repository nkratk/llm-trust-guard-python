"""
Tests for ToolChainValidator.
Ported from tool-chain-validator.test.ts (11 tests).
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.tool_chain_validator import (
    ToolChainValidator,
    ToolChainValidatorConfig,
    ForbiddenSequence,
)

SESSION_ID = "test-session-1"


def _make_validator(**overrides):
    defaults = dict(
        forbidden_sequences=[
            ForbiddenSequence(
                name="read_then_execute",
                sequence=["read_file", "execute_code"],
                reason="Reading then executing is dangerous",
                severity="block",
            ),
            ForbiddenSequence(
                name="credentials_then_http",
                sequence=["get_api_key", "http_request"],
                reason="Credential theft pattern",
                severity="block",
            ),
        ],
        tool_cooldowns={"delete_record": 5000},
        max_tools_per_request=3,
        max_sensitive_tools_per_session=2,
        sensitive_tools=["delete", "execute", "admin"],
        # Disable v2 checks to keep tests deterministic
        enable_time_anomaly_detection=False,
        enable_loop_detection=False,
        enable_state_tracking=False,
        enable_autonomy_detection=False,
        enable_resource_tracking=False,
        enable_impact_scoring=False,
    )
    defaults.update(overrides)
    return ToolChainValidator(ToolChainValidatorConfig(**defaults))


# ── Forbidden Sequence Blocking ───────────────────────────────────────


class TestForbiddenSequenceBlocking:
    def test_should_block_read_file_followed_by_execute_code(self):
        validator = _make_validator()
        first = validator.validate(SESSION_ID, "read_file")
        assert first.allowed is True

        second = validator.validate(SESSION_ID, "execute_code")
        assert second.allowed is False
        assert "read_then_execute" in second.chain_analysis.forbidden_sequences_detected
        assert any("FORBIDDEN_SEQUENCE" in v for v in second.violations)

    def test_should_block_get_api_key_followed_by_http_request(self):
        validator = _make_validator()
        validator.validate(SESSION_ID, "get_api_key")
        result = validator.validate(SESSION_ID, "http_request")
        assert result.allowed is False
        assert "credentials_then_http" in result.chain_analysis.forbidden_sequences_detected

    def test_should_allow_non_forbidden_sequences(self):
        validator = _make_validator()
        validator.validate(SESSION_ID, "get_info")
        result = validator.validate(SESSION_ID, "update_profile")
        assert result.allowed is True
        assert len(result.chain_analysis.forbidden_sequences_detected) == 0


# ── Sensitive Tool Count Limit ────────────────────────────────────────


class TestSensitiveToolCountLimit:
    def test_should_block_after_exceeding_max_sensitive_tools_per_session(self):
        validator = _make_validator()
        r1 = validator.validate(SESSION_ID, "delete_record")
        assert r1.allowed is True

        r2 = validator.validate(SESSION_ID, "delete_user")
        assert r2.allowed is True

        # Third sensitive tool should be blocked
        r3 = validator.validate(SESSION_ID, "admin_panel")
        assert r3.allowed is False
        assert "MAX_SENSITIVE_TOOLS_EXCEEDED" in r3.violations


# ── Batch Validation ──────────────────────────────────────────────────


class TestBatchValidation:
    def test_should_block_batch_exceeding_max_tools_per_request(self):
        validator = _make_validator()
        result = validator.validate_batch(SESSION_ID, [
            "tool_a", "tool_b", "tool_c", "tool_d",
        ])
        assert result.allowed is False
        assert "MAX_TOOLS_PER_REQUEST_EXCEEDED" in result.violations

    def test_should_allow_batch_within_limits(self):
        validator = _make_validator()
        result = validator.validate_batch(SESSION_ID, ["get_info", "get_status"])
        assert result.allowed is True

    def test_should_detect_forbidden_sequences_within_a_batch(self):
        validator = _make_validator()
        result = validator.validate_batch(SESSION_ID, ["read_file", "execute_code"])
        assert result.allowed is False
        assert len(result.chain_analysis.forbidden_sequences_detected) > 0


# ── Cooldown Enforcement ──────────────────────────────────────────────


class TestCooldownEnforcement:
    def test_should_block_tool_call_within_cooldown_period(self):
        validator = _make_validator()
        first = validator.validate(SESSION_ID, "delete_record")
        assert first.allowed is True

        # Immediately call again - should be blocked by cooldown (5000ms)
        second = validator.validate(SESSION_ID, "delete_record")
        assert second.allowed is False
        assert any("COOLDOWN_VIOLATION" in v for v in second.violations)
        assert len(second.chain_analysis.cooldown_violations) > 0


# ── Session Management ────────────────────────────────────────────────


class TestSessionManagement:
    def test_should_track_tool_history_per_session(self):
        validator = _make_validator()
        validator.validate(SESSION_ID, "tool_a")
        validator.validate(SESSION_ID, "tool_b")
        history = validator.get_tool_history(SESSION_ID)
        assert "tool_a" in history
        assert "tool_b" in history

    def test_should_reset_session_clearing_all_history(self):
        validator = _make_validator()
        validator.validate(SESSION_ID, "tool_a")
        validator.reset_session(SESSION_ID)
        history = validator.get_tool_history(SESSION_ID)
        assert len(history) == 0


# ── False Positive - Legitimate Tool Chain ────────────────────────────


class TestFalsePositiveLegitimateToolChain:
    def test_should_allow_a_normal_sequence_of_safe_tools(self):
        validator = _make_validator()
        r1 = validator.validate(SESSION_ID, "get_user_profile")
        assert r1.allowed is True

        r2 = validator.validate(SESSION_ID, "update_preferences")
        assert r2.allowed is True

        r3 = validator.validate(SESSION_ID, "get_notifications")
        assert r3.allowed is True

        assert len(r3.violations) == 0
        assert len(r3.warnings) == 0
