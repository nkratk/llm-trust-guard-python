"""Tests for SessionIntegrityGuard — ported from session-integrity-guard.test.ts (37 tests)."""

import sys
import os
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.session_integrity_guard import (
    SessionIntegrityGuard,
    SessionIntegrityGuardConfig,
)


# ---------------------------------------------------------------------------
# Session Creation
# ---------------------------------------------------------------------------

class TestCreateSession:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_create_a_session_with_valid_inputs(self):
        result = self.guard.create_session("s1", "user1", ["read", "write"])
        assert result.allowed is True
        assert result.violations == []
        assert result.session_age == 0

    def test_should_create_a_session_with_metadata(self):
        result = self.guard.create_session("s1", "user1", ["read"], {"source": "api"})
        assert result.allowed is True

    def test_should_reject_empty_permissions(self):
        result = self.guard.create_session("s1", "user1", [])
        assert result.allowed is False
        assert "empty_permissions" in result.violations

    def test_should_reject_duplicate_session_ids(self):
        self.guard.create_session("s1", "user1", ["read"])
        result = self.guard.create_session("s1", "user2", ["write"])
        assert result.allowed is False
        assert "duplicate_session_id" in result.violations
        assert "already exists" in result.reason

    def test_should_allow_different_session_ids_for_same_user(self):
        r1 = self.guard.create_session("s1", "user1", ["read"])
        r2 = self.guard.create_session("s2", "user1", ["write"])
        assert r1.allowed is True
        assert r2.allowed is True


# ---------------------------------------------------------------------------
# Concurrent Session Limits
# ---------------------------------------------------------------------------

class TestConcurrentSessionLimits:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_enforce_default_concurrent_session_limit_of_5(self):
        for i in range(1, 6):
            r = self.guard.create_session(f"s{i}", "user1", ["read"])
            assert r.allowed is True
        result = self.guard.create_session("s6", "user1", ["read"])
        assert result.allowed is False
        assert "concurrent_session_limit_exceeded" in result.violations

    def test_should_respect_custom_concurrent_session_limit(self):
        self.guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(max_concurrent_sessions=2))
        self.guard.create_session("s1", "user1", ["read"])
        self.guard.create_session("s2", "user1", ["read"])
        result = self.guard.create_session("s3", "user1", ["read"])
        assert result.allowed is False
        assert "concurrent_session_limit_exceeded" in result.violations

    def test_should_not_count_ended_sessions_against_the_limit(self):
        self.guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(max_concurrent_sessions=2))
        self.guard.create_session("s1", "user1", ["read"])
        self.guard.create_session("s2", "user1", ["read"])
        self.guard.end_session("s1")
        result = self.guard.create_session("s3", "user1", ["read"])
        assert result.allowed is True

    def test_should_track_limits_independently_per_user(self):
        self.guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(max_concurrent_sessions=1))
        r1 = self.guard.create_session("s1", "user1", ["read"])
        r2 = self.guard.create_session("s2", "user2", ["read"])
        assert r1.allowed is True
        assert r2.allowed is True


# ---------------------------------------------------------------------------
# Permission Consistency
# ---------------------------------------------------------------------------

class TestPermissionConsistency:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_block_requests_for_permissions_not_in_original_scope(self):
        self.guard.create_session("s1", "user1", ["read"])
        result = self.guard.validate_request("s1", "action", ["read", "admin"])
        assert result.allowed is False
        assert "scope_violation" in result.violations
        assert "+admin" in result.permission_delta

    def test_should_allow_requests_within_granted_permissions(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        result = self.guard.validate_request("s1", "action", ["read"])
        assert result.allowed is True
        assert result.violations == []

    def test_should_block_re_escalation_of_degraded_permissions(self):
        self.guard.create_session("s1", "user1", ["read", "write", "delete"])
        self.guard.degrade_permissions("s1", ["write"])
        result = self.guard.validate_request("s1", "action", ["write"])
        assert result.allowed is False
        assert "authority_re_escalation" in result.violations

    def test_should_allow_escalation_when_allow_permission_escalation_is_true(self):
        self.guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(allow_permission_escalation=True))
        self.guard.create_session("s1", "user1", ["read"])
        result = self.guard.validate_request("s1", "action", ["read", "admin"])
        assert "scope_violation" in result.violations


# ---------------------------------------------------------------------------
# Session Timeout
# ---------------------------------------------------------------------------

class TestSessionTimeout:
    def test_should_reject_requests_after_absolute_timeout(self):
        guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(max_session_duration=100))
        guard.create_session("s1", "user1", ["read", "write"])

        # Mock time.time to simulate 200ms later
        import time as _time
        original_time = _time.time()
        with patch("llm_trust_guard.guards.session_integrity_guard.time.time", return_value=original_time + 0.2):
            result = guard.validate_request("s1", "action")
        assert result.allowed is False
        assert "absolute_timeout_exceeded" in result.violations

    def test_should_reject_requests_after_inactivity_timeout(self):
        guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(inactivity_timeout=100))
        guard.create_session("s1", "user1", ["read", "write"])

        import time as _time
        original_time = _time.time()
        with patch("llm_trust_guard.guards.session_integrity_guard.time.time", return_value=original_time + 0.2):
            result = guard.validate_request("s1", "action")
        assert result.allowed is False
        assert "inactivity_timeout_exceeded" in result.violations

    def test_should_allow_requests_within_timeout_window(self):
        guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(
            max_session_duration=10_000,
            inactivity_timeout=10_000,
        ))
        guard.create_session("s1", "user1", ["read", "write"])
        result = guard.validate_request("s1", "action")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Request Sequence Validation
# ---------------------------------------------------------------------------

class TestRequestSequenceValidation:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_accept_requests_in_correct_sequence_order(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        r1 = self.guard.validate_request("s1", "action", None, None, 1)
        r2 = self.guard.validate_request("s1", "action", None, None, 2)
        assert r1.allowed is True
        assert r2.allowed is True

    def test_should_reject_out_of_order_sequence_numbers(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        self.guard.validate_request("s1", "action", None, None, 1)
        result = self.guard.validate_request("s1", "action", None, None, 5)
        assert result.allowed is False
        assert "sequence_violation" in result.violations

    def test_should_detect_replay_attacks_via_duplicate_nonce(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        r1 = self.guard.validate_request("s1", "action", None, "nonce-abc")
        assert r1.allowed is True
        r2 = self.guard.validate_request("s1", "action", None, "nonce-abc")
        assert r2.allowed is False
        assert "replay_detected" in r2.violations

    def test_should_allow_different_nonces(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        r1 = self.guard.validate_request("s1", "action", None, "nonce-1")
        r2 = self.guard.validate_request("s1", "action", None, "nonce-2")
        assert r1.allowed is True
        assert r2.allowed is True

    def test_should_skip_sequence_validation_when_disabled(self):
        self.guard = SessionIntegrityGuard(SessionIntegrityGuardConfig(enforce_sequence_validation=False))
        self.guard.create_session("s1", "user1", ["read", "write"])
        self.guard.validate_request("s1", "action", None, None, 1)
        # Skip to sequence 10 — should be allowed
        result = self.guard.validate_request("s1", "action", None, None, 10)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Permission Degradation
# ---------------------------------------------------------------------------

class TestDegradePermissions:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_remove_specified_permissions(self):
        self.guard.create_session("s1", "user1", ["read", "write", "delete"])
        result = self.guard.degrade_permissions("s1", ["write", "delete"])
        assert result.allowed is True
        assert "-write" in result.permission_delta
        assert "-delete" in result.permission_delta

    def test_should_silently_ignore_permissions_not_currently_held(self):
        self.guard.create_session("s1", "user1", ["read"])
        result = self.guard.degrade_permissions("s1", ["admin"])
        assert result.allowed is True
        assert result.permission_delta == []

    def test_should_fail_on_non_existent_session(self):
        result = self.guard.degrade_permissions("nonexistent", ["read"])
        assert result.allowed is False
        assert "session_not_found" in result.violations


# ---------------------------------------------------------------------------
# endSession
# ---------------------------------------------------------------------------

class TestEndSession:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_terminate_an_active_session(self):
        self.guard.create_session("s1", "user1", ["read"])
        result = self.guard.end_session("s1")
        assert result.allowed is True
        assert result.session_age is not None

    def test_should_reject_requests_on_ended_sessions(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        self.guard.end_session("s1")
        result = self.guard.validate_request("s1", "action")
        assert result.allowed is False
        assert "session_inactive" in result.violations

    def test_should_return_error_for_non_existent_session(self):
        result = self.guard.end_session("nonexistent")
        assert result.allowed is False
        assert "session_not_found" in result.violations


# ---------------------------------------------------------------------------
# getActiveSessions
# ---------------------------------------------------------------------------

class TestGetActiveSessions:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_return_active_sessions_for_a_user(self):
        self.guard.create_session("s1", "user1", ["read"])
        self.guard.create_session("s2", "user1", ["write"])
        sessions = self.guard.get_active_sessions("user1")
        assert len(sessions) == 2
        assert "s1" in sessions
        assert "s2" in sessions

    def test_should_not_include_ended_sessions(self):
        self.guard.create_session("s1", "user1", ["read"])
        self.guard.create_session("s2", "user1", ["write"])
        self.guard.end_session("s1")
        sessions = self.guard.get_active_sessions("user1")
        assert len(sessions) == 1
        assert "s2" in sessions

    def test_should_return_empty_list_for_unknown_user(self):
        sessions = self.guard.get_active_sessions("nobody")
        assert sessions == []


# ---------------------------------------------------------------------------
# Abrupt State Change Detection
# ---------------------------------------------------------------------------

class TestAbruptStateChangeDetection:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_block_destructive_actions_on_read_only_sessions(self):
        self.guard.create_session("s1", "user1", ["read"])
        result = self.guard.validate_request("s1", "delete_records")
        assert result.allowed is False
        assert "abrupt_state_change" in result.violations

    def test_should_block_admin_actions_without_admin_permissions(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        result = self.guard.validate_request("s1", "admin_configure")
        assert result.allowed is False
        assert "abrupt_state_change" in result.violations

    def test_should_allow_destructive_actions_when_delete_permission_is_granted(self):
        self.guard.create_session("s1", "user1", ["read", "write", "delete"])
        result = self.guard.validate_request("s1", "delete_records")
        assert result.allowed is True

    def test_should_allow_admin_actions_with_admin_permission(self):
        self.guard.create_session("s1", "user1", ["read", "admin"])
        result = self.guard.validate_request("s1", "admin_configure")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def setup_method(self):
        self.guard = SessionIntegrityGuard()

    def test_should_reject_validate_request_for_non_existent_session(self):
        result = self.guard.validate_request("nonexistent", "action")
        assert result.allowed is False
        assert "session_not_found" in result.violations

    def test_should_handle_validate_request_with_no_optional_parameters(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        result = self.guard.validate_request("s1", "action")
        assert result.allowed is True

    def test_should_auto_increment_sequence_when_no_explicit_sequence(self):
        self.guard.create_session("s1", "user1", ["read", "write"])
        self.guard.validate_request("s1", "action")
        self.guard.validate_request("s1", "action")
        # After two successful requests with auto-increment, next explicit should be 3
        result = self.guard.validate_request("s1", "action", None, None, 3)
        assert result.allowed is True
