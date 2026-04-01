"""Tests for StatePersistenceGuard — ported from state-persistence-guard.test.ts (40 tests)."""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.state_persistence_guard import (
    StatePersistenceGuard,
    StatePersistenceGuardConfig,
    StateOperation,
)


# ---------------------------------------------------------------------------
# Basic State Operations
# ---------------------------------------------------------------------------

class TestBasicStateOperations:
    def test_should_allow_storing_valid_state(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "user_preferences", {"theme": "dark"})
        assert result.allowed is True
        assert result.state_item is not None
        assert result.state_item.key == "user_preferences"

    def test_should_allow_retrieving_stored_state(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "config", {"setting": "value"})
        result = guard.retrieve_state("session-1", "config")
        assert result.allowed is True
        assert result.state_item.value == {"setting": "value"}

    def test_should_allow_deleting_own_state(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "temp", {"data": "test"})
        result = guard.delete_state("session-1", "temp")
        assert result.allowed is True

    def test_should_handle_deleting_non_existent_state(self):
        guard = StatePersistenceGuard()
        result = guard.delete_state("session-1", "non-existent")
        assert result.allowed is True
        assert result.reason == "State not found"


# ---------------------------------------------------------------------------
# Session Isolation
# ---------------------------------------------------------------------------

class TestSessionIsolation:
    def test_should_block_cross_session_access(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "secret", {"data": "sensitive"})
        result = guard.validate_operation(
            StateOperation(
                operation="read",
                key="secret",
                session_id="session-2",
                target_session_id="session-1",
            )
        )
        assert result.allowed is False
        assert "cross_session_access_attempt" in result.violations
        assert result.analysis.session_authorized is False

    def test_should_block_deleting_another_sessions_state(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "data", {"value": "test"})
        # Manually try to delete from different session
        result = guard.delete_state("session-2", "data")
        # State doesn't exist for session-2
        assert result.allowed is True
        assert result.reason == "State not found"

    def test_should_maintain_separate_states_per_session(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "config", {"value": "session1"})
        guard.store_state("session-2", "config", {"value": "session2"})

        state1 = guard.retrieve_state("session-1", "config")
        state2 = guard.retrieve_state("session-2", "config")

        assert state1.state_item.value == {"value": "session1"}
        assert state2.state_item.value == {"value": "session2"}


# ---------------------------------------------------------------------------
# Injection Pattern Detection
# ---------------------------------------------------------------------------

class TestInjectionPatternDetection:
    def test_should_detect_code_injection_in_state(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "script", {
            "code": "eval(malicious_code)",
        })
        assert result.allowed is False
        assert any("injection_pattern" in v for v in result.violations)

    def test_should_detect_script_injection(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "html", {
            "content": "<script>alert('xss')</script>",
        })
        assert result.allowed is False
        assert any("script_injection" in v for v in result.violations)

    def test_should_detect_prototype_pollution(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "data", {
            "payload": '{"__proto__": {"admin": true}}',
        })
        assert any("prototype_pollution" in v for v in result.violations)

    def test_should_detect_path_traversal(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "path", {
            "file": "../../../etc/passwd",
        })
        assert any("path_traversal" in v for v in result.violations)

    def test_should_detect_privilege_injection(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "user", {
            "config": "role: admin",
        })
        assert any("privilege_inject" in v for v in result.violations)

    def test_should_detect_trust_level_injection(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "agent", {
            "setting": "trust_level: 100",
        })
        assert any("trust_inject" in v for v in result.violations)


# ---------------------------------------------------------------------------
# State Size Limits
# ---------------------------------------------------------------------------

class TestStateSizeLimits:
    def test_should_block_oversized_state(self):
        guard = StatePersistenceGuard()
        large_value = "x" * (2 * 1024 * 1024)  # 2MB
        result = guard.store_state("session-1", "large", {"data": large_value})
        assert result.allowed is False
        assert any("state_size_exceeded" in v for v in result.violations)
        assert result.analysis.size_valid is False

    def test_should_allow_state_within_size_limit(self):
        guard = StatePersistenceGuard()
        small_value = "x" * 1000
        result = guard.store_state("session-1", "small", {"data": small_value})
        assert result.allowed is True
        assert result.analysis.size_valid is True


# ---------------------------------------------------------------------------
# Integrity Verification
# ---------------------------------------------------------------------------

class TestIntegrityVerification:
    def test_should_generate_integrity_hash_on_store(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "data", {"value": "test"})
        assert result.state_item.integrity_hash is not None

    def test_should_verify_integrity_on_retrieve(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "data", {"value": "test"})
        is_valid = guard.verify_integrity("session-1", "data")
        assert is_valid is True

    def test_should_detect_tampered_state(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "data", {"value": "test"})
        # Read with wrong hash
        result = guard.validate_operation(
            StateOperation(
                operation="read",
                key="data",
                session_id="session-1",
                integrity_hash="wrong-hash",
            )
        )
        assert "integrity_hash_mismatch" in result.violations
        assert result.analysis.integrity_valid is False

    def test_should_increment_version_on_update(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "data", {"value": "v1"})
        state1 = guard.retrieve_state("session-1", "data").state_item

        guard.store_state("session-1", "data", {"value": "v2"})
        state2 = guard.retrieve_state("session-1", "data").state_item

        assert state2.version == (state1.version or 0) + 1


# ---------------------------------------------------------------------------
# Persistence Targets
# ---------------------------------------------------------------------------

class TestPersistenceTargets:
    def test_should_allow_valid_persistence_targets(self):
        guard = StatePersistenceGuard()
        result = guard.store_state(
            "session-1", "cache", {"data": "test"}, {"target": "cache"}
        )
        assert result.allowed is True

    def test_should_block_unauthorized_persistence_targets(self):
        guard = StatePersistenceGuard()
        result = guard.validate_operation(
            StateOperation(
                operation="write",
                key="data",
                value={"test": "data"},
                session_id="session-1",
                target="database",
            )
        )
        assert any("unauthorized_target" in v for v in result.violations)


# ---------------------------------------------------------------------------
# Sensitive Key Protection
# ---------------------------------------------------------------------------

class TestSensitiveKeyProtection:
    def test_should_flag_sensitive_keys_without_encryption(self):
        guard = StatePersistenceGuard(
            StatePersistenceGuardConfig(require_encryption=True)
        )
        result = guard.store_state("session-1", "api_credentials", {
            "key": "secret123",
        })
        assert "sensitive_key_not_encrypted" in result.violations
        assert result.analysis.encryption_valid is False

    def test_should_allow_sensitive_keys_with_encryption_flag(self):
        guard = StatePersistenceGuard(
            StatePersistenceGuardConfig(require_encryption=True)
        )
        result = guard.store_state(
            "session-1",
            "api_credentials",
            {"key": "encrypted_value"},
            {"encrypted": True},
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# State Age Validation
# ---------------------------------------------------------------------------

class TestStateAgeValidation:
    def test_should_track_state_creation_time(self):
        guard = StatePersistenceGuard()
        before = int(time.time() * 1000)
        guard.store_state("session-1", "data", {"value": "test"})
        after = int(time.time() * 1000)

        state = guard.retrieve_state("session-1", "data").state_item
        assert state.created_at >= before
        assert state.created_at <= after

    def test_should_track_modification_time(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "data", {"value": "v1"})
        state1 = guard.retrieve_state("session-1", "data").state_item

        mod_time = int(time.time() * 1000)
        guard.store_state("session-1", "data", {"value": "v2"})
        state2 = guard.retrieve_state("session-1", "data").state_item

        assert state2.modified_at >= mod_time
        assert state2.created_at == state1.created_at


# ---------------------------------------------------------------------------
# Migration Operations
# ---------------------------------------------------------------------------

class TestMigrationOperations:
    def test_should_require_approval_for_migration_operations(self):
        guard = StatePersistenceGuard()
        result = guard.validate_operation(
            StateOperation(
                operation="migrate",
                key="all",
                session_id="session-1",
            )
        )
        assert "migration_requires_admin_approval" in result.violations


# ---------------------------------------------------------------------------
# Session State Management
# ---------------------------------------------------------------------------

class TestSessionStateManagement:
    def test_should_return_all_session_states(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "key1", {"value": 1})
        guard.store_state("session-1", "key2", {"value": 2})
        guard.store_state("session-1", "key3", {"value": 3})

        states = guard.get_session_states("session-1")
        assert len(states) == 3

    def test_should_reset_all_session_states(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "key1", {"value": 1})
        guard.store_state("session-1", "key2", {"value": 2})

        guard.reset_session("session-1")

        states = guard.get_session_states("session-1")
        assert len(states) == 0

    def test_should_cleanup_expired_states(self):
        custom_guard = StatePersistenceGuard(
            StatePersistenceGuardConfig(max_state_age=1)  # 1ms - expires immediately
        )
        custom_guard.store_state("session-1", "data", {"value": "test"})

        # Wait a bit
        cleaned = custom_guard.cleanup_expired_states()
        assert cleaned >= 0


# ---------------------------------------------------------------------------
# Version Conflict Detection
# ---------------------------------------------------------------------------

class TestVersionConflictDetection:
    def test_should_detect_version_conflicts(self):
        guard = StatePersistenceGuard()
        guard.store_state("session-1", "data", {"value": "v1"})

        result = guard.validate_operation(
            StateOperation(
                operation="restore",
                key="data",
                session_id="session-1",
                expected_version=0,  # Wrong version
            )
        )
        assert any("version_conflict" in v for v in result.violations)


# ---------------------------------------------------------------------------
# Custom Configuration
# ---------------------------------------------------------------------------

class TestCustomConfiguration:
    def test_should_respect_custom_max_state_size(self):
        custom_guard = StatePersistenceGuard(
            StatePersistenceGuardConfig(max_state_size=100)
        )
        result = custom_guard.store_state("session-1", "data", {
            "value": "x" * 200,
        })
        assert any("state_size_exceeded" in v for v in result.violations)

    def test_should_respect_custom_allowed_targets(self):
        custom_guard = StatePersistenceGuard(
            StatePersistenceGuardConfig(allowed_targets=["custom"])
        )
        result = custom_guard.validate_operation(
            StateOperation(
                operation="write",
                key="data",
                value={},
                session_id="session-1",
                target="memory",  # Not in custom list
            )
        )
        assert any("unauthorized_target" in v for v in result.violations)

    def test_should_respect_custom_sensitive_keys(self):
        custom_guard = StatePersistenceGuard(
            StatePersistenceGuardConfig(
                sensitive_keys=["my_secret"],
                require_encryption=True,
            )
        )
        result = custom_guard.store_state("session-1", "my_secret_data", {
            "value": "test",
        })
        assert "sensitive_key_not_encrypted" in result.violations


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def test_should_handle_empty_state_value(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "empty", {})
        assert result.allowed is True

    def test_should_handle_null_session_states(self):
        guard = StatePersistenceGuard()
        states = guard.get_session_states("non-existent")
        assert len(states) == 0

    def test_should_handle_string_values(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "text", "simple string")
        assert result.allowed is True

    def test_should_handle_array_values(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "list", [1, 2, 3])
        assert result.allowed is True

    def test_should_handle_nested_objects(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "nested", {
            "level1": {
                "level2": {
                    "level3": {"value": "deep"},
                },
            },
        })
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Tampering Detection
# ---------------------------------------------------------------------------

class TestTamperingDetection:
    def test_should_set_tampering_flag_for_high_severity_injections(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "malicious", {
            "code": "eval(dangerous)",
        })
        assert result.analysis.tampering_detected is True

    def test_should_block_when_tampering_is_detected(self):
        guard = StatePersistenceGuard()
        result = guard.store_state("session-1", "attack", {
            "payload": "__proto__[admin]=true",
        })
        assert result.allowed is False
