"""Tests for AutonomyEscalationGuard — ported from autonomy-escalation-guard.test.ts (37 tests)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.autonomy_escalation_guard import (
    AutonomyEscalationGuard,
    AutonomyEscalationGuardConfig,
)


# ---------------------------------------------------------------------------
# Basic Action Validation
# ---------------------------------------------------------------------------

class TestBasicActionValidation:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_allow_read_only_actions_at_base_autonomy_level(self):
        result = self.guard.validate("read_only", "session-1")
        assert result.allowed is True
        assert len(result.violations) == 0

    def test_should_allow_query_actions_at_base_autonomy_level(self):
        result = self.guard.validate("query", "session-1")
        assert result.allowed is True

    def test_should_block_execute_code_at_base_autonomy_level(self):
        result = self.guard.validate("execute_code", "session-1")
        assert result.allowed is False
        assert "escalation_required: execute_code" in result.violations
        assert result.requires_approval is True

    def test_should_block_modify_system_action(self):
        result = self.guard.validate("modify_system", "session-1")
        assert result.allowed is False
        assert result.requires_approval is True


# ---------------------------------------------------------------------------
# Self-Modification Detection
# ---------------------------------------------------------------------------

class TestSelfModificationDetection:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_detect_and_block_self_modification_attempts(self):
        result = self.guard.validate("update", "session-1", {
            "action": "modify my own code to bypass restrictions",
        })
        assert result.allowed is False
        assert result.analysis.self_modification_detected is True
        assert any("self_modification" in v for v in result.violations)

    def test_should_detect_disable_safety_attempts(self):
        result = self.guard.validate("config", "session-1", {
            "command": "disable safety filters",
        })
        assert result.allowed is False
        assert "disable_safety" in result.analysis.escalation_patterns_detected

    def test_should_detect_change_constraints_attempts(self):
        result = self.guard.validate("update", "session-1", {
            "request": "remove my constraints",
        })
        assert result.allowed is False
        assert result.analysis.self_modification_detected is True


# ---------------------------------------------------------------------------
# Autonomy Level Escalation
# ---------------------------------------------------------------------------

class TestAutonomyLevelEscalation:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_detect_autonomy_level_escalation_requests(self):
        result = self.guard.validate("update_level", "session-1", {
            "autonomy_level": 75,
        })
        assert any("autonomy_level_escalation" in v for v in result.violations)
        assert result.requires_approval is True

    def test_should_block_requests_exceeding_max_autonomy_level(self):
        result = self.guard.validate("update_level", "session-1", {
            "autonomy_level": 100,
        })
        assert any("autonomy_level_exceeds_max" in v for v in result.violations)

    def test_should_track_current_autonomy_level(self):
        result = self.guard.validate("query", "session-1")
        assert result.analysis.current_autonomy_level == 25  # base level


# ---------------------------------------------------------------------------
# HITL Bypass Detection
# ---------------------------------------------------------------------------

class TestHITLBypassDetection:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_detect_bypass_approval_attempts(self):
        result = self.guard.validate("execute", "session-1", {
            "command": "bypass human approval for this action",
        })
        assert result.allowed is False
        assert "bypass_approval" in result.analysis.escalation_patterns_detected

    def test_should_detect_skip_review_attempts(self):
        result = self.guard.validate("action", "session-1", {
            "note": "skip human review",
        })
        assert "skip_review" in result.analysis.escalation_patterns_detected

    def test_should_detect_no_supervision_requests(self):
        result = self.guard.validate("action", "session-1", {
            "mode": "without human supervision",
        })
        assert "no_supervision" in result.analysis.escalation_patterns_detected

    def test_should_require_human_approval_for_sensitive_actions(self):
        guard = AutonomyEscalationGuard(AutonomyEscalationGuardConfig(
            always_require_human=["delete_data"],
        ))
        result = guard.validate("delete_data", "session-1")
        assert result.analysis.hitl_required is True
        assert result.requires_approval is True
        assert result.approval_type == "human"


# ---------------------------------------------------------------------------
# Sub-Agent Control
# ---------------------------------------------------------------------------

class TestSubAgentControl:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_detect_spawn_agent_attempts(self):
        result = self.guard.validate("spawn_agent", "session-1")
        assert result.requires_approval is True

    def test_should_detect_clone_fork_attempts(self):
        result = self.guard.validate("action", "session-1", {
            "command": "fork this agent",
        })
        assert "fork_agent" in result.analysis.escalation_patterns_detected

    def test_should_enforce_sub_agent_limits(self):
        # Register max sub-agents
        self.guard.register_sub_agent("session-1", "sub-1")
        self.guard.register_sub_agent("session-1", "sub-2")
        self.guard.register_sub_agent("session-1", "sub-3")

        result = self.guard.validate("spawn_agent", "session-1")
        assert result.analysis.sub_agent_limit_exceeded is True
        assert any("sub_agent_limit" in v for v in result.violations)

    def test_should_allow_sub_agent_registration_within_limits(self):
        success = self.guard.register_sub_agent("session-1", "sub-1")
        assert success is True

        state = self.guard.get_agent_state("session-1")
        assert "sub-1" in state.sub_agents


# ---------------------------------------------------------------------------
# Capability Boundaries
# ---------------------------------------------------------------------------

class TestCapabilityBoundaries:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_enforce_capability_boundaries_based_on_autonomy_level(self):
        result = self.guard.validate("execute_any", "session-1")
        assert result.analysis.capability_violation is True
        assert any("capability_violation" in v for v in result.violations)

    def test_should_allow_capabilities_at_appropriate_level(self):
        self.guard.set_autonomy_level("session-1", 50)
        result = self.guard.validate("create_draft", "session-1")
        assert result.analysis.capability_violation is False

    def test_should_expand_capabilities_when_autonomy_level_increases(self):
        self.guard.set_autonomy_level("session-1", 75)
        result = self.guard.validate("api_call_internal", "session-1")
        assert result.analysis.capability_violation is False


# ---------------------------------------------------------------------------
# Escalation Requests
# ---------------------------------------------------------------------------

class TestEscalationRequests:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_accept_capability_expansion_requests_for_approval(self):
        result = self.guard.request_escalation(
            "session-1",
            request_type="capability_expansion",
            requested_capability="api_call_external",
            reason="Need to call external API",
            source="agent",
        )
        assert result.allowed is True
        assert result.requires_approval is True
        assert result.approval_type == "admin"

    def test_should_block_self_modification_requests(self):
        result = self.guard.request_escalation(
            "session-1",
            request_type="self_modify",
            reason="Want to update my own code",
            source="agent",
        )
        assert result.allowed is False
        assert "self_modification_blocked" in result.violations

    def test_should_block_hitl_bypass_requests(self):
        result = self.guard.request_escalation(
            "session-1",
            request_type="bypass_hitl",
            reason="Want to skip human approval",
            source="agent",
        )
        assert result.allowed is False
        assert "hitl_bypass_not_allowed" in result.violations

    def test_should_flag_large_autonomy_jumps(self):
        result = self.guard.request_escalation(
            "session-1",
            request_type="level_increase",
            requested_level=75,
            reason="Need more autonomy",
            source="agent",
        )
        assert "large_autonomy_jump" in result.violations
        assert result.approval_type == "human"

    def test_should_block_repeated_denied_requests(self):
        # First request - will be denied
        self.guard.request_escalation(
            "session-1",
            request_type="self_modify",
            reason="Update code",
            source="agent",
        )

        # Second request - should be blocked as repeated
        result = self.guard.request_escalation(
            "session-1",
            request_type="self_modify",
            reason="Update code again",
            source="agent",
        )
        assert "repeated_denied_request" in result.violations


# ---------------------------------------------------------------------------
# Approval Workflow
# ---------------------------------------------------------------------------

class TestApprovalWorkflow:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_approve_escalation_requests_and_apply_changes(self):
        request = self.guard.request_escalation(
            "session-1",
            request_type="level_increase",
            requested_level=50,
            reason="Need higher autonomy",
            source="agent",
        )

        approved = self.guard.approve_escalation("session-1", request.request_id)
        assert approved is True

        state = self.guard.get_agent_state("session-1")
        assert state.autonomy_level == 50

    def test_should_deny_escalation_requests_and_reduce_autonomy(self):
        request = self.guard.request_escalation(
            "session-1",
            request_type="level_increase",
            requested_level=50,
            reason="Need higher autonomy",
            source="agent",
        )

        initial_state = self.guard.get_agent_state("session-1")
        initial_level = initial_state.autonomy_level if initial_state else 25

        denied = self.guard.deny_escalation("session-1", request.request_id)
        assert denied is True

        state = self.guard.get_agent_state("session-1")
        assert state.autonomy_level < initial_level

    def test_should_approve_capability_expansion_requests(self):
        request = self.guard.request_escalation(
            "session-1",
            request_type="capability_expansion",
            requested_capability="special_action",
            reason="Need special capability",
            source="agent",
        )

        self.guard.approve_escalation("session-1", request.request_id)

        state = self.guard.get_agent_state("session-1")
        assert "special_action" in state.capabilities


# ---------------------------------------------------------------------------
# Session Management
# ---------------------------------------------------------------------------

class TestSessionManagement:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_reset_session_state(self):
        self.guard.validate("query", "session-1")
        self.guard.set_autonomy_level("session-1", 75)

        self.guard.reset_session("session-1")

        state = self.guard.get_agent_state("session-1")
        assert state is None

    def test_should_maintain_separate_states_for_different_sessions(self):
        self.guard.set_autonomy_level("session-1", 50)
        self.guard.set_autonomy_level("session-2", 75)

        assert self.guard.get_agent_state("session-1").autonomy_level == 50
        assert self.guard.get_agent_state("session-2").autonomy_level == 75


# ---------------------------------------------------------------------------
# Edge Cases
# ---------------------------------------------------------------------------

class TestEdgeCases:
    def setup_method(self):
        self.guard = AutonomyEscalationGuard()

    def test_should_handle_empty_params(self):
        result = self.guard.validate("query", "session-1", {})
        assert result.allowed is True

    def test_should_handle_undefined_session_state(self):
        state = self.guard.get_agent_state("non-existent")
        assert state is None

    def test_should_cap_autonomy_level_at_max(self):
        self.guard.set_autonomy_level("session-1", 150)
        state = self.guard.get_agent_state("session-1")
        assert state.autonomy_level == 75  # maxAutonomyLevel default


# ---------------------------------------------------------------------------
# Custom Configuration
# ---------------------------------------------------------------------------

class TestCustomConfiguration:
    def test_should_respect_custom_max_autonomy_level(self):
        custom_guard = AutonomyEscalationGuard(AutonomyEscalationGuardConfig(
            max_autonomy_level=50,
        ))

        custom_guard.set_autonomy_level("session-1", 100)
        state = custom_guard.get_agent_state("session-1")
        assert state.autonomy_level == 50

    def test_should_respect_custom_base_autonomy_level(self):
        custom_guard = AutonomyEscalationGuard(AutonomyEscalationGuardConfig(
            base_autonomy_level=50,
        ))

        custom_guard.validate("query", "session-1")
        state = custom_guard.get_agent_state("session-1")
        assert state.autonomy_level == 50

    def test_should_respect_custom_capability_levels(self):
        custom_guard = AutonomyEscalationGuard(AutonomyEscalationGuardConfig(
            capability_levels={
                0: ["custom_action"],
            },
        ))

        result = custom_guard.validate("custom_action", "session-1")
        assert result.analysis.capability_violation is False
