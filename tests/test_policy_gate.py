"""Tests for PolicyGate guard - ported from policy-gate.test.ts (15 tests)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.policy_gate import (
    PolicyGate,
    PolicyGateConfig,
    SessionContext,
    ToolDefinition,
)


@pytest.fixture
def admin_session():
    return SessionContext(user_id="admin-1", tenant_id="tenant-1", role="admin", authenticated=True)


@pytest.fixture
def customer_session():
    return SessionContext(user_id="customer-1", tenant_id="tenant-1", role="customer", authenticated=True)


@pytest.fixture
def admin_tool():
    return ToolDefinition(
        name="manage_users",
        description="Manage user accounts",
        parameters={"type": "object", "properties": {}, "required": []},
        roles=["admin"],
    )


@pytest.fixture
def public_tool():
    return ToolDefinition(
        name="get_info",
        description="Get public information",
        parameters={"type": "object", "properties": {}, "required": []},
        roles=[],
    )


@pytest.fixture
def constrained_tool():
    return ToolDefinition(
        name="transfer_funds",
        description="Transfer funds between accounts",
        parameters={"type": "object", "properties": {}, "required": []},
        roles=["admin", "customer"],
        constraints={
            "customer": {"max_amount": 1000, "require_approval": False},
            "admin": {"max_amount": 100000},
        },
    )


@pytest.fixture
def gate():
    return PolicyGate(PolicyGateConfig(
        role_hierarchy={"admin": 100, "manager": 50, "customer": 10, "guest": 0},
    ))


# ---------------------------------------------------------------------------
# Role-Based Access Control
# ---------------------------------------------------------------------------

class TestRoleBasedAccessControl:
    def test_should_allow_admin_to_access_admin_only_tool(self, gate, admin_tool, admin_session):
        result = gate.check(admin_tool, {}, admin_session, None)
        assert result.allowed is True

    def test_should_block_customer_from_accessing_admin_only_tool(self, gate, admin_tool, customer_session):
        result = gate.check(admin_tool, {}, customer_session, None)
        assert result.allowed is False
        assert "UNAUTHORIZED_TOOL" in result.violations
        assert "not authorized" in result.reason

    def test_should_allow_any_role_to_access_tool_with_no_role_restrictions(self, gate, public_tool, customer_session):
        result = gate.check(public_tool, {}, customer_session, None)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Role Hierarchy
# ---------------------------------------------------------------------------

class TestRoleHierarchy:
    def test_should_allow_higher_hierarchy_role_to_access_lower_role_tool(self, gate, admin_session):
        manager_tool = ToolDefinition(
            name="view_reports",
            description="View reports",
            parameters={"type": "object", "properties": {}, "required": []},
            roles=["manager"],
        )
        result = gate.check(manager_tool, {}, admin_session, None)
        assert result.allowed is True

    def test_should_block_lower_hierarchy_role_from_accessing_higher_role_tool(self, gate, admin_tool, customer_session):
        result = gate.check(admin_tool, {}, customer_session, None)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Role Tampering Detection
# ---------------------------------------------------------------------------

class TestRoleTamperingDetection:
    def test_should_detect_when_claimed_role_differs_from_session_role(self, gate, customer_session):
        result = gate.detect_role_tampering(customer_session, "admin")
        assert result["tampered"] is True
        assert result["actual"] == "customer"
        assert result["claimed"] == "admin"

    def test_should_not_flag_tampering_when_claimed_role_matches_session(self, gate, admin_session):
        result = gate.detect_role_tampering(admin_session, "admin")
        assert result["tampered"] is False
        assert result["actual"] == "admin"

    def test_should_not_flag_tampering_when_no_claimed_role_provided(self, gate, customer_session):
        result = gate.detect_role_tampering(customer_session, None)
        assert result["tampered"] is False

    def test_should_still_use_session_role_for_access_even_with_tampered_claimed_role(self, gate, admin_tool, customer_session):
        result = gate.check(admin_tool, {}, customer_session, "admin")
        assert result.allowed is False
        assert "ROLE_TAMPERING" in result.violations


# ---------------------------------------------------------------------------
# Constraint Validation
# ---------------------------------------------------------------------------

class TestConstraintValidation:
    def test_should_block_when_amount_exceeds_max_amount_for_role(self, gate, constrained_tool, customer_session):
        result = gate.check(constrained_tool, {"amount": 5000}, customer_session, None)
        assert result.allowed is False
        assert result.constraint_violations is not None
        assert len(result.constraint_violations) > 0
        assert "exceeds limit" in result.constraint_violations[0]

    def test_should_allow_when_amount_is_within_max_amount_for_role(self, gate, constrained_tool, customer_session):
        result = gate.check(constrained_tool, {"amount": 500}, customer_session, None)
        assert result.allowed is True

    def test_should_enforce_require_approval_constraint(self, gate, customer_session):
        approval_tool = ToolDefinition(
            name="high_value_action",
            description="Requires approval",
            parameters={"type": "object", "properties": {}, "required": []},
            roles=["customer"],
            constraints={"customer": {"require_approval": True}},
        )

        without_approval = gate.check_constraints(approval_tool, {}, customer_session)
        assert without_approval["valid"] is False
        assert "requires approval" in without_approval["violations"][0]

        with_approval = gate.check_constraints(approval_tool, {"approval_id": "APR-123"}, customer_session)
        assert with_approval["valid"] is True


# ---------------------------------------------------------------------------
# Session Validation
# ---------------------------------------------------------------------------

class TestSessionValidation:
    def test_should_reject_missing_session(self, gate, public_tool):
        result = gate.check(public_tool, {}, None, None)
        assert result.allowed is False
        assert "INVALID_SESSION" in result.violations

    def test_should_reject_unauthenticated_session(self, gate, public_tool):
        unauth_session = SessionContext(user_id="u1", tenant_id="t1", role="customer", authenticated=False)
        result = gate.check(public_tool, {}, unauth_session, None)
        assert result.allowed is False
        assert "not authenticated" in result.reason


# ---------------------------------------------------------------------------
# False Positive - Legitimate Access
# ---------------------------------------------------------------------------

class TestFalsePositiveLegitimateAccess:
    def test_should_allow_customer_to_use_customer_authorized_tool_within_constraints(self, gate, constrained_tool, customer_session):
        result = gate.check(constrained_tool, {"amount": 100}, customer_session, "customer")
        assert result.allowed is True
        assert len(result.violations) == 0
