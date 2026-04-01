"""Tests for TenantBoundary guard - ported from tenant-boundary.test.ts (13 tests)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.tenant_boundary import (
    TenantBoundary,
    TenantBoundaryConfig,
    SessionContext,
)


@pytest.fixture
def tenant_a_session():
    return SessionContext(user_id="user-a1", tenant_id="tenant-A", role="customer", authenticated=True)


@pytest.fixture
def tenant_b_session():
    return SessionContext(user_id="user-b1", tenant_id="tenant-B", role="customer", authenticated=True)


@pytest.fixture
def guard():
    g = TenantBoundary(TenantBoundaryConfig(
        valid_tenants={"tenant-A", "tenant-B"},
    ))
    g.register_resource("order-100", "tenant-A", "order")
    g.register_resource("order-200", "tenant-B", "order")
    g.register_resource("doc-50", "tenant-A", "document")
    return g


# ---------------------------------------------------------------------------
# Cross-Tenant Access Blocking
# ---------------------------------------------------------------------------

class TestCrossTenantAccessBlocking:
    def test_should_block_tenant_a_from_accessing_tenant_b_resource(self, guard, tenant_a_session):
        result = guard.check("get_order", {"order_id": "order-200"}, tenant_a_session)
        assert result.allowed is False
        assert "CROSS_TENANT_ACCESS" in result.violations
        assert result.resource_tenant == "tenant-B"

    def test_should_allow_tenant_a_to_access_its_own_resource(self, guard, tenant_a_session):
        result = guard.check("get_order", {"order_id": "order-100"}, tenant_a_session)
        assert result.allowed is True
        assert len(result.violations) == 0

    def test_should_block_cross_tenant_access_via_document_id_field(self, guard, tenant_b_session):
        result = guard.check("get_document", {"document_id": "doc-50"}, tenant_b_session)
        assert result.allowed is False
        assert "CROSS_TENANT_ACCESS" in result.violations


# ---------------------------------------------------------------------------
# Tenant Parameter Injection Detection
# ---------------------------------------------------------------------------

class TestTenantParameterInjectionDetection:
    def test_should_block_when_tenant_id_param_differs_from_session_tenant(self, guard, tenant_a_session):
        result = guard.check("get_data", {"tenant_id": "tenant-B"}, tenant_a_session)
        assert result.allowed is False
        assert "TENANT_MANIPULATION" in result.violations
        assert "Cannot access tenant tenant-B" in result.reason

    def test_should_allow_when_tenant_id_param_matches_session_tenant(self, guard, tenant_a_session):
        result = guard.check("get_data", {"tenant_id": "tenant-A"}, tenant_a_session)
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Resource Ownership Validation
# ---------------------------------------------------------------------------

class TestResourceOwnershipValidation:
    def test_should_allow_access_to_unregistered_resource(self, guard, tenant_a_session):
        result = guard.check("get_order", {"order_id": "order-999"}, tenant_a_session)
        assert result.allowed is True

    def test_should_validate_ownership_across_multiple_resource_id_fields(self, guard, tenant_a_session):
        guard.register_resource("cust-77", "tenant-B", "customer")
        result = guard.check("get_customer", {"customer_id": "cust-77"}, tenant_a_session)
        assert result.allowed is False
        assert "CROSS_TENANT_ACCESS" in result.violations


# ---------------------------------------------------------------------------
# Tenant Filtering Enforcement
# ---------------------------------------------------------------------------

class TestTenantFilteringEnforcement:
    def test_should_enforce_tenant_filter_on_list_operations(self, guard, tenant_a_session):
        result = guard.check("list_orders", {}, tenant_a_session)
        assert result.allowed is True
        assert result.enforced_params is not None
        assert result.enforced_params["tenant_id"] == "tenant-A"

    def test_should_block_list_operation_with_different_tenant_filter(self, guard, tenant_a_session):
        result = guard.check("search_documents", {"tenant_id": "tenant-B"}, tenant_a_session)
        assert result.allowed is False
        assert "TENANT_MANIPULATION" in result.violations

    def test_should_not_enforce_tenant_filter_on_non_list_operations(self, guard, tenant_a_session):
        result = guard.check("update_profile", {"name": "New Name"}, tenant_a_session)
        assert result.allowed is True
        assert result.enforced_params == {"name": "New Name"}


# ---------------------------------------------------------------------------
# Session Validation
# ---------------------------------------------------------------------------

class TestSessionValidation:
    def test_should_reject_missing_session(self, guard):
        result = guard.check("get_order", {"order_id": "order-100"}, None)
        assert result.allowed is False
        assert "INVALID_SESSION" in result.violations

    def test_should_reject_session_with_invalid_tenant(self, guard):
        invalid_session = SessionContext(user_id="u1", tenant_id="tenant-UNKNOWN", role="customer", authenticated=True)
        result = guard.check("get_data", {}, invalid_session)
        assert result.allowed is False
        assert "Invalid tenant" in result.reason


# ---------------------------------------------------------------------------
# False Positive - Legitimate Access
# ---------------------------------------------------------------------------

class TestFalsePositiveLegitimateAccess:
    def test_should_allow_tenant_to_list_and_access_own_resources(self, guard, tenant_a_session):
        list_result = guard.check("list_orders", {"status": "active"}, tenant_a_session)
        assert list_result.allowed is True

        get_result = guard.check("get_order", {"order_id": "order-100"}, tenant_a_session)
        assert get_result.allowed is True
