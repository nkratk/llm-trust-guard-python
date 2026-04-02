"""Tests for DelegationScopeGuard."""
import pytest
from llm_trust_guard import DelegationScopeGuard, DelegationScopeGuardConfig, DelegationRequest


def _req(**kwargs):
    defaults = dict(
        parent_agent_id="parent",
        parent_scopes=["read", "write", "admin"],
        child_agent_id="child",
        requested_scopes=["read"],
        hop_depth=0,
    )
    defaults.update(kwargs)
    return DelegationRequest(**defaults)


class TestBasicScopeEnforcement:
    def test_allows_strict_subset(self):
        guard = DelegationScopeGuard()
        result = guard.validate_delegation(_req(requested_scopes=["read"]))
        assert result.allowed is True
        assert result.scope_analysis.granted_scopes == ["read"]

    def test_allows_all_parent_scopes(self):
        guard = DelegationScopeGuard()
        result = guard.validate_delegation(_req(requested_scopes=["read", "write", "admin"]))
        assert result.allowed is True

    def test_blocks_privilege_amplification(self):
        guard = DelegationScopeGuard()
        result = guard.validate_delegation(_req(
            parent_scopes=["read"],
            requested_scopes=["read", "admin"],
        ))
        assert result.allowed is False
        assert "admin" in result.scope_analysis.out_of_parent_scopes
        assert any("scopes_exceed_parent" in v for v in result.violations)


class TestBlockedScopes:
    def test_blocks_configured_scopes(self):
        guard = DelegationScopeGuard(DelegationScopeGuardConfig(blocked_scopes=["admin", "superuser"]))
        result = guard.validate_delegation(_req(requested_scopes=["read", "admin"]))
        assert result.allowed is False
        assert "admin" in result.scope_analysis.blocked_scopes_found

    def test_allows_non_blocked_scopes(self):
        guard = DelegationScopeGuard(DelegationScopeGuardConfig(blocked_scopes=["admin"]))
        result = guard.validate_delegation(_req(requested_scopes=["read", "write"]))
        assert result.allowed is True
        assert result.scope_analysis.blocked_scopes_found == []


class TestScopeDecay:
    def test_reduces_allowed_count_per_hop(self):
        guard = DelegationScopeGuard(DelegationScopeGuardConfig(scope_decay_per_hop=0.5))
        # 4 parent scopes; at hop 2: floor(4 * 1.0 * 0.5^2) = 1
        result = guard.validate_delegation(_req(
            parent_scopes=["a", "b", "c", "d"],
            requested_scopes=["a", "b"],
            hop_depth=2,
        ))
        assert result.allowed is False
        assert result.scope_analysis.decay_applied is True
        assert result.scope_analysis.exceeds_inheritance_limit is True

    def test_allows_within_decayed_limit(self):
        guard = DelegationScopeGuard(DelegationScopeGuardConfig(scope_decay_per_hop=0.5))
        # at hop 1: floor(4 * 1.0 * 0.5) = 2
        result = guard.validate_delegation(_req(
            parent_scopes=["a", "b", "c", "d"],
            requested_scopes=["a", "b"],
            hop_depth=1,
        ))
        assert result.allowed is True


class TestMaxScopeInheritance:
    def test_limits_to_fraction_of_parent(self):
        guard = DelegationScopeGuard(DelegationScopeGuardConfig(max_scope_inheritance=0.5))
        # 4 scopes * 0.5 = 2 max
        result = guard.validate_delegation(_req(
            parent_scopes=["a", "b", "c", "d"],
            requested_scopes=["a", "b", "c"],
            hop_depth=0,
        ))
        assert result.allowed is False
        assert result.scope_analysis.exceeds_inheritance_limit is True

    def test_allows_at_exact_fraction(self):
        guard = DelegationScopeGuard(DelegationScopeGuardConfig(max_scope_inheritance=0.5))
        result = guard.validate_delegation(_req(
            parent_scopes=["a", "b", "c", "d"],
            requested_scopes=["a", "b"],
            hop_depth=0,
        ))
        assert result.allowed is True


class TestAllowedScopesAllowlist:
    def test_blocks_scopes_not_in_allowlist(self):
        guard = DelegationScopeGuard(DelegationScopeGuardConfig(allowed_scopes=["read", "list"]))
        result = guard.validate_delegation(_req(
            parent_scopes=["read", "write"],
            requested_scopes=["read", "write"],
        ))
        assert result.allowed is False
        assert any("scopes_not_in_allowlist" in v for v in result.violations)


class TestAuditLog:
    def test_stores_result_in_audit_log(self):
        guard = DelegationScopeGuard()
        result = guard.validate_delegation(_req(requested_scopes=["read"]), request_id="test-req")
        logged = guard.get_audit_log("test-req")
        assert logged is not None
        assert logged.allowed == result.allowed
