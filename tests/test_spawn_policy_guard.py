"""Tests for SpawnPolicyGuard."""
import pytest
from llm_trust_guard import SpawnPolicyGuard, SpawnPolicyGuardConfig, SpawnRequest


@pytest.fixture
def guard():
    g = SpawnPolicyGuard()
    g.register_parent("root-agent")
    return g


def _req(**kwargs):
    defaults = dict(
        parent_agent_id="root-agent",
        child_agent_id="child-1",
        spawn_origin="internal",
        delegation_depth=0,
        is_third_party=False,
    )
    defaults.update(kwargs)
    return SpawnRequest(**defaults)


class TestDefaultPolicy:
    def test_allows_registered_parent_at_depth_0(self, guard):
        result = guard.validate_spawn(_req())
        assert result.allowed is True
        assert result.violations == []

    def test_blocks_unregistered_parent(self, guard):
        result = guard.validate_spawn(_req(parent_agent_id="unknown"))
        assert result.allowed is False
        assert "parent_not_registered" in result.violations
        assert result.policy_analysis.parent_not_registered is True

    def test_blocks_third_party_by_default(self, guard):
        result = guard.validate_spawn(_req(is_third_party=True, spawn_origin="openai"))
        assert result.allowed is False
        assert "third_party_spawning_blocked" in result.violations
        assert result.policy_analysis.third_party_blocked is True

    def test_blocks_depth_at_max(self, guard):
        result = guard.validate_spawn(_req(delegation_depth=2))
        assert result.allowed is False
        assert result.policy_analysis.depth_exceeded is True


class TestOriginAllowlist:
    def test_blocks_origin_not_in_allowlist(self):
        g = SpawnPolicyGuard(SpawnPolicyGuardConfig(allowed_spawn_origins=["internal"]))
        g.register_parent("root-agent")
        result = g.validate_spawn(_req(spawn_origin="anthropic"))
        assert result.allowed is False
        assert result.policy_analysis.origin_blocked is True

    def test_allows_origin_in_allowlist(self):
        g = SpawnPolicyGuard(SpawnPolicyGuardConfig(allowed_spawn_origins=["internal", "anthropic"]))
        g.register_parent("root-agent")
        result = g.validate_spawn(_req(spawn_origin="anthropic"))
        assert result.allowed is True


class TestChildLimit:
    def test_blocks_when_limit_exceeded(self):
        g = SpawnPolicyGuard(SpawnPolicyGuardConfig(max_children_per_parent=2))
        g.register_parent("root-agent")
        for i in range(2):
            g.validate_spawn(_req(child_agent_id=f"c{i}"))
        result = g.validate_spawn(_req(child_agent_id="c3"))
        assert result.allowed is False
        assert result.policy_analysis.children_limit_exceeded is True

    def test_allows_after_child_removed(self):
        g = SpawnPolicyGuard(SpawnPolicyGuardConfig(max_children_per_parent=1))
        g.register_parent("root-agent")
        g.validate_spawn(_req(child_agent_id="c1"))
        g.remove_child("root-agent", "c1")
        result = g.validate_spawn(_req(child_agent_id="c2"))
        assert result.allowed is True


class TestHumanApprovalGate:
    def test_sets_requires_human_approval(self):
        g = SpawnPolicyGuard(SpawnPolicyGuardConfig(require_approval_for_new_agents=True))
        g.register_parent("root-agent")
        result = g.validate_spawn(_req())
        assert result.requires_human_approval is True
        assert result.policy_analysis.approval_required is True
        # Should still be allowed (approval gate is informational, not blocking)
        assert result.allowed is True


class TestThirdPartyAllowed:
    def test_allows_third_party_when_permitted(self):
        g = SpawnPolicyGuard(SpawnPolicyGuardConfig(allow_third_party_spawning=True))
        g.register_parent("root-agent")
        result = g.validate_spawn(_req(is_third_party=True, spawn_origin="openai"))
        assert result.allowed is True


class TestZeroDepth:
    def test_blocks_all_spawning_when_depth_is_0(self):
        g = SpawnPolicyGuard(SpawnPolicyGuardConfig(max_delegation_depth=0))
        g.register_parent("root-agent")
        result = g.validate_spawn(_req(delegation_depth=0))
        assert result.allowed is False
        assert result.policy_analysis.depth_exceeded is True


class TestGetChildCount:
    def test_tracks_child_count(self, guard):
        guard.validate_spawn(_req(child_agent_id="x1"))
        guard.validate_spawn(_req(child_agent_id="x2"))
        assert guard.get_child_count("root-agent") == 2
