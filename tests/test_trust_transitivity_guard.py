"""Tests for TrustTransitivityGuard."""
import pytest
from llm_trust_guard import (
    TrustTransitivityGuard,
    TrustTransitivityGuardConfig,
    AgentTrustEntry,
)


@pytest.fixture
def guard():
    g = TrustTransitivityGuard()
    g.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["B"]))
    g.register_agent(AgentTrustEntry("B", trust_score=80, trusted_agents=["C"]))
    g.register_agent(AgentTrustEntry("C", trust_score=70, trusted_agents=[]))
    return g


class TestDirectTrust:
    def test_allows_single_registered_agent(self, guard):
        result = guard.validate_trust_chain(["A"])
        assert result.allowed is True
        assert result.chain_analysis.chain_depth == 0

    def test_rejects_empty_chain(self, guard):
        result = guard.validate_trust_chain([])
        assert result.allowed is False
        assert "empty_chain" in result.violations


class TestOneHopTransitivity:
    def test_allows_a_to_b(self, guard):
        result = guard.validate_trust_chain(["A", "B"])
        assert result.allowed is True
        assert result.chain_analysis.chain_depth == 1

    def test_blocks_a_b_c_when_one_hop(self, guard):
        result = guard.validate_trust_chain(["A", "B", "C"])
        assert result.allowed is False
        assert any("transitivity_one_hop" in v for v in result.violations)


class TestFullTransitivity:
    def test_allows_a_b_c_with_full_mode(self):
        g = TrustTransitivityGuard(TrustTransitivityGuardConfig(transitivity="full"))
        g.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["B"]))
        g.register_agent(AgentTrustEntry("B", trust_score=80, trusted_agents=["C"]))
        g.register_agent(AgentTrustEntry("C", trust_score=70, trusted_agents=[]))
        result = g.validate_trust_chain(["A", "B", "C"])
        assert result.allowed is True

    def test_blocks_chain_exceeding_max_depth(self):
        g = TrustTransitivityGuard(TrustTransitivityGuardConfig(
            transitivity="full", max_chain_depth=1
        ))
        g.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["B"]))
        g.register_agent(AgentTrustEntry("B", trust_score=80, trusted_agents=["C"]))
        g.register_agent(AgentTrustEntry("C", trust_score=70, trusted_agents=[]))
        result = g.validate_trust_chain(["A", "B", "C"])
        assert result.allowed is False
        assert result.chain_analysis.depth_exceeded is True


class TestNoneTransitivity:
    def test_blocks_a_b_when_none(self):
        g = TrustTransitivityGuard(TrustTransitivityGuardConfig(transitivity="none"))
        g.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["B"]))
        g.register_agent(AgentTrustEntry("B", trust_score=80, trusted_agents=[]))
        result = g.validate_trust_chain(["A", "B"])
        assert result.allowed is False
        assert any("transitivity_disabled" in v for v in result.violations)

    def test_allows_single_agent_when_none(self):
        g = TrustTransitivityGuard(TrustTransitivityGuardConfig(transitivity="none"))
        g.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=[]))
        result = g.validate_trust_chain(["A"])
        assert result.allowed is True


class TestBrokenLink:
    def test_rejects_undeclared_link(self, guard):
        # B does not trust A — reverse is a broken link
        result = guard.validate_trust_chain(["B", "A"])
        assert result.allowed is False
        assert {"from": "B", "to": "A"} in result.chain_analysis.broken_links


class TestUnknownAgent:
    def test_rejects_unregistered_agent(self, guard):
        result = guard.validate_trust_chain(["A", "Unknown"])
        assert result.allowed is False
        assert "Unknown" in result.chain_analysis.unknown_agents


class TestTrustDecay:
    def test_reduces_effective_trust_per_hop(self):
        g = TrustTransitivityGuard(TrustTransitivityGuardConfig(
            transitivity="full",
            trust_decay_per_hop=0.2,
            min_trust_score=10,
        ))
        g.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["B"]))
        g.register_agent(AgentTrustEntry("B", trust_score=80, trusted_agents=[]))
        result = g.validate_trust_chain(["A", "B"])
        assert result.allowed is True
        # B: 80 * (1-0.2)^1 = 64
        assert result.chain_analysis.final_effective_trust == 64

    def test_blocks_when_decayed_trust_below_minimum(self):
        g = TrustTransitivityGuard(TrustTransitivityGuardConfig(
            transitivity="full",
            trust_decay_per_hop=0.5,
            min_trust_score=50,
        ))
        g.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["low"]))
        g.register_agent(AgentTrustEntry("low", trust_score=60, trusted_agents=[]))
        # 60 * (1-0.5)^1 = 30 < 50
        result = g.validate_trust_chain(["A", "low"])
        assert result.allowed is False
        assert result.chain_analysis.trust_below_minimum is True


class TestHelpers:
    def test_directly_trusts_declared(self, guard):
        assert guard.directly_trusts("A", "B") is True

    def test_directly_trusts_undeclared(self, guard):
        assert guard.directly_trusts("A", "C") is False

    def test_update_trust_score(self, guard):
        guard.update_trust_score("B", 10)
        g2 = TrustTransitivityGuard(TrustTransitivityGuardConfig(
            transitivity="full", min_trust_score=50
        ))
        g2.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["B"]))
        g2.register_agent(AgentTrustEntry("B", trust_score=10, trusted_agents=[]))
        result = g2.validate_trust_chain(["A", "B"])
        assert result.allowed is False
