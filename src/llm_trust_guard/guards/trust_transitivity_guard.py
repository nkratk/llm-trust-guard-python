"""
TrustTransitivityGuard (L34)

Governs whether trust flows transitively through an agent chain.
"You trust A. A trusts B. B trusts C. Should you trust C?"

Modelled on X.509 certificate chain validation — the chain is only as
strong as its weakest link, and depth / decay rules prevent unbounded
trust propagation.

Threat Model:
- ASI07: Insecure Inter-Agent Communication
- Trust laundering through intermediaries
- Long-chain attacks
- Phantom-agent injection into a trusted chain

Protection Capabilities:
- Configurable transitivity modes: none | one-hop | full
- Per-hop trust decay
- Maximum chain depth enforcement
- Individual agent trust score validation
- Full chain audit with per-hop breakdown
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional

TransitivityMode = Literal["none", "one-hop", "full"]


@dataclass
class TrustTransitivityGuardConfig:
    """Configuration for TrustTransitivityGuard."""
    transitivity: TransitivityMode = "one-hop"
    max_chain_depth: int = 3
    trust_decay_per_hop: float = 0.1   # fractional decay per hop
    min_trust_score: int = 50          # 0-100


@dataclass
class AgentTrustEntry:
    agent_id: str
    trust_score: int                              # 0-100
    trusted_agents: List[str] = field(default_factory=list)


@dataclass
class TrustChainLink:
    agent_id: str
    trust_score: int
    effective_trust_score: int
    direct_trust: bool


@dataclass
class ChainAnalysis:
    chain: List[TrustChainLink]
    chain_depth: int
    final_effective_trust: int
    transitivity_mode: str
    depth_exceeded: bool
    trust_below_minimum: bool
    unknown_agents: List[str]
    broken_links: List[Dict[str, str]]


@dataclass
class TrustTransitivityResult:
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    chain_analysis: ChainAnalysis


class TrustTransitivityGuard:
    """
    Validates trust chains in multi-agent systems.

    Usage::

        guard = TrustTransitivityGuard(TrustTransitivityGuardConfig(transitivity="full"))
        guard.register_agent(AgentTrustEntry("A", trust_score=90, trusted_agents=["B"]))
        guard.register_agent(AgentTrustEntry("B", trust_score=80, trusted_agents=["C"]))
        guard.register_agent(AgentTrustEntry("C", trust_score=70))
        result = guard.validate_trust_chain(["A", "B", "C"])
    """

    guard_name = "TrustTransitivityGuard"
    guard_layer = "L34"

    def __init__(self, config: Optional[TrustTransitivityGuardConfig] = None) -> None:
        self._config = config or TrustTransitivityGuardConfig()
        self._registry: Dict[str, AgentTrustEntry] = {}

    def register_agent(self, entry: AgentTrustEntry) -> None:
        self._registry[entry.agent_id] = AgentTrustEntry(
            agent_id=entry.agent_id,
            trust_score=entry.trust_score,
            trusted_agents=list(entry.trusted_agents),
        )

    def validate_trust_chain(
        self,
        agent_chain: List[str],
        request_id: Optional[str] = None,
    ) -> TrustTransitivityResult:
        req_id = request_id or f"ttg-{os.urandom(6).hex()}"
        violations: List[str] = []
        cfg = self._config

        if not agent_chain:
            return TrustTransitivityResult(
                allowed=False,
                reason="Empty agent chain",
                violations=["empty_chain"],
                request_id=req_id,
                chain_analysis=ChainAnalysis(
                    chain=[],
                    chain_depth=0,
                    final_effective_trust=0,
                    transitivity_mode=cfg.transitivity,
                    depth_exceeded=False,
                    trust_below_minimum=True,
                    unknown_agents=[],
                    broken_links=[],
                ),
            )

        chain_depth = len(agent_chain) - 1

        # 1. Depth check
        depth_exceeded = chain_depth > cfg.max_chain_depth
        if depth_exceeded:
            violations.append(
                f"chain_depth_exceeded: {chain_depth} > max {cfg.max_chain_depth}"
            )

        # 2. Transitivity mode
        if cfg.transitivity == "none" and chain_depth > 0:
            violations.append("transitivity_disabled: only direct trust allowed")
        elif cfg.transitivity == "one-hop" and chain_depth > 1:
            violations.append(f"transitivity_one_hop: chain has {chain_depth} hops, max 1")

        # 3. Walk chain
        chain_links: List[TrustChainLink] = []
        unknown_agents: List[str] = []
        broken_links: List[Dict[str, str]] = []
        effective_trust = 100

        for i, agent_id in enumerate(agent_chain):
            entry = self._registry.get(agent_id)
            if entry is None:
                unknown_agents.append(agent_id)
                violations.append(f"unknown_agent: {agent_id}")
                chain_links.append(TrustChainLink(
                    agent_id=agent_id,
                    trust_score=0,
                    effective_trust_score=0,
                    direct_trust=False,
                ))
                effective_trust = 0
                continue

            decay_multiplier = (1.0 - cfg.trust_decay_per_hop) ** i if i > 0 else 1.0
            effective_trust = round(entry.trust_score * decay_multiplier)

            direct_trust = True
            if i > 0:
                prev_id = agent_chain[i - 1]
                prev_entry = self._registry.get(prev_id)
                if prev_entry is None or agent_id not in prev_entry.trusted_agents:
                    broken_links.append({"from": prev_id, "to": agent_id})
                    violations.append(f"broken_trust_link: {prev_id} -> {agent_id}")
                    direct_trust = False

            chain_links.append(TrustChainLink(
                agent_id=agent_id,
                trust_score=entry.trust_score,
                effective_trust_score=effective_trust,
                direct_trust=direct_trust,
            ))

        # 4. Minimum trust threshold
        trust_below_min = effective_trust < cfg.min_trust_score
        if trust_below_min:
            violations.append(
                f"effective_trust_too_low: {effective_trust} < min {cfg.min_trust_score}"
            )

        allowed = len(violations) == 0

        return TrustTransitivityResult(
            allowed=allowed,
            reason="Trust chain validated" if allowed else f"Trust chain rejected: {'; '.join(violations[:3])}",
            violations=violations,
            request_id=req_id,
            chain_analysis=ChainAnalysis(
                chain=chain_links,
                chain_depth=chain_depth,
                final_effective_trust=effective_trust,
                transitivity_mode=cfg.transitivity,
                depth_exceeded=depth_exceeded,
                trust_below_minimum=trust_below_min,
                unknown_agents=unknown_agents,
                broken_links=broken_links,
            ),
        )

    def update_trust_score(self, agent_id: str, score: int) -> None:
        entry = self._registry.get(agent_id)
        if entry:
            entry.trust_score = max(0, min(100, score))

    def directly_trusts(self, agent_a: str, agent_b: str) -> bool:
        entry = self._registry.get(agent_a)
        return agent_b in (entry.trusted_agents if entry else [])

    def reset(self) -> None:
        self._registry.clear()
