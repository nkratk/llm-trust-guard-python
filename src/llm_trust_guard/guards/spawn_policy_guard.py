"""
SpawnPolicyGuard (L32)

Controls whether agents can spawn child agents (sub-agents).
Like CSP headers but for agent spawning — defines which agents may create
other agents, under what conditions, and with what constraints.

Threat Model:
- ASI07: Insecure Inter-Agent Communication
- Unauthorized agent spawning (evading controls via sub-agents)
- Third-party agent injection
- Delegation depth explosion
- Privilege amplification through spawning

Protection Capabilities:
- Per-origin spawn allowlisting
- Third-party spawn gating
- Delegation depth enforcement
- Human-in-the-loop gate
- Runtime spawn counter per parent
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class SpawnPolicyGuardConfig:
    """Configuration for SpawnPolicyGuard."""
    allow_third_party_spawning: bool = False
    max_delegation_depth: int = 2
    require_approval_for_new_agents: bool = False
    allowed_spawn_origins: List[str] = field(default_factory=list)
    max_children_per_parent: int = 10
    require_registered_parent: bool = True


@dataclass
class SpawnRequest:
    """Describes a proposed agent spawn."""
    parent_agent_id: str
    child_agent_id: str
    spawn_origin: str
    delegation_depth: int
    is_third_party: bool
    reason: Optional[str] = None
    metadata: Optional[Dict] = None


@dataclass
class SpawnPolicyAnalysis:
    third_party_blocked: bool = False
    depth_exceeded: bool = False
    origin_blocked: bool = False
    parent_not_registered: bool = False
    children_limit_exceeded: bool = False
    approval_required: bool = False


@dataclass
class SpawnPolicyResult:
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    policy_analysis: SpawnPolicyAnalysis
    requires_human_approval: bool


class SpawnPolicyGuard:
    """
    Controls agent spawning via configurable policy rules.

    Usage::

        guard = SpawnPolicyGuard(SpawnPolicyGuardConfig(max_delegation_depth=1))
        guard.register_parent("orchestrator")
        result = guard.validate_spawn(SpawnRequest(
            parent_agent_id="orchestrator",
            child_agent_id="worker-1",
            spawn_origin="internal",
            delegation_depth=0,
            is_third_party=False,
        ))
    """

    guard_name = "SpawnPolicyGuard"
    guard_layer = "L32"

    def __init__(self, config: Optional[SpawnPolicyGuardConfig] = None) -> None:
        self._config = config or SpawnPolicyGuardConfig()
        self._registered_parents: Set[str] = set()
        # parent_id -> set of active child ids
        self._active_children: Dict[str, Set[str]] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_parent(self, agent_id: str) -> None:
        """Mark an agent as an approved spawner."""
        self._registered_parents.add(agent_id)

    def remove_child(self, parent_agent_id: str, child_agent_id: str) -> None:
        """Record that a child agent has been terminated."""
        self._active_children.get(parent_agent_id, set()).discard(child_agent_id)

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def validate_spawn(
        self,
        request: SpawnRequest,
        request_id: Optional[str] = None,
    ) -> SpawnPolicyResult:
        """Validate whether a spawn is permitted under the current policy."""
        req_id = request_id or f"spawn-{os.urandom(6).hex()}"
        violations: List[str] = []
        analysis = SpawnPolicyAnalysis()

        cfg = self._config

        # 1. Registered parent check
        if cfg.require_registered_parent and request.parent_agent_id not in self._registered_parents:
            violations.append("parent_not_registered")
            analysis.parent_not_registered = True

        # 2. Third-party spawn check
        if request.is_third_party and not cfg.allow_third_party_spawning:
            violations.append("third_party_spawning_blocked")
            analysis.third_party_blocked = True

        # 3. Delegation depth check
        if request.delegation_depth >= cfg.max_delegation_depth:
            violations.append(
                f"delegation_depth_exceeded: {request.delegation_depth} >= max {cfg.max_delegation_depth}"
            )
            analysis.depth_exceeded = True

        # 4. Origin allowlist check (only when the list is non-empty)
        if cfg.allowed_spawn_origins and request.spawn_origin not in cfg.allowed_spawn_origins:
            violations.append(f"spawn_origin_not_allowed: {request.spawn_origin}")
            analysis.origin_blocked = True

        # 5. Per-parent child limit
        child_count = len(self._active_children.get(request.parent_agent_id, set()))
        if child_count >= cfg.max_children_per_parent:
            violations.append(
                f"children_limit_exceeded: {child_count} >= max {cfg.max_children_per_parent}"
            )
            analysis.children_limit_exceeded = True

        # 6. Human approval gate (informational — not a blocking violation)
        if cfg.require_approval_for_new_agents:
            analysis.approval_required = True

        allowed = len(violations) == 0

        if allowed:
            if request.parent_agent_id not in self._active_children:
                self._active_children[request.parent_agent_id] = set()
            self._active_children[request.parent_agent_id].add(request.child_agent_id)

        return SpawnPolicyResult(
            allowed=allowed,
            reason="Spawn permitted" if allowed else f"Spawn blocked: {'; '.join(violations[:3])}",
            violations=violations,
            request_id=req_id,
            policy_analysis=analysis,
            requires_human_approval=cfg.require_approval_for_new_agents,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_child_count(self, parent_agent_id: str) -> int:
        return len(self._active_children.get(parent_agent_id, set()))

    def reset(self) -> None:
        self._active_children.clear()
        self._registered_parents.clear()
