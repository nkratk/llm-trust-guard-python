"""
DelegationScopeGuard (L33)

Limits what permissions a child agent can inherit from its parent.
Like OAuth token downscoping — a child can only receive a strict subset of
the parent's scopes, and scopes further decay with each delegation hop.

Threat Model:
- ASI07: Insecure Inter-Agent Communication
- Privilege amplification via delegation
- Lateral movement through scope inheritance
- Scope laundering across hops

Protection Capabilities:
- Strict subset enforcement (child ⊆ parent)
- Per-hop scope decay
- Blocked scope list (never inheritable)
- Maximum allowed scope fraction
- Full delegation audit trail
"""

from __future__ import annotations

import math
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class DelegationScopeGuardConfig:
    """Configuration for DelegationScopeGuard."""
    max_scope_inheritance: float = 1.0   # fraction of parent scopes child may receive
    blocked_scopes: List[str] = field(default_factory=list)
    scope_decay_per_hop: float = 0.0     # fraction shrinkage per delegation hop
    allowed_scopes: List[str] = field(default_factory=list)


@dataclass
class DelegationRequest:
    """Describes a delegation being attempted."""
    parent_agent_id: str
    parent_scopes: List[str]
    child_agent_id: str
    requested_scopes: List[str]
    hop_depth: int
    reason: Optional[str] = None


@dataclass
class ScopeAnalysis:
    parent_scopes: List[str]
    requested_scopes: List[str]
    granted_scopes: List[str]
    blocked_scopes_found: List[str]
    out_of_parent_scopes: List[str]
    exceeds_inheritance_limit: bool
    decay_applied: bool
    effective_max_scopes: int


@dataclass
class DelegationScopeResult:
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    scope_analysis: ScopeAnalysis


class DelegationScopeGuard:
    """
    Enforces OAuth-style scope downscoping for agent delegation.

    Usage::

        guard = DelegationScopeGuard(DelegationScopeGuardConfig(
            blocked_scopes=["admin"],
            scope_decay_per_hop=0.25,
        ))
        result = guard.validate_delegation(DelegationRequest(
            parent_agent_id="parent",
            parent_scopes=["read", "write", "admin"],
            child_agent_id="child",
            requested_scopes=["read"],
            hop_depth=0,
        ))
    """

    guard_name = "DelegationScopeGuard"
    guard_layer = "L33"

    def __init__(self, config: Optional[DelegationScopeGuardConfig] = None) -> None:
        self._config = config or DelegationScopeGuardConfig()
        self._audit_log: Dict[str, DelegationScopeResult] = {}

    def validate_delegation(
        self,
        request: DelegationRequest,
        request_id: Optional[str] = None,
    ) -> DelegationScopeResult:
        req_id = request_id or f"delg-{os.urandom(6).hex()}"
        violations: List[str] = []
        cfg = self._config

        parent_set = set(request.parent_scopes)
        requested = request.requested_scopes

        # 1. Blocked scopes
        blocked_found = [s for s in requested if s in cfg.blocked_scopes]
        if blocked_found:
            violations.append(f"blocked_scopes: [{', '.join(blocked_found)}]")

        # 2. Scopes not held by parent
        out_of_parent = [s for s in requested if s not in parent_set]
        if out_of_parent:
            violations.append(f"scopes_exceed_parent: [{', '.join(out_of_parent)}]")

        # 3. Allowlist check
        if cfg.allowed_scopes:
            not_allowed = [s for s in requested if s not in cfg.allowed_scopes]
            if not_allowed:
                violations.append(f"scopes_not_in_allowlist: [{', '.join(not_allowed)}]")

        # 4. Effective max scopes after decay
        decay_factor = max(0.0, 1.0 - cfg.scope_decay_per_hop * request.hop_depth)
        raw_max = math.floor(len(request.parent_scopes) * cfg.max_scope_inheritance * decay_factor)
        effective_max = max(0, raw_max)
        decay_applied = cfg.scope_decay_per_hop > 0 and request.hop_depth > 0

        exceeds_limit = len(requested) > effective_max
        if exceeds_limit:
            violations.append(
                f"inheritance_limit_exceeded: requested {len(requested)}, max {effective_max}"
            )

        # Compute grantable scopes
        grantable = [
            s for s in requested
            if s in parent_set
            and s not in cfg.blocked_scopes
            and (not cfg.allowed_scopes or s in cfg.allowed_scopes)
        ]
        granted = grantable[:effective_max]

        allowed = len(violations) == 0

        result = DelegationScopeResult(
            allowed=allowed,
            reason="Delegation scopes granted" if allowed else f"Delegation restricted: {'; '.join(violations[:3])}",
            violations=violations,
            request_id=req_id,
            scope_analysis=ScopeAnalysis(
                parent_scopes=request.parent_scopes,
                requested_scopes=requested,
                granted_scopes=granted if allowed else [],
                blocked_scopes_found=blocked_found,
                out_of_parent_scopes=out_of_parent,
                exceeds_inheritance_limit=exceeds_limit,
                decay_applied=decay_applied,
                effective_max_scopes=effective_max,
            ),
        )
        self._audit_log[req_id] = result
        return result

    def get_audit_log(self, request_id: str) -> Optional[DelegationScopeResult]:
        return self._audit_log.get(request_id)

    def clear_audit_log(self) -> None:
        self._audit_log.clear()
