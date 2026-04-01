"""
AutonomyEscalationGuard (L21)

Detects and prevents unauthorized autonomy escalation attempts.
Implements ASI10 from OWASP Agentic Applications 2026.

Threat Model:
- ASI10: Unauthorized Autonomy Escalation
- Self-modification attempts
- Capability expansion
- Human-in-the-loop bypass
- Sub-agent spawning without approval

Protection Capabilities:
- Autonomy level tracking
- Capability boundary enforcement
- Self-modification detection
- Sub-agent control
- Escalation pattern detection
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class AutonomyEscalationGuardConfig:
    """Configuration for AutonomyEscalationGuard."""
    max_autonomy_level: int = 75
    base_autonomy_level: int = 25
    detect_self_modification: bool = True
    control_sub_agents: bool = True
    max_sub_agents: int = 3
    escalation_required_actions: List[str] = field(
        default_factory=lambda: [
            "execute_code", "modify_system", "api_call_external",
            "spawn_agent", "modify_config",
        ]
    )
    enforce_capability_boundaries: bool = True
    capability_levels: Optional[Dict[int, List[str]]] = None
    enforce_hitl: bool = True
    always_require_human: List[str] = field(
        default_factory=lambda: [
            "delete_data", "payment_process", "credential_modify",
            "user_data_export", "system_shutdown",
        ]
    )


DEFAULT_CAPABILITY_LEVELS: Dict[int, List[str]] = {
    0: ["read_only", "query"],
    25: ["read_only", "query", "suggest", "analyze"],
    50: ["read_only", "query", "suggest", "analyze", "create_draft", "modify_draft"],
    75: ["read_only", "query", "suggest", "analyze", "create_draft", "modify_draft", "execute_safe", "api_call_internal"],
    100: [
        "read_only", "query", "suggest", "analyze", "create_draft", "modify_draft",
        "execute_safe", "api_call_internal", "execute_any", "api_call_external", "modify_system",
    ],
}


@dataclass
class AutonomyRequest:
    """An autonomy escalation request."""
    request_id: str
    request_type: str  # "capability_expansion" | "level_increase" | "spawn_agent" | "self_modify" | "bypass_hitl" | "persist_state"
    source: str
    timestamp: int
    requested_capability: Optional[str] = None
    requested_level: Optional[int] = None
    reason: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AgentCapabilities:
    """Current agent capabilities state."""
    capabilities: Set[str]
    autonomy_level: int
    sub_agents: List[str]
    pending_requests: List[AutonomyRequest]
    denied_requests: List[AutonomyRequest]
    last_capability_change: int
    hitl_checkpoints: int


@dataclass
class AutonomyAnalysis:
    """Analysis sub-result."""
    current_autonomy_level: int
    requested_autonomy_level: Optional[int]
    capability_violation: bool
    self_modification_detected: bool
    sub_agent_limit_exceeded: bool
    hitl_required: bool
    escalation_patterns_detected: List[str]


@dataclass
class AutonomyEscalationResult:
    """Result of autonomy escalation validation."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    analysis: AutonomyAnalysis
    requires_approval: bool
    approval_type: Optional[str] = None  # "human" | "admin" | "system"
    recommendations: List[str] = field(default_factory=list)


@dataclass
class _EscalationPattern:
    name: str
    pattern: re.Pattern[str]
    severity: int


class AutonomyEscalationGuard:
    """Detects and prevents unauthorized autonomy escalation attempts."""

    ESCALATION_PATTERNS: List[_EscalationPattern] = [
        # Self-modification attempts
        _EscalationPattern("modify_own_code", re.compile(r"modify\s+(?:my\s+own|my|own|this\s+agent'?s?)\s+(?:code|behavior|instructions?)", re.IGNORECASE), 90),
        _EscalationPattern("update_capabilities", re.compile(r'update\s+(?:my|own)\s+(?:capabilities|permissions?|abilities)', re.IGNORECASE), 80),
        _EscalationPattern("change_constraints", re.compile(r'remove?\s+(?:my|the)?\s*(?:constraints?|limitations?|restrictions?)', re.IGNORECASE), 85),
        _EscalationPattern("disable_safety", re.compile(r'disable\s+(?:safety|security|guardrails?|filters?)', re.IGNORECASE), 95),

        # Autonomy expansion
        _EscalationPattern("increase_autonomy", re.compile(r"increase\s+(?:my|agent'?s?)?\s*autonomy", re.IGNORECASE), 70),
        _EscalationPattern("act_freely", re.compile(r'act\s+(?:freely|without\s+restriction|independently)', re.IGNORECASE), 75),
        _EscalationPattern("full_control", re.compile(r'give\s+(?:me|agent)\s+(?:full|complete|total)\s+control', re.IGNORECASE), 85),
        _EscalationPattern("unrestricted", re.compile(r'unrestricted\s+(?:access|mode|operation)', re.IGNORECASE), 80),

        # Human-in-the-loop bypass
        _EscalationPattern("bypass_approval", re.compile(r'bypass\s+(?:human\s+)?(?:approval|verification|confirmation)', re.IGNORECASE), 90),
        _EscalationPattern("skip_review", re.compile(r'skip\s+(?:human\s+)?(?:review|check|oversight)', re.IGNORECASE), 85),
        _EscalationPattern("no_supervision", re.compile(r'without\s+(?:human\s+)?(?:supervision|oversight|intervention)', re.IGNORECASE), 80),
        _EscalationPattern("auto_approve", re.compile(r'auto[-\s]?(?:approve|authorize|confirm)', re.IGNORECASE), 75),

        # Sub-agent spawning
        _EscalationPattern("spawn_agent", re.compile(r'spawn\s+(?:new\s+)?(?:agent|process|worker)', re.IGNORECASE), 60),
        _EscalationPattern("create_copy", re.compile(r'create\s+(?:a\s+)?(?:copy|clone|replica)\s+of\s+(?:myself|this\s+agent)', re.IGNORECASE), 85),
        _EscalationPattern("delegate_all", re.compile(r'delegate\s+(?:all|everything|full\s+authority)', re.IGNORECASE), 70),
        _EscalationPattern("fork_agent", re.compile(r'fork\s+(?:myself|this\s+agent|process)', re.IGNORECASE), 80),

        # Persistence attempts
        _EscalationPattern("persist_changes", re.compile(r'persist\s+(?:these\s+)?(?:changes|modifications?|settings?)', re.IGNORECASE), 65),
        _EscalationPattern("permanent_mode", re.compile(r'permanent(?:ly)?\s+(?:enable|activate|set)', re.IGNORECASE), 70),
        _EscalationPattern("save_state", re.compile(r'save\s+(?:my|current)\s+state\s+(?:permanently|forever)', re.IGNORECASE), 60),
        _EscalationPattern("write_config", re.compile(r'write\s+to\s+(?:config|configuration|settings)', re.IGNORECASE), 75),

        # Capability escalation
        _EscalationPattern("need_more_access", re.compile(r'need\s+(?:more|additional|elevated)\s+access', re.IGNORECASE), 50),
        _EscalationPattern("require_permissions", re.compile(r'require\s+(?:admin|root|elevated)\s+permissions?', re.IGNORECASE), 70),
        _EscalationPattern("unlock_features", re.compile(r'unlock\s+(?:hidden|restricted|blocked)\s+features?', re.IGNORECASE), 75),
        _EscalationPattern("enable_all", re.compile(r'enable\s+all\s+(?:capabilities|features?|functions?)', re.IGNORECASE), 80),
    ]

    def __init__(self, config: Optional[AutonomyEscalationGuardConfig] = None) -> None:
        cfg = config or AutonomyEscalationGuardConfig()
        self._max_autonomy_level = cfg.max_autonomy_level
        self._base_autonomy_level = cfg.base_autonomy_level
        self._detect_self_modification = cfg.detect_self_modification
        self._control_sub_agents = cfg.control_sub_agents
        self._max_sub_agents = cfg.max_sub_agents
        self._escalation_required_actions = list(cfg.escalation_required_actions)
        self._enforce_capability_boundaries = cfg.enforce_capability_boundaries
        self._capability_levels: Dict[int, List[str]] = (
            dict(cfg.capability_levels) if cfg.capability_levels else dict(DEFAULT_CAPABILITY_LEVELS)
        )
        self._enforce_hitl = cfg.enforce_hitl
        self._always_require_human = list(cfg.always_require_human)

        self._agent_states: Dict[str, AgentCapabilities] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        action: str,
        session_id: str,
        params: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> AutonomyEscalationResult:
        req_id = request_id or f"auto-{_now_ms()}"
        violations: List[str] = []
        escalation_patterns: List[str] = []

        state = self._agent_states.get(session_id)
        if not state:
            state = self._create_agent_state()
            self._agent_states[session_id] = state

        capability_violation = False
        self_modification_detected = False
        sub_agent_limit_exceeded = False
        hitl_required = False
        requires_approval = False
        approval_type: Optional[str] = None

        # 1. Check for escalation patterns in action/params
        text_to_check = f"{action} {json.dumps(params or {})}"
        for pat in self.ESCALATION_PATTERNS:
            if pat.pattern.search(text_to_check):
                escalation_patterns.append(pat.name)
                if pat.severity >= 80:
                    violations.append(f"escalation_pattern: {pat.name}")
                if "modify" in pat.name or "change" in pat.name or "disable" in pat.name:
                    self_modification_detected = True

        # 2. Check if action requires escalation approval
        if action in self._escalation_required_actions:
            requires_approval = True
            approval_type = "admin"
            violations.append(f"escalation_required: {action}")

        # 3. Check capability boundaries
        if self._enforce_capability_boundaries:
            allowed_capabilities = self._get_capabilities_for_level(state.autonomy_level)
            if action not in allowed_capabilities and action not in state.capabilities:
                capability_violation = True
                violations.append(f"capability_violation: {action} not allowed at level {state.autonomy_level}")
                requires_approval = True
                approval_type = "admin"

        # 4. Check for self-modification attempts
        if self._detect_self_modification and self_modification_detected:
            violations.append("self_modification_attempt")
            requires_approval = True
            approval_type = "human"

        # 5. Check sub-agent limits
        if self._control_sub_agents:
            if action == "spawn_agent" or any(
                p in ("spawn_agent", "fork_agent", "create_copy")
                for p in escalation_patterns
            ):
                if len(state.sub_agents) >= self._max_sub_agents:
                    sub_agent_limit_exceeded = True
                    violations.append(
                        f"sub_agent_limit_exceeded: {len(state.sub_agents)}/{self._max_sub_agents}"
                    )
                else:
                    requires_approval = True
                    approval_type = "human"

        # 6. Check HITL enforcement
        if self._enforce_hitl:
            if action in self._always_require_human:
                hitl_required = True
                requires_approval = True
                approval_type = "human"

        # 7. Check for autonomy level escalation in params
        if params and params.get("autonomy_level") is not None:
            requested_level = int(params["autonomy_level"])
            if requested_level > state.autonomy_level:
                violations.append(
                    f"autonomy_level_escalation: {state.autonomy_level} -> {requested_level}"
                )
                requires_approval = True
                approval_type = "admin"
            if requested_level > self._max_autonomy_level:
                violations.append(
                    f"autonomy_level_exceeds_max: {requested_level} > {self._max_autonomy_level}"
                )

        # Determine if action should be blocked
        high_severity_patterns = [
            p for p in escalation_patterns
            if any(ep.name == p and ep.severity >= 85 for ep in self.ESCALATION_PATTERNS)
        ]

        blocked = (
            (self_modification_detected and self._detect_self_modification)
            or sub_agent_limit_exceeded
            or capability_violation
            or len(violations) >= 3
            or len(high_severity_patterns) >= 1
            or (requires_approval and action in self._escalation_required_actions)
        )

        return AutonomyEscalationResult(
            allowed=not blocked,
            reason=(
                f"Autonomy escalation blocked: {', '.join(violations[:3])}"
                if blocked
                else (
                    "Action requires approval"
                    if requires_approval
                    else "Action validated"
                )
            ),
            violations=violations,
            request_id=req_id,
            analysis=AutonomyAnalysis(
                current_autonomy_level=state.autonomy_level,
                requested_autonomy_level=params.get("autonomy_level") if params else None,
                capability_violation=capability_violation,
                self_modification_detected=self_modification_detected,
                sub_agent_limit_exceeded=sub_agent_limit_exceeded,
                hitl_required=hitl_required,
                escalation_patterns_detected=escalation_patterns,
            ),
            requires_approval=requires_approval,
            approval_type=approval_type,
            recommendations=self._generate_recommendations(violations, state.autonomy_level, requires_approval),
        )

    def request_escalation(
        self,
        session_id: str,
        request_type: str,
        source: str,
        requested_capability: Optional[str] = None,
        requested_level: Optional[int] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AutonomyEscalationResult:
        req_id = f"esc-{_now_ms()}"
        violations: List[str] = []

        state = self._agent_states.get(session_id)
        if not state:
            state = self._create_agent_state()
            self._agent_states[session_id] = state

        full_request = AutonomyRequest(
            request_id=req_id,
            request_type=request_type,
            source=source,
            timestamp=_now_ms(),
            requested_capability=requested_capability,
            requested_level=requested_level,
            reason=reason,
            metadata=metadata,
        )

        # Check if similar request was recently denied
        recent_denial = None
        for r in state.denied_requests:
            if (
                r.request_type == request_type
                and r.requested_capability == requested_capability
                and _now_ms() - r.timestamp < 5 * 60 * 1000
            ):
                recent_denial = r
                break

        if recent_denial:
            violations.append("repeated_denied_request")
            return AutonomyEscalationResult(
                allowed=False,
                reason="Similar request was recently denied",
                violations=violations,
                request_id=req_id,
                analysis=AutonomyAnalysis(
                    current_autonomy_level=state.autonomy_level,
                    requested_autonomy_level=requested_level,
                    capability_violation=False,
                    self_modification_detected=(request_type == "self_modify"),
                    sub_agent_limit_exceeded=False,
                    hitl_required=True,
                    escalation_patterns_detected=[],
                ),
                requires_approval=False,
                recommendations=["Wait before retrying escalation request", "Provide additional justification"],
            )

        blocked = False
        approval_type: str = "admin"

        if request_type == "self_modify":
            blocked = True
            violations.append("self_modification_blocked")

        elif request_type == "level_increase":
            if requested_level is not None:
                if requested_level > self._max_autonomy_level:
                    blocked = True
                    violations.append("exceeds_max_autonomy_level")
                elif requested_level > state.autonomy_level + 25:
                    violations.append("large_autonomy_jump")
                    approval_type = "human"

        elif request_type == "spawn_agent":
            if len(state.sub_agents) >= self._max_sub_agents:
                blocked = True
                violations.append("sub_agent_limit_reached")
            else:
                approval_type = "human"

        elif request_type == "capability_expansion":
            approval_type = "admin"

        elif request_type == "bypass_hitl":
            blocked = True
            violations.append("hitl_bypass_not_allowed")

        elif request_type == "persist_state":
            approval_type = "human"

        # Add to pending or denied requests
        if blocked:
            state.denied_requests.append(full_request)
            if len(state.denied_requests) > 10:
                state.denied_requests.pop(0)
        else:
            state.pending_requests.append(full_request)

        self._agent_states[session_id] = state

        return AutonomyEscalationResult(
            allowed=not blocked,
            reason=(
                f"Escalation request denied: {', '.join(violations)}"
                if blocked
                else "Escalation request pending approval"
            ),
            violations=violations,
            request_id=req_id,
            analysis=AutonomyAnalysis(
                current_autonomy_level=state.autonomy_level,
                requested_autonomy_level=requested_level,
                capability_violation=False,
                self_modification_detected=(request_type == "self_modify"),
                sub_agent_limit_exceeded=(len(state.sub_agents) >= self._max_sub_agents),
                hitl_required=True,
                escalation_patterns_detected=[],
            ),
            requires_approval=not blocked,
            approval_type=approval_type,
            recommendations=self._generate_recommendations(violations, state.autonomy_level, not blocked),
        )

    def approve_escalation(self, session_id: str, request_id: str) -> bool:
        state = self._agent_states.get(session_id)
        if not state:
            return False

        request_index = None
        for i, r in enumerate(state.pending_requests):
            if r.request_id == request_id:
                request_index = i
                break

        if request_index is None:
            return False

        request = state.pending_requests.pop(request_index)

        if request.request_type == "level_increase":
            if request.requested_level is not None:
                state.autonomy_level = min(request.requested_level, self._max_autonomy_level)

        elif request.request_type == "capability_expansion":
            if request.requested_capability:
                state.capabilities.add(request.requested_capability)

        elif request.request_type == "spawn_agent":
            if request.metadata and request.metadata.get("agent_id"):
                state.sub_agents.append(request.metadata["agent_id"])

        state.last_capability_change = _now_ms()
        state.hitl_checkpoints += 1
        self._agent_states[session_id] = state
        return True

    def deny_escalation(self, session_id: str, request_id: str) -> bool:
        state = self._agent_states.get(session_id)
        if not state:
            return False

        request_index = None
        for i, r in enumerate(state.pending_requests):
            if r.request_id == request_id:
                request_index = i
                break

        if request_index is None:
            return False

        request = state.pending_requests.pop(request_index)
        state.denied_requests.append(request)

        state.autonomy_level = max(0, state.autonomy_level - 5)
        self._agent_states[session_id] = state
        return True

    def register_sub_agent(self, session_id: str, sub_agent_id: str) -> bool:
        state = self._agent_states.get(session_id)
        if not state:
            state = self._create_agent_state()
            self._agent_states[session_id] = state

        if len(state.sub_agents) >= self._max_sub_agents:
            return False

        state.sub_agents.append(sub_agent_id)
        self._agent_states[session_id] = state
        return True

    def get_agent_state(self, session_id: str) -> Optional[AgentCapabilities]:
        return self._agent_states.get(session_id)

    def set_autonomy_level(self, session_id: str, level: int) -> None:
        state = self._agent_states.get(session_id)
        if not state:
            state = self._create_agent_state()
        state.autonomy_level = min(level, self._max_autonomy_level)
        state.last_capability_change = _now_ms()
        self._agent_states[session_id] = state

    def reset_session(self, session_id: str) -> None:
        self._agent_states.pop(session_id, None)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _create_agent_state(self) -> AgentCapabilities:
        return AgentCapabilities(
            capabilities=set(self._get_capabilities_for_level(self._base_autonomy_level)),
            autonomy_level=self._base_autonomy_level,
            sub_agents=[],
            pending_requests=[],
            denied_requests=[],
            last_capability_change=_now_ms(),
            hitl_checkpoints=0,
        )

    def _get_capabilities_for_level(self, level: int) -> List[str]:
        levels = sorted(
            [l for l in self._capability_levels if l <= level],
            reverse=True,
        )
        if not levels:
            return []
        return self._capability_levels.get(levels[0], [])

    def _generate_recommendations(
        self,
        violations: List[str],
        autonomy_level: int,
        requires_approval: bool,
    ) -> List[str]:
        recommendations: List[str] = []

        if any("self_modification" in v for v in violations):
            recommendations.append("Self-modification is not allowed - use approved update channels")
        if any("capability_violation" in v for v in violations):
            recommendations.append("Request capability expansion through proper escalation process")
        if any("sub_agent" in v for v in violations):
            recommendations.append("Sub-agent limit reached - terminate existing agents before spawning new ones")
        if any("autonomy_level" in v for v in violations):
            recommendations.append("Request autonomy increase through formal escalation process")
        if requires_approval:
            recommendations.append("Wait for human/admin approval before proceeding")
        if autonomy_level < 50:
            recommendations.append("Build trust through successful operations to increase autonomy level")

        if not recommendations:
            recommendations.append("Continue operating within current capability boundaries")

        return recommendations
