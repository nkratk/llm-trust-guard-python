"""
L3 Policy Gate

Enforces role-based access control with constraint validation.
The definitive layer for authorization decisions.

Port of the TypeScript PolicyGate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable

LoggerFn = Optional[Callable[[str, str], None]]


@dataclass
class ToolDefinition:
    name: str
    description: str = ""
    roles: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    constraints: Optional[Dict[str, Any]] = None


@dataclass
class SessionContext:
    authenticated: bool = False
    role: str = ""
    tenant_id: str = ""
    user_id: str = ""


@dataclass
class PolicyGateResult:
    allowed: bool
    violations: List[str]
    session_role: str
    required_roles: List[str]
    reason: Optional[str] = None
    constraint_violations: Optional[List[str]] = None


@dataclass
class PolicyGateConfig:
    role_hierarchy: Optional[Dict[str, int]] = None
    tool_permissions: Optional[Dict[str, Dict[str, Any]]] = None
    logger: LoggerFn = None


class PolicyGate:
    """L3 Policy Gate - enforces RBAC with constraint validation."""

    def __init__(self, config: Optional[PolicyGateConfig] = None) -> None:
        config = config or PolicyGateConfig()
        self._role_hierarchy: Dict[str, int] = config.role_hierarchy or {}
        self._tool_permissions: Dict[str, Dict[str, Any]] = config.tool_permissions or {}
        self._logger: Callable[[str, str], None] = config.logger or (lambda _m, _l: None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_session(
        self,
        session: Optional[SessionContext],
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Validate session is authentic."""
        if session is None:
            if request_id:
                self._logger(f"[L3:{request_id}] BLOCKED: No session", "info")
            return {"valid": False, "error": "Missing session context"}

        if not session.authenticated:
            if request_id:
                self._logger(f"[L3:{request_id}] BLOCKED: Not authenticated", "info")
            return {"valid": False, "error": "Session not authenticated"}

        if not session.role:
            if request_id:
                self._logger(f"[L3:{request_id}] BLOCKED: No role in session", "info")
            return {"valid": False, "error": "Missing role in session"}

        return {"valid": True}

    def detect_role_tampering(
        self,
        session: SessionContext,
        claimed_role: Optional[str],
    ) -> Dict[str, Any]:
        """Detect role tampering (claimed vs session role)."""
        if claimed_role is None:
            return {"tampered": False, "actual": session.role}

        if claimed_role != session.role:
            return {"tampered": True, "actual": session.role, "claimed": claimed_role}

        return {"tampered": False, "actual": session.role}

    def check_tool_access(
        self,
        tool: ToolDefinition,
        session: SessionContext,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Check tool access for a session."""
        if not tool.roles:
            return {"allowed": True}

        if session.role not in tool.roles:
            # Check hierarchy if defined
            session_role_level = self._role_hierarchy.get(session.role, -1)
            has_higher_role = any(
                session_role_level >= self._role_hierarchy.get(r, -1) >= 0
                for r in tool.roles
            )

            if not has_higher_role:
                if request_id:
                    self._logger(
                        f"[L3:{request_id}] BLOCKED: Role '{session.role}' cannot use '{tool.name}'",
                        "info",
                    )
                return {
                    "allowed": False,
                    "reason": f"Role '{session.role}' is not authorized for tool '{tool.name}'",
                }

        return {"allowed": True}

    def check_constraints(
        self,
        tool: ToolDefinition,
        params: Dict[str, Any],
        session: SessionContext,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Check constraints for a tool call."""
        violations: List[str] = []

        if not tool.constraints:
            return {"valid": True, "violations": []}

        role_constraints = tool.constraints.get(session.role)
        if not role_constraints:
            return {"valid": True, "violations": []}

        # Check max_amount
        max_amount = role_constraints.get("max_amount")
        if max_amount is not None:
            amount = params.get("amount") or params.get("total_amount")
            if amount is not None and amount > max_amount:
                violations.append(
                    f"Amount {amount} exceeds limit of {max_amount} for role '{session.role}'"
                )
                if request_id:
                    self._logger(f"[L3:{request_id}] CONSTRAINT: Amount exceeds limit", "info")

        # Check require_approval
        if role_constraints.get("require_approval") and not params.get("approval_id"):
            violations.append(f"Tool '{tool.name}' requires approval for role '{session.role}'")
            if request_id:
                self._logger(f"[L3:{request_id}] CONSTRAINT: Requires approval", "info")

        # Check allowed_values
        allowed_values = role_constraints.get("allowed_values")
        if allowed_values:
            for field_name, allowed_vals in allowed_values.items():
                if params.get(field_name) and params[field_name] not in allowed_vals:
                    violations.append(
                        f"Value '{params[field_name]}' not allowed for field '{field_name}'"
                    )

        return {"valid": len(violations) == 0, "violations": violations}

    def check(
        self,
        tool: ToolDefinition,
        params: Dict[str, Any],
        session: Optional[SessionContext],
        claimed_role: Optional[str],
        request_id: str = "",
    ) -> PolicyGateResult:
        """Complete policy check."""
        # Validate session
        session_check = self.validate_session(session, request_id)
        if not session_check["valid"]:
            return PolicyGateResult(
                allowed=False,
                reason=session_check.get("error"),
                violations=["INVALID_SESSION"],
                session_role="",
                required_roles=tool.roles or [],
            )

        valid_session = session  # type: ignore[assignment]
        assert valid_session is not None

        # Detect tampering
        tamper_check = self.detect_role_tampering(valid_session, claimed_role)
        violations: List[str] = []

        if tamper_check["tampered"]:
            violations.append("ROLE_TAMPERING")
            if request_id:
                self._logger(f"[L3:{request_id}] ALERT: Role tampering detected", "info")
                self._logger(
                    f"[L3:{request_id}]   Claimed: {tamper_check['claimed']}, Actual: {tamper_check['actual']}",
                    "info",
                )

        # Check tool access (using SESSION role)
        access_check = self.check_tool_access(tool, valid_session, request_id)
        if not access_check["allowed"]:
            return PolicyGateResult(
                allowed=False,
                reason=access_check.get("reason"),
                violations=[*violations, "UNAUTHORIZED_TOOL"],
                session_role=valid_session.role,
                required_roles=tool.roles or [],
            )

        # Check constraints
        constraint_check = self.check_constraints(tool, params, valid_session, request_id)
        if not constraint_check["valid"]:
            return PolicyGateResult(
                allowed=False,
                reason="Constraint violation",
                violations=[*violations, *constraint_check["violations"]],
                session_role=valid_session.role,
                required_roles=tool.roles or [],
                constraint_violations=constraint_check["violations"],
            )

        if request_id:
            self._logger(f"[L3:{request_id}] Policy check PASSED", "info")

        return PolicyGateResult(
            allowed=True,
            violations=["ROLE_TAMPERING_HANDLED"] if tamper_check["tampered"] else [],
            session_role=valid_session.role,
            required_roles=tool.roles or [],
        )

    def set_role_hierarchy(self, hierarchy: Dict[str, int]) -> None:
        """Set role hierarchy."""
        self._role_hierarchy = hierarchy
