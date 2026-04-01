"""
L4 Tenant Boundary Guard

Enforces strict multi-tenant isolation.
Prevents cross-tenant data access.

Port of the TypeScript TenantBoundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Callable

LoggerFn = Optional[Callable[[str, str], None]]


@dataclass
class SessionContext:
    authenticated: bool = False
    role: str = ""
    tenant_id: str = ""
    user_id: str = ""


@dataclass
class ResourceOwnership:
    resource_id: str
    tenant_id: str
    resource_type: Optional[str] = None


@dataclass
class TenantBoundaryResult:
    allowed: bool
    violations: List[str]
    session_tenant: str
    reason: Optional[str] = None
    resource_tenant: Optional[str] = None
    enforced_params: Optional[Dict[str, Any]] = None


@dataclass
class TenantBoundaryConfig:
    valid_tenants: Optional[Set[str]] = None
    resource_ownership: Optional[Dict[str, ResourceOwnership]] = None
    resource_id_fields: Optional[List[str]] = None
    list_operations: Optional[List[str]] = None
    logger: LoggerFn = None


_DEFAULT_RESOURCE_ID_FIELDS = [
    "order_id",
    "customer_id",
    "invoice_id",
    "document_id",
    "resource_id",
    "id",
]

_DEFAULT_LIST_OPERATIONS = [
    "list",
    "search",
    "query",
    "find",
    "get_all",
]


class TenantBoundary:
    """L4 Tenant Boundary Guard - enforces multi-tenant isolation."""

    def __init__(self, config: Optional[TenantBoundaryConfig] = None) -> None:
        config = config or TenantBoundaryConfig()
        self._valid_tenants: Set[str] = config.valid_tenants or set()
        self._resource_ownership: Dict[str, ResourceOwnership] = config.resource_ownership or {}
        self._resource_id_fields: List[str] = config.resource_id_fields or list(_DEFAULT_RESOURCE_ID_FIELDS)
        self._list_operations: List[str] = config.list_operations or list(_DEFAULT_LIST_OPERATIONS)
        self._logger: Callable[[str, str], None] = config.logger or (lambda _m, _l: None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_session(
        self,
        session: Optional[SessionContext],
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Validate session has a valid tenant."""
        if session is None:
            return {"valid": False, "error": "Missing session context"}

        if not session.authenticated:
            return {"valid": False, "error": "Session not authenticated"}

        if not session.tenant_id:
            return {"valid": False, "error": "Missing tenant_id in session"}

        # Validate tenant if we have a whitelist
        if self._valid_tenants and session.tenant_id not in self._valid_tenants:
            if request_id:
                self._logger(f"[L4:{request_id}] BLOCKED: Invalid tenant '{session.tenant_id}'", "info")
            return {"valid": False, "error": f"Invalid tenant: {session.tenant_id}"}

        return {"valid": True}

    def check_resource_ownership(
        self,
        resource_id: str,
        session: SessionContext,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Check resource ownership."""
        ownership = self._resource_ownership.get(resource_id)

        if ownership is None:
            # Resource not in registry - allow (tool will return not found)
            return {"allowed": True}

        if ownership.tenant_id != session.tenant_id:
            if request_id:
                self._logger(f"[L4:{request_id}] BLOCKED: Cross-tenant access", "info")
                self._logger(
                    f"[L4:{request_id}]   Session: {session.tenant_id}, Resource: {ownership.tenant_id}",
                    "info",
                )
            return {"allowed": False, "resource_tenant": ownership.tenant_id}

        return {"allowed": True, "resource_tenant": ownership.tenant_id}

    def check_tenant_parameter(
        self,
        params: Dict[str, Any],
        session: SessionContext,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Check if tenant_id parameter matches session."""
        if params.get("tenant_id") and params["tenant_id"] != session.tenant_id:
            if request_id:
                self._logger(f"[L4:{request_id}] BLOCKED: Tenant parameter manipulation", "info")
            return {
                "allowed": False,
                "reason": f"Cannot access tenant {params['tenant_id']} - bound to {session.tenant_id}",
            }

        return {"allowed": True}

    def enforce_tenant_filter(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session: SessionContext,
        request_id: str = "",
    ) -> Dict[str, Any]:
        """Enforce tenant filtering for list operations."""
        is_list_op = any(op in tool_name.lower() for op in self._list_operations)

        if is_list_op:
            # Block if trying to access different tenant
            if params.get("tenant_id") and params["tenant_id"] != session.tenant_id:
                return {
                    "allowed": False,
                    "enforced_params": params,
                    "reason": f"Cannot filter by tenant {params['tenant_id']}",
                }

            # Enforce session tenant
            enforced_params = {**params, "tenant_id": session.tenant_id}

            if request_id:
                self._logger(f"[L4:{request_id}] Enforcing tenant filter: {session.tenant_id}", "info")

            return {"allowed": True, "enforced_params": enforced_params}

        return {"allowed": True, "enforced_params": params}

    def check(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session: Optional[SessionContext],
        request_id: str = "",
    ) -> TenantBoundaryResult:
        """Complete tenant boundary check."""
        # Validate session
        session_check = self.validate_session(session, request_id)
        if not session_check["valid"]:
            return TenantBoundaryResult(
                allowed=False,
                reason=session_check.get("error"),
                violations=["INVALID_SESSION"],
                session_tenant="",
            )

        valid_session = session
        assert valid_session is not None

        # Check tenant parameter manipulation
        param_check = self.check_tenant_parameter(params, valid_session, request_id)
        if not param_check["allowed"]:
            return TenantBoundaryResult(
                allowed=False,
                reason=param_check.get("reason"),
                violations=["TENANT_MANIPULATION"],
                session_tenant=valid_session.tenant_id,
            )

        # Check resource ownership
        for id_field in self._resource_id_fields:
            if params.get(id_field):
                ownership_check = self.check_resource_ownership(
                    params[id_field], valid_session, request_id
                )
                if not ownership_check["allowed"]:
                    return TenantBoundaryResult(
                        allowed=False,
                        reason=f"Resource {params[id_field]} belongs to different tenant",
                        violations=["CROSS_TENANT_ACCESS"],
                        session_tenant=valid_session.tenant_id,
                        resource_tenant=ownership_check.get("resource_tenant"),
                    )

        # Enforce tenant filtering
        filter_check = self.enforce_tenant_filter(tool_name, params, valid_session, request_id)
        if not filter_check["allowed"]:
            return TenantBoundaryResult(
                allowed=False,
                reason=filter_check.get("reason"),
                violations=["TENANT_FILTER_BYPASS"],
                session_tenant=valid_session.tenant_id,
            )

        if request_id:
            self._logger(f"[L4:{request_id}] Tenant boundary check PASSED", "info")

        return TenantBoundaryResult(
            allowed=True,
            violations=[],
            session_tenant=valid_session.tenant_id,
            enforced_params=filter_check.get("enforced_params"),
        )

    def register_resource(
        self,
        resource_id: str,
        tenant_id: str,
        resource_type: Optional[str] = None,
    ) -> None:
        """Register resource ownership."""
        self._resource_ownership[resource_id] = ResourceOwnership(
            resource_id=resource_id,
            tenant_id=tenant_id,
            resource_type=resource_type,
        )

    def add_valid_tenant(self, tenant_id: str) -> None:
        """Add a valid tenant."""
        self._valid_tenants.add(tenant_id)
