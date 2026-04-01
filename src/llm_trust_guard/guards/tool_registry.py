"""
L2 Tool Registry Guard

Maintains strict control over which tools can be executed.
Prevents LLM hallucination attacks.

Port of the TypeScript ToolRegistry.
"""

from __future__ import annotations

import re
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
class ToolRegistryResult:
    allowed: bool
    violations: List[str]
    hallucination_detected: bool = False
    reason: Optional[str] = None
    tool: Optional[ToolDefinition] = None
    similar_tools: Optional[List[str]] = None


# Common hallucination patterns
HALLUCINATION_PATTERNS = [
    re.compile(r"^execute", re.IGNORECASE),
    re.compile(r"^run", re.IGNORECASE),
    re.compile(r"^shell", re.IGNORECASE),
    re.compile(r"^admin", re.IGNORECASE),
    re.compile(r"^override", re.IGNORECASE),
    re.compile(r"^delete_all", re.IGNORECASE),
    re.compile(r"^export_", re.IGNORECASE),
    re.compile(r"^import_", re.IGNORECASE),
    re.compile(r"^hack", re.IGNORECASE),
    re.compile(r"^bypass", re.IGNORECASE),
    re.compile(r"^sudo", re.IGNORECASE),
    re.compile(r"^root", re.IGNORECASE),
    re.compile(r"^system", re.IGNORECASE),
]

# Valid tool name characters
_VALID_TOOL_NAME = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class ToolRegistryConfig:
    tools: List[ToolDefinition] = field(default_factory=list)
    strict_matching: bool = True
    logger: LoggerFn = None


class ToolRegistry:
    """L2 Tool Registry Guard - validates tool names against a whitelist."""

    def __init__(self, config: ToolRegistryConfig) -> None:
        self._tools: Dict[str, ToolDefinition] = {}
        self._strict_matching = config.strict_matching
        self._logger: Callable[[str, str], None] = config.logger or (lambda _m, _l: None)

        for tool in config.tools:
            self._tools[tool.name] = tool

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        tool_name: str,
        role: str,
        request_id: str = "",
    ) -> ToolRegistryResult:
        """Check if a tool exists and is accessible for the given role."""
        tool = self._tools.get(tool_name)

        if tool is None:
            is_hallucination = self._detect_hallucination(tool_name)
            similar_tools = self._find_similar_tools(tool_name)

            if request_id:
                self._logger(f"[L2:{request_id}] BLOCKED: Tool '{tool_name}' not in registry", "info")
                if is_hallucination:
                    self._logger(f"[L2:{request_id}] ALERT: Potential hallucination detected", "info")

            return ToolRegistryResult(
                allowed=False,
                reason=f"Tool '{tool_name}' is not registered",
                violations=["UNREGISTERED_TOOL"],
                hallucination_detected=is_hallucination,
                similar_tools=similar_tools if similar_tools else None,
            )

        # Check role access if roles are defined
        if tool.roles and role not in tool.roles:
            if request_id:
                self._logger(f"[L2:{request_id}] BLOCKED: Role '{role}' cannot use '{tool_name}'", "info")

            return ToolRegistryResult(
                allowed=False,
                reason=f"Role '{role}' is not authorized for tool '{tool_name}'",
                violations=["UNAUTHORIZED_ROLE"],
                tool=tool,
                hallucination_detected=False,
            )

        if request_id:
            self._logger(f"[L2:{request_id}] Tool '{tool_name}' ALLOWED for role '{role}'", "info")

        return ToolRegistryResult(
            allowed=True,
            violations=[],
            tool=tool,
            hallucination_detected=False,
        )

    def get_tools_for_role(self, role: str) -> List[ToolDefinition]:
        """Get tools accessible by a specific role."""
        result: List[ToolDefinition] = []
        for tool in self._tools.values():
            if not tool.roles or role in tool.roles:
                result.append(tool)
        return result

    def get_registered_tool_names(self) -> List[str]:
        """Get all registered tool names."""
        return list(self._tools.keys())

    def register_tool(self, tool: ToolDefinition) -> None:
        """Register a new tool at runtime."""
        self._tools[tool.name] = tool

    def unregister_tool(self, tool_name: str) -> bool:
        """Unregister a tool. Returns True if it existed."""
        if tool_name in self._tools:
            del self._tools[tool_name]
            return True
        return False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_hallucination(self, tool_name: str) -> bool:
        """Detect if a tool name looks like a hallucination."""
        for pattern in HALLUCINATION_PATTERNS:
            if pattern.search(tool_name):
                return True

        # Suspicious characters
        if ".." in tool_name or "/" in tool_name or "\\" in tool_name:
            return True

        # Unusually long names
        if len(tool_name) > 50:
            return True

        # Special characters
        if not _VALID_TOOL_NAME.match(tool_name):
            return True

        return False

    def _find_similar_tools(self, tool_name: str) -> List[str]:
        """Find similar registered tools for helpful error messages."""
        similar: List[str] = []
        tool_name_lower = tool_name.lower()

        for registered_tool in self._tools:
            registered_lower = registered_tool.lower()
            requested_words = re.split(r"[_-]", tool_name_lower)
            registered_words = re.split(r"[_-]", registered_lower)

            for word in requested_words:
                if len(word) > 2 and any(
                    rw in word or word in rw for rw in registered_words
                ):
                    similar.append(registered_tool)
                    break

        return list(dict.fromkeys(similar))  # dedupe preserving order
