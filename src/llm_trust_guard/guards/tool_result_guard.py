"""
ToolResultGuard

Validates tool return values before they flow back into LLM context.
Addresses the #1 attack vector in 2025-2026: tool output poisoning.

Real-world incidents this guard prevents:
- Microsoft Copilot "Copirate" (2025): tool output contained hidden prompt injection
- Supabase Cursor SQL exfiltration (2025): tool returned attacker-controlled data
- WhatsApp MCP exfiltration (2025): tool output used for cross-service data theft
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ToolResultSchema:
    type: str  # "string" | "number" | "boolean" | "object" | "array"
    properties: Optional[Dict[str, Dict[str, Any]]] = None
    max_length: Optional[int] = None


@dataclass
class ToolResultThreat:
    type: str
    severity: str  # "low" | "medium" | "high" | "critical"
    location: str
    detail: str


@dataclass
class ToolResultGuardResult:
    allowed: bool
    violations: List[str]
    injection_detected: bool
    schema_valid: bool
    threats: List[ToolResultThreat]
    reason: Optional[str] = None


@dataclass
class ToolResultGuardConfig:
    expected_schemas: Optional[Dict[str, ToolResultSchema]] = None
    scan_for_injection: bool = True
    max_result_size: int = 50_000
    sensitive_patterns: Optional[List[re.Pattern[str]]] = None
    detect_state_change_claims: bool = True


@dataclass
class _InjectionPattern:
    name: str
    pattern: re.Pattern[str]
    severity: str


@dataclass
class _StateChangePattern:
    name: str
    pattern: re.Pattern[str]


# fmt: off
_RESULT_INJECTION_PATTERNS: List[_InjectionPattern] = [
    _InjectionPattern("system_instruction", re.compile(r"(?:SYSTEM|ADMIN|INSTRUCTION)\s*:", re.I), "critical"),
    _InjectionPattern("ignore_instructions", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules)", re.I), "critical"),
    _InjectionPattern("new_instructions", re.compile(r"new\s+instructions?\s*:", re.I), "critical"),
    _InjectionPattern("role_override", re.compile(r"you\s+are\s+now|from\s+now\s+on|act\s+as\s+(?:a|an)", re.I), "critical"),
    _InjectionPattern("xml_system_tag", re.compile(r"</?system>|</?admin>|\[system\]|\[admin\]", re.I), "critical"),
    _InjectionPattern("jailbreak", re.compile(r"jailbreak|DAN\s*mode|developer\s+mode|unrestricted", re.I), "critical"),
    _InjectionPattern("bypass_safety", re.compile(r"bypass\s+(?:security|safety|filters|restrictions)", re.I), "high"),
    _InjectionPattern("data_exfiltration", re.compile(r"send\s+(?:this|the|all)\s+(?:data|info)\s+to|exfiltrate", re.I), "critical"),
    _InjectionPattern("hidden_instruction", re.compile(r"HIDDEN_PROMPT|HIDDEN_INSTRUCTION|INVISIBLE_TEXT", re.I), "critical"),
    _InjectionPattern("markdown_injection", re.compile(r"!\[.*\]\(https?://[^)]*\?.*(?:token|key|secret|auth)", re.I), "high"),
    # Exfiltration via URL in tool results instructing the LLM
    _InjectionPattern("url_exfiltration", re.compile(r"(?:fetch|request|call|post|get|send|forward|transmit|relay)\s+(?:to|from)?\s*https?://", re.I), "critical"),
    _InjectionPattern("url_data_leak", re.compile(r"https?://[^\s]+\?.*(?:data|prompt|conversation|history|context|message|response)=", re.I), "critical"),
    # Credential solicitation
    _InjectionPattern("credential_solicitation", re.compile(r"(?:ask|request|get|obtain|collect)\s+(?:the\s+)?(?:user|them|him|her)\s+(?:for\s+)?(?:their\s+)?(?:password|credentials?|api[_\s]?key|token|secret|ssn|social\s+security)", re.I), "critical"),
    _InjectionPattern("credential_prompt", re.compile(r"(?:enter|provide|type|input|share)\s+(?:your\s+)?(?:password|credentials?|api[_\s]?key|auth(?:entication)?\s+token|private\s+key|secret)", re.I), "high"),
    # Imperative tool call injection
    _InjectionPattern("tool_call_injection", re.compile(r"(?:execute|invoke|call|run|trigger|use)\s+(?:the\s+)?(?:function|tool|command|action)\s+(?:named?\s+)?[`\"']?\w+[`\"']?", re.I), "critical"),
    _InjectionPattern("tool_chain_manipulation", re.compile(r"(?:first|then|next|now)\s+(?:execute|call|run|invoke|delete|drop|remove|wipe)\s+", re.I), "high"),
]
# fmt: on

_STATE_CHANGE_PATTERNS: List[_StateChangePattern] = [
    _StateChangePattern("privilege_claim", re.compile(r"(?:user|role|permission)\s+(?:is\s+now|changed\s+to|promoted\s+to|set\s+to)\s+(?:admin|root|superuser)", re.I)),
    _StateChangePattern("auth_claim", re.compile(r"(?:authenticated|authorized|verified)\s+as\s+(?:admin|root|superuser)", re.I)),
    _StateChangePattern("approval_claim", re.compile(r"(?:approved|granted|authorized)\s+(?:without|bypassing)\s+(?:verification|approval|review)", re.I)),
    _StateChangePattern("config_change_claim", re.compile(r"(?:configuration|settings?|policy)\s+(?:updated|changed|modified)\s+(?:to|:)", re.I)),
    _StateChangePattern("role_upgrade_claim", re.compile(r"(?:role|access|privilege)\s+(?:upgraded|elevated|escalated|promoted)\s+(?:to|successfully)", re.I)),
    _StateChangePattern("permissions_granted_claim", re.compile(r"(?:permissions?|access)\s+(?:granted|unlocked|enabled|activated)\s+(?:for|to|successfully|without)", re.I)),
]


class ToolResultGuard:
    """Validates tool return values before they flow back into LLM context."""

    def __init__(self, config: Optional[ToolResultGuardConfig] = None) -> None:
        self._config = config or ToolResultGuardConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_result(
        self,
        tool_name: str,
        result: Any,
        request_id: Optional[str] = None,
    ) -> ToolResultGuardResult:
        """Validate a tool's return value before feeding it back to the LLM."""
        violations: List[str] = []
        threats: List[ToolResultThreat] = []
        injection_detected = False
        schema_valid = True

        # Size check
        result_str = result if isinstance(result, str) else self._safe_stringify(result)
        if len(result_str) > self._config.max_result_size:
            violations.append("RESULT_TOO_LARGE")
            threats.append(ToolResultThreat(
                type="size_exceeded",
                severity="high",
                location="root",
                detail=f"Result size {len(result_str)} exceeds max {self._config.max_result_size}",
            ))

        # Schema validation
        if self._config.expected_schemas and tool_name in self._config.expected_schemas:
            schema_result = self._validate_schema(result, self._config.expected_schemas[tool_name])
            if not schema_result["valid"]:
                schema_valid = False
                violations.append("SCHEMA_MISMATCH")
                for e in schema_result["errors"]:
                    threats.append(ToolResultThreat(
                        type="schema_violation",
                        severity="high",
                        location=e["path"],
                        detail=e["message"],
                    ))

        # Injection scanning
        if self._config.scan_for_injection:
            inj_result = self.scan_for_injection(result)
            if inj_result["detected"]:
                injection_detected = True
                violations.append("INJECTION_IN_TOOL_RESULT")
                threats.extend(inj_result["threats"])

        # State change claim detection
        if self._config.detect_state_change_claims:
            state_result = self._detect_state_change_claims(result_str)
            if state_result["detected"]:
                violations.append("STATE_CHANGE_CLAIM")
                threats.extend(state_result["threats"])

        # Custom sensitive patterns
        if self._config.sensitive_patterns:
            for pattern in self._config.sensitive_patterns:
                if pattern.search(result_str):
                    violations.append("SENSITIVE_PATTERN_MATCH")
                    threats.append(ToolResultThreat(
                        type="sensitive_content",
                        severity="high",
                        location="root",
                        detail=f"Matched sensitive pattern: {pattern.pattern[:50]}",
                    ))

        allowed = len(violations) == 0
        return ToolResultGuardResult(
            allowed=allowed,
            reason=None if allowed else f"Tool result validation failed: {', '.join(violations)}",
            violations=violations,
            injection_detected=injection_detected,
            schema_valid=schema_valid,
            threats=threats,
        )

    def scan_for_injection(
        self, value: Any, path: str = "root"
    ) -> Dict[str, Any]:
        """Scan any value (string, object, list) for injection patterns."""
        threats: List[ToolResultThreat] = []

        if isinstance(value, str):
            for ip in _RESULT_INJECTION_PATTERNS:
                if ip.pattern.search(value):
                    threats.append(ToolResultThreat(
                        type=f"injection_{ip.name}",
                        severity=ip.severity,
                        location=path,
                        detail=f"Injection pattern '{ip.name}' detected in tool result",
                    ))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                sub = self.scan_for_injection(item, f"{path}[{i}]")
                threats.extend(sub["threats"])
        elif isinstance(value, dict):
            for key, val in value.items():
                sub = self.scan_for_injection(val, f"{path}.{key}")
                threats.extend(sub["threats"])

        return {"detected": len(threats) > 0, "threats": threats}

    def register_schema(self, tool_name: str, schema: ToolResultSchema) -> None:
        """Register expected schema for a tool."""
        if self._config.expected_schemas is None:
            self._config.expected_schemas = {}
        self._config.expected_schemas[tool_name] = schema

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_state_change_claims(self, text: str) -> Dict[str, Any]:
        threats: List[ToolResultThreat] = []
        for sp in _STATE_CHANGE_PATTERNS:
            if sp.pattern.search(text):
                threats.append(ToolResultThreat(
                    type=f"state_change_{sp.name}",
                    severity="critical",
                    location="root",
                    detail=f"Tool result claims state change: {sp.name}",
                ))
        return {"detected": len(threats) > 0, "threats": threats}

    def _validate_schema(
        self, value: Any, schema: ToolResultSchema
    ) -> Dict[str, Any]:
        errors: List[Dict[str, str]] = []

        actual_type = self._python_type_name(value)
        if actual_type != schema.type:
            errors.append({"path": "root", "message": f"Expected type '{schema.type}', got '{actual_type}'"})
            return {"valid": False, "errors": errors}

        if schema.type == "string" and schema.max_length and len(value) > schema.max_length:
            errors.append({"path": "root", "message": f"String length exceeds max {schema.max_length}"})

        if schema.type == "object" and schema.properties:
            for key, prop in schema.properties.items():
                if prop.get("required") and (key not in value or value[key] is None):
                    errors.append({"path": key, "message": f"Missing required field '{key}'"})
                if key in value and value[key] is not None:
                    exp_type = prop.get("type", "")
                    act_type = self._python_type_name(value[key])
                    if act_type != exp_type:
                        errors.append({"path": key, "message": f"Field '{key}' expected '{exp_type}', got '{act_type}'"})

        return {"valid": len(errors) == 0, "errors": errors}

    @staticmethod
    def _python_type_name(value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int) or isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, list):
            return "array"
        if isinstance(value, dict):
            return "object"
        return type(value).__name__

    @staticmethod
    def _safe_stringify(value: Any) -> str:
        try:
            return json.dumps(value)
        except (TypeError, ValueError):
            return str(value)
