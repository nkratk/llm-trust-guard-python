"""
OutputSchemaGuard

Validates LLM structured outputs (JSON, function calls) before they
reach downstream systems (databases, APIs, UIs).

Addresses OWASP LLM05: Improper Output Handling.

Why: LLMs can produce structured outputs containing:
- Unexpected actions ("delete_all" instead of "search")
- Injection in JSON values flowing to downstream parsers
- Hallucinated function calls that don't match available tools
- Hidden instructions in field values for downstream systems
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class OutputSchema:
    type: str  # "object" | "array" | "string"
    properties: Optional[Dict[str, Dict[str, Any]]] = None
    required: Optional[List[str]] = None


@dataclass
class OutputThreat:
    field: str
    type: str
    detail: str


@dataclass
class OutputSchemaResult:
    allowed: bool
    violations: List[str]
    schema_valid: bool
    injection_found: bool
    threats: List[OutputThreat]
    reason: Optional[str] = None


@dataclass
class OutputSchemaGuardConfig:
    schemas: Optional[Dict[str, OutputSchema]] = None
    scan_for_injection: bool = True
    strict_schema: bool = False
    max_output_size: int = 100_000


@dataclass
class _InjectionPattern:
    name: str
    pattern: re.Pattern[str]


# fmt: off
_OUTPUT_INJECTION_PATTERNS: List[_InjectionPattern] = [
    _InjectionPattern("sql_injection", re.compile(r"\b(?:DROP|DELETE|INSERT|UPDATE|ALTER)\s+(?:TABLE|FROM|INTO|SET)\b", re.I)),
    _InjectionPattern("command_injection", re.compile(r";\s*(?:rm|cat|wget|curl|bash|sh|python)\b", re.I)),
    _InjectionPattern("xss", re.compile(r"<script|javascript:|on\w+\s*=", re.I)),
    _InjectionPattern("prompt_injection", re.compile(r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|above)", re.I)),
    _InjectionPattern("system_override", re.compile(r"(?:SYSTEM|ADMIN)\s*:|</?system>|\[system\]", re.I)),
    _InjectionPattern("path_traversal", re.compile(r"\.\./", re.I)),
    _InjectionPattern("url_exfiltration", re.compile(r"https?://[^\s]+\?(?:.*(?:token|key|secret|password|auth))", re.I)),
]
# fmt: on


class OutputSchemaGuard:
    """Validates LLM structured outputs before they reach downstream systems."""

    def __init__(self, config: Optional[OutputSchemaGuardConfig] = None) -> None:
        self._config = config or OutputSchemaGuardConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        output: Any,
        schema_name: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> OutputSchemaResult:
        """Validate LLM structured output."""
        violations: List[str] = []
        threats: List[OutputThreat] = []
        schema_valid = True
        injection_found = False

        # Size check
        output_str = self._safe_stringify(output)
        if len(output_str) > self._config.max_output_size:
            violations.append("OUTPUT_TOO_LARGE")

        # Schema validation
        if schema_name and self._config.schemas and schema_name in self._config.schemas:
            schema = self._config.schemas[schema_name]
            schema_errors = self._validate_against_schema(output, schema)
            if schema_errors:
                schema_valid = False
                violations.append("SCHEMA_VIOLATION")
                for e in schema_errors:
                    threats.append(OutputThreat(field=e["field"], type="schema", detail=e["message"]))

        # Injection scanning
        if self._config.scan_for_injection:
            inj_results = self._scan_for_injection(output)
            if inj_results:
                injection_found = True
                violations.append("INJECTION_IN_OUTPUT")
                threats.extend(inj_results)

        allowed = len(violations) == 0
        return OutputSchemaResult(
            allowed=allowed,
            reason=None if allowed else f"Output validation failed: {', '.join(violations)}",
            violations=violations,
            schema_valid=schema_valid,
            injection_found=injection_found,
            threats=threats,
        )

    def validate_function_call(
        self,
        function_name: str,
        args: Dict[str, Any],
        request_id: Optional[str] = None,
    ) -> OutputSchemaResult:
        """Validate a function/tool call output from LLM."""
        return self.validate(args, function_name, request_id)

    def register_schema(self, name: str, schema: OutputSchema) -> None:
        """Register a schema for an action/function."""
        if self._config.schemas is None:
            self._config.schemas = {}
        self._config.schemas[name] = schema

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_against_schema(
        self, output: Any, schema: OutputSchema
    ) -> List[Dict[str, str]]:
        errors: List[Dict[str, str]] = []

        if schema.type == "object" and isinstance(output, dict):
            # Check required fields
            for f in (schema.required or []):
                if f not in output or output[f] is None:
                    errors.append({"field": f, "message": f"Missing required field '{f}'"})

            # Check field types and constraints
            if schema.properties:
                for f, prop in schema.properties.items():
                    if f in output and output[f] is not None:
                        actual_type = self._python_type_name(output[f])
                        expected_type = prop.get("type", "")
                        if actual_type != expected_type:
                            errors.append({"field": f, "message": f"Expected '{expected_type}', got '{actual_type}'"})
                        enum_vals = prop.get("enum")
                        if enum_vals and output[f] not in enum_vals:
                            errors.append({"field": f, "message": f"Value '{output[f]}' not in allowed values: {', '.join(enum_vals)}"})
                        max_len = prop.get("maxLength") or prop.get("max_length")
                        if max_len and isinstance(output[f], str) and len(output[f]) > max_len:
                            errors.append({"field": f, "message": f"Exceeds max length {max_len}"})

                # Strict schema: reject unexpected fields
                if self._config.strict_schema:
                    for key in output:
                        if key not in schema.properties:
                            errors.append({"field": key, "message": f"Unexpected field '{key}' not in schema"})

        elif schema.type != self._python_type_name(output):
            errors.append({"field": "root", "message": f"Expected type '{schema.type}', got '{type(output).__name__}'"})

        return errors

    def _scan_for_injection(
        self, value: Any, path: str = "root"
    ) -> List[OutputThreat]:
        threats: List[OutputThreat] = []

        if isinstance(value, str):
            for ip in _OUTPUT_INJECTION_PATTERNS:
                if ip.pattern.search(value):
                    threats.append(OutputThreat(
                        field=path,
                        type=f"injection_{ip.name}",
                        detail=f"Pattern '{ip.name}' found in output field '{path}'",
                    ))
        elif isinstance(value, list):
            for i, item in enumerate(value):
                threats.extend(self._scan_for_injection(item, f"{path}[{i}]"))
        elif isinstance(value, dict):
            for key, val in value.items():
                threats.extend(self._scan_for_injection(val, f"{path}.{key}"))

        return threats

    @staticmethod
    def _python_type_name(value: Any) -> str:
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, (int, float)):
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
