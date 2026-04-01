"""
L5 Schema Validator

Validates tool parameters against schemas.
Detects injection attacks and type coercion.

Port of the TypeScript SchemaValidator.
"""

from __future__ import annotations

import math
import re
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Callable

LoggerFn = Optional[Callable[[str, str], None]]


@dataclass
class SchemaProperty:
    type: str
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min: Optional[float] = None
    max: Optional[float] = None
    enum: Optional[List[str]] = None
    pattern: Optional[str] = None
    properties: Optional[Dict[str, Any]] = None
    required: Optional[List[str]] = None


@dataclass
class ToolDefinition:
    name: str
    description: str = ""
    roles: List[str] = field(default_factory=list)
    parameters: Optional[Dict[str, Any]] = None
    constraints: Optional[Dict[str, Any]] = None


@dataclass
class SchemaValidatorResult:
    allowed: bool
    violations: List[str]
    errors: List[str]
    warnings: List[str]
    sanitized_params: Dict[str, Any]
    blocked_attacks: List[str]
    reason: Optional[str] = None


# Injection patterns
INJECTION_PATTERNS: Dict[str, List[re.Pattern[str]]] = {
    "SQL": [
        re.compile(
            r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b.*?(--|;|/\*)",
            re.IGNORECASE,
        ),
        re.compile(r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b", re.IGNORECASE),
        re.compile(r"(\bOR\b|\bAND\b)\s*\d+\s*=\s*\d+", re.IGNORECASE),
    ],
    "NOSQL": [
        re.compile(r"\$where|\$regex|\$ne|\$gt|\$lt|\$nin|\$or|\$and", re.IGNORECASE),
        re.compile(r"\{\s*['\"]\\$[a-z]+['\"]\s*:", re.IGNORECASE),
    ],
    "PATH_TRAVERSAL": [
        re.compile(r"\.\./"),
        re.compile(r"\.\.\\"),
        re.compile(r"^/etc/", re.IGNORECASE),
        re.compile(r"^/root/", re.IGNORECASE),
        re.compile(r"%2e%2e%2f", re.IGNORECASE),
    ],
    "COMMAND": [
        re.compile(
            r";\s*\b(cat|ls|rm|wget|curl|nc|bash|sh|python|chmod|chown)\b",
            re.IGNORECASE,
        ),
        re.compile(r"\|\s*\b(sh|bash|cat|nc)\b", re.IGNORECASE),
        re.compile(r"`[^`]+`"),
        re.compile(r"\$\([^)]+\)"),
    ],
    "XSS": [
        re.compile(r"<script", re.IGNORECASE),
        re.compile(r"javascript:", re.IGNORECASE),
        re.compile(r"on\w+\s*=", re.IGNORECASE),
    ],
}

# Dangerous object keys
DANGEROUS_KEYS = frozenset([
    "__proto__",
    "constructor",
    "prototype",
    "__defineGetter__",
    "__defineSetter__",
])


@dataclass
class SchemaValidatorConfig:
    strict_types: bool = True
    detect_injection: bool = True
    sanitize_strings: bool = True
    logger: LoggerFn = None


class SchemaValidator:
    """L5 Schema Validator - validates tool parameters and detects injections."""

    def __init__(self, config: Optional[SchemaValidatorConfig] = None) -> None:
        config = config or SchemaValidatorConfig()
        self._strict_types = config.strict_types
        self._detect_injection = config.detect_injection
        self._sanitize_strings = config.sanitize_strings
        self._logger: Callable[[str, str], None] = config.logger or (lambda _m, _l: None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate(
        self,
        tool: ToolDefinition,
        params: Dict[str, Any],
        request_id: str = "",
    ) -> SchemaValidatorResult:
        """Validate parameters against tool schema."""
        errors: List[str] = []
        warnings: List[str] = []
        blocked_attacks: List[str] = []
        sanitized_params: Dict[str, Any] = {}

        # Check for prototype pollution at top level
        pollution_check = self._check_prototype_pollution(params)
        if not pollution_check["safe"]:
            if request_id:
                self._logger(f"[L5:{request_id}] BLOCKED: Prototype pollution", "info")
            return SchemaValidatorResult(
                allowed=False,
                reason="Prototype pollution detected",
                violations=["PROTOTYPE_POLLUTION"],
                errors=pollution_check["errors"],
                warnings=[],
                sanitized_params={},
                blocked_attacks=["PROTOTYPE_POLLUTION"],
            )

        schema = tool.parameters or {}
        properties: Dict[str, Any] = schema.get("properties", {})
        required_fields: List[str] = schema.get("required", [])

        # Check required fields
        for f in required_fields:
            if params.get(f) is None:
                errors.append(f"Missing required field: {f}")

        if errors:
            return SchemaValidatorResult(
                allowed=False,
                reason="Missing required fields",
                violations=["MISSING_REQUIRED"],
                errors=errors,
                warnings=warnings,
                sanitized_params={},
                blocked_attacks=blocked_attacks,
            )

        # Validate each parameter
        for param_name, param_schema_raw in properties.items():
            value = params.get(param_name)
            if value is None:
                continue

            # Convert raw dict to SchemaProperty if needed
            if isinstance(param_schema_raw, dict):
                prop = SchemaProperty(
                    type=param_schema_raw.get("type", "string"),
                    min_length=param_schema_raw.get("minLength"),
                    max_length=param_schema_raw.get("maxLength"),
                    min=param_schema_raw.get("min"),
                    max=param_schema_raw.get("max"),
                    enum=param_schema_raw.get("enum"),
                    pattern=param_schema_raw.get("pattern"),
                    properties=param_schema_raw.get("properties"),
                    required=param_schema_raw.get("required"),
                )
            elif isinstance(param_schema_raw, SchemaProperty):
                prop = param_schema_raw
            else:
                continue

            result = self._validate_parameter(param_name, value, prop, request_id)

            if not result["valid"]:
                errors.extend(result["errors"])
                blocked_attacks.extend(result["blocked"])
            else:
                sanitized_params[param_name] = result["sanitized_value"]

            warnings.extend(result["warnings"])

        allowed = len(errors) == 0

        if request_id:
            if allowed:
                self._logger(f"[L5:{request_id}] Validation PASSED", "info")
            else:
                self._logger(f"[L5:{request_id}] Validation FAILED: {', '.join(errors)}", "info")

        return SchemaValidatorResult(
            allowed=allowed,
            reason=None if allowed else errors[0],
            violations=[] if allowed else ["VALIDATION_FAILED"],
            errors=errors,
            warnings=warnings,
            sanitized_params=sanitized_params,
            blocked_attacks=blocked_attacks,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _validate_parameter(
        self,
        name: str,
        value: Any,
        schema: SchemaProperty,
        request_id: str,
    ) -> Dict[str, Any]:
        errors: List[str] = []
        warnings: List[str] = []
        blocked: List[str] = []
        sanitized_value = value

        # Strict type checking
        actual_type = self._get_strict_type(value)
        if self._strict_types and actual_type != schema.type:
            errors.append(f"Type mismatch for '{name}': expected {schema.type}, got {actual_type}")
            blocked.append("TYPE_COERCION")
            return {"valid": False, "errors": errors, "warnings": warnings, "sanitized_value": sanitized_value, "blocked": blocked}

        # Type-specific validation
        if schema.type == "string":
            str_result = self._validate_string(name, value, schema, request_id)
            errors.extend(str_result["errors"])
            warnings.extend(str_result["warnings"])
            blocked.extend(str_result["blocked"])
            if str_result["valid"]:
                sanitized_value = str_result["sanitized_value"]

        elif schema.type == "number":
            num_result = self._validate_number(name, value, schema)
            errors.extend(num_result["errors"])
            blocked.extend(num_result["blocked"])

        elif schema.type == "object":
            obj_result = self._validate_object(name, value, schema, request_id)
            errors.extend(obj_result["errors"])
            blocked.extend(obj_result["blocked"])

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "sanitized_value": sanitized_value,
            "blocked": blocked,
        }

    def _get_strict_type(self, value: Any) -> str:
        if value is None:
            return "null"
        if isinstance(value, list):
            return "array"
        if isinstance(value, bool):
            return "boolean"
        if isinstance(value, int):
            return "number"
        if isinstance(value, float):
            return "number"
        if isinstance(value, str):
            return "string"
        if isinstance(value, dict):
            return "object"
        return type(value).__name__

    def _validate_string(
        self,
        name: str,
        value: str,
        schema: SchemaProperty,
        request_id: str,
    ) -> Dict[str, Any]:
        errors: List[str] = []
        warnings: List[str] = []
        blocked: List[str] = []
        sanitized_value = value

        # Length checks
        if schema.min_length is not None and len(value) < schema.min_length:
            errors.append(f"'{name}' is too short (min: {schema.min_length})")
        if schema.max_length is not None and len(value) > schema.max_length:
            errors.append(f"'{name}' is too long (max: {schema.max_length})")

        # Enum check
        if schema.enum is not None and value not in schema.enum:
            errors.append(f"'{name}' must be one of: {', '.join(schema.enum)}")

        # Pattern check
        if schema.pattern is not None:
            regex = re.compile(schema.pattern)
            if not regex.search(value):
                errors.append(f"'{name}' does not match required format")
                blocked.append("FORMAT_VIOLATION")

        # Injection detection
        if self._detect_injection:
            injection_check = self._detect_injection_patterns(value)
            if injection_check["detected"]:
                errors.append(f"Injection detected in '{name}': {', '.join(injection_check['types'])}")
                blocked.extend(f"{t}_INJECTION" for t in injection_check["types"])
                if request_id:
                    self._logger(f"[L5:{request_id}] BLOCKED: Injection in '{name}'", "info")

        # Sanitize
        if self._sanitize_strings and not errors:
            sanitized_value = self._sanitize_string(value)

        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "sanitized_value": sanitized_value, "blocked": blocked}

    def _validate_number(
        self,
        name: str,
        value: Any,
        schema: SchemaProperty,
    ) -> Dict[str, Any]:
        errors: List[str] = []
        blocked: List[str] = []

        if isinstance(value, float) and (math.isinf(value) or math.isnan(value)):
            errors.append(f"'{name}' must be a finite number")
            blocked.append("INVALID_NUMBER")
            return {"valid": False, "errors": errors, "blocked": blocked}

        if abs(value) > 2**53 - 1:  # MAX_SAFE_INTEGER equivalent
            errors.append(f"'{name}' exceeds safe integer bounds")
            blocked.append("INTEGER_OVERFLOW")
            return {"valid": False, "errors": errors, "blocked": blocked}

        if schema.min is not None and value < schema.min:
            errors.append(f"'{name}' must be at least {schema.min}")
            if value < 0:
                blocked.append("NEGATIVE_VALUE")

        if schema.max is not None and value > schema.max:
            errors.append(f"'{name}' must be at most {schema.max}")
            blocked.append("BOUNDARY_VIOLATION")

        return {"valid": len(errors) == 0, "errors": errors, "blocked": blocked}

    def _validate_object(
        self,
        name: str,
        value: Dict[str, Any],
        schema: SchemaProperty,
        request_id: str,
    ) -> Dict[str, Any]:
        errors: List[str] = []
        blocked: List[str] = []

        # Prototype pollution check
        pollution_check = self._check_prototype_pollution(value)
        if not pollution_check["safe"]:
            errors.extend(pollution_check["errors"])
            blocked.append("PROTOTYPE_POLLUTION")
            return {"valid": False, "errors": errors, "blocked": blocked}

        # Deep scan for injection
        if self._detect_injection:
            self._deep_scan_for_injection(name, value, errors, blocked, request_id)

        return {"valid": len(errors) == 0, "errors": errors, "blocked": blocked}

    def _check_prototype_pollution(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        errors: List[str] = []

        def check(o: Any, path: str) -> None:
            if not isinstance(o, dict):
                return
            for key in o:
                if key in DANGEROUS_KEYS:
                    errors.append(f"Dangerous key '{key}' at {path or 'root'}")
                if isinstance(o[key], dict):
                    check(o[key], f"{path}.{key}" if path else key)

        check(obj, "")
        return {"safe": len(errors) == 0, "errors": errors}

    def _detect_injection_patterns(self, value: str) -> Dict[str, Any]:
        types: List[str] = []

        for injection_type, patterns in INJECTION_PATTERNS.items():
            for pattern in patterns:
                if pattern.search(value):
                    types.append(injection_type)
                    break

        return {"detected": len(types) > 0, "types": types}

    def _deep_scan_for_injection(
        self,
        name: str,
        obj: Dict[str, Any],
        errors: List[str],
        blocked: List[str],
        request_id: str,
    ) -> None:
        def scan(o: Any, path: str) -> None:
            if isinstance(o, str):
                check = self._detect_injection_patterns(o)
                if check["detected"]:
                    errors.append(f"Injection in '{path}': {', '.join(check['types'])}")
                    blocked.extend(f"{t}_INJECTION" for t in check["types"])
            elif isinstance(o, dict):
                for key, val in o.items():
                    scan(val, f"{path}.{key}")

        for key, val in obj.items():
            scan(val, f"{name}.{key}")

    def _sanitize_string(self, value: str) -> str:
        value = re.sub(r"[<>]", "", value)
        value = re.sub(r"['\";]", "", value)
        return value.strip()
