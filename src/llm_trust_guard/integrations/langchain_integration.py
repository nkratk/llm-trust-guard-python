"""
LangChain Integration for llm-trust-guard.

Provides a wrapper class and helper functions for securing LangChain-based
applications.  Works with any LangChain version -- the library is never
imported directly.

Zero extra dependencies.

Usage::

    from llm_trust_guard.integrations.langchain_integration import (
        TrustGuardLangChain,
        create_input_validator,
        create_output_filter,
    )

    guard = TrustGuardLangChain(
        validate_input=True,
        filter_output=True,
        throw_on_violation=True,
    )

    # Validate before sending to LLM
    result = guard.validate_input(user_message)
    if not result.allowed:
        raise ValueError(f"Blocked: {', '.join(result.violations)}")

    # Use the sanitised text in your chain
    llm_input = result.sanitized_input or user_message

    # Filter output before returning to the user
    safe_output = guard.filter_output(response_text)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

from llm_trust_guard import (
    InputSanitizer,
    EncodingDetector,
    MemoryGuard,
    ToolChainValidator,
    OutputFilter,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class SecurityCheckResult:
    """Result of a guard check."""
    allowed: bool
    guard: str
    violations: List[str]
    sanitized_input: Optional[str] = None
    details: Any = None


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class TrustGuardViolationError(Exception):
    """Raised when ``throw_on_violation`` is ``True`` and a check fails."""

    def __init__(self, violation_type: str, details: Any = None) -> None:
        self.violation_type = violation_type
        self.details = details
        super().__init__(f"Trust guard violation: {violation_type}")


# ---------------------------------------------------------------------------
# Main wrapper
# ---------------------------------------------------------------------------

class TrustGuardLangChain:
    """Security wrapper for LangChain pipelines.

    Parameters
    ----------
    validate_input : bool
        Run ``InputSanitizer`` + ``EncodingDetector`` on user inputs.
    filter_output : bool
        Run ``OutputFilter`` on LLM responses.
    validate_tools : bool
        Run ``ToolChainValidator`` on tool calls.
    throw_on_violation : bool
        Raise ``TrustGuardViolationError`` instead of returning a result.
    on_violation : callable, optional
        ``on_violation(type_str, details)`` -- custom handler.
    sanitizer_config : dict, optional
        Keyword arguments forwarded to ``InputSanitizer()``.
    output_config : dict, optional
        Keyword arguments forwarded to ``OutputFilter()``.
    """

    def __init__(
        self,
        validate_input: bool = True,
        filter_output: bool = True,
        validate_tools: bool = True,
        throw_on_violation: bool = False,
        on_violation: Optional[Callable[[str, Any], None]] = None,
        sanitizer_config: Optional[Dict[str, Any]] = None,
        output_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._validate_input = validate_input
        self._filter_output = filter_output
        self._validate_tools = validate_tools
        self._throw_on_violation = throw_on_violation
        self._on_violation = on_violation

        self.input_sanitizer = InputSanitizer(**(sanitizer_config or {}))
        self.encoding_detector = EncodingDetector()
        self.memory_guard = MemoryGuard()
        self.tool_chain_validator = ToolChainValidator()
        self.output_filter = OutputFilter(**(output_config or {}))

    # -- Public API ---------------------------------------------------------

    def validate_input(
        self, text: str, request_id: Optional[str] = None,
    ) -> SecurityCheckResult:
        """Validate user input before sending to the LLM."""
        req_id = request_id or f"lc-{int(time.time() * 1000)}"

        # Input sanitisation
        sanitize_result = self.input_sanitizer.sanitize(text)
        if not sanitize_result.allowed:
            self._handle_violation("input_sanitization", sanitize_result)
            return SecurityCheckResult(
                allowed=False,
                guard="InputSanitizer",
                violations=sanitize_result.violations,
                sanitized_input=sanitize_result.sanitized_input,
                details=sanitize_result,
            )

        # Encoding attack detection
        encoding_result = self.encoding_detector.detect(text, req_id)
        if not encoding_result.allowed:
            self._handle_violation("encoding_attack", encoding_result)
            return SecurityCheckResult(
                allowed=False,
                guard="EncodingDetector",
                violations=encoding_result.violations,
                details=encoding_result,
            )

        return SecurityCheckResult(
            allowed=True,
            guard="all",
            violations=[],
            sanitized_input=sanitize_result.sanitized_input,
        )

    def validate_context(
        self,
        context: Union[str, List[str]],
        session_id: str,
        request_id: Optional[str] = None,
    ) -> SecurityCheckResult:
        """Validate context / memory before injection."""
        req_id = request_id or f"lc-ctx-{int(time.time() * 1000)}"
        result = self.memory_guard.validate_context_injection(
            context, session_id, req_id,
        )

        if not result.allowed:
            self._handle_violation("context_injection", result)
            return SecurityCheckResult(
                allowed=False,
                guard="MemoryGuard",
                violations=result.violations,
                details=result,
            )

        return SecurityCheckResult(
            allowed=True,
            guard="MemoryGuard",
            violations=[],
        )

    def validate_documents(
        self,
        documents: List[Dict[str, Any]],
        session_id: str,
    ) -> SecurityCheckResult:
        """Validate RAG documents before context injection.

        Each document dict must contain a ``"content"`` key with the text.
        """
        violations: List[str] = []

        for i, doc in enumerate(documents):
            content = doc.get("content", "")
            if not isinstance(content, str):
                continue

            context_result = self.memory_guard.validate_context_injection(
                content, session_id,
            )
            if not context_result.allowed:
                violations.append(
                    f"doc[{i}]: {', '.join(context_result.violations)}"
                )

            encoding_result = self.encoding_detector.detect(content)
            if not encoding_result.allowed:
                violations.append(f"doc[{i}]: encoded threat detected")

        if violations:
            self._handle_violation("document_validation", {"violations": violations})
            return SecurityCheckResult(
                allowed=False,
                guard="DocumentValidator",
                violations=violations,
            )

        return SecurityCheckResult(
            allowed=True,
            guard="DocumentValidator",
            violations=[],
        )

    def validate_tool_call(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        session_id: str,
    ) -> SecurityCheckResult:
        """Validate a tool call before execution."""
        result = self.tool_chain_validator.validate(session_id, tool_name)

        if not result.allowed:
            self._handle_violation("tool_call", result)
            return SecurityCheckResult(
                allowed=False,
                guard="ToolChainValidator",
                violations=result.violations,
                details=result,
            )

        return SecurityCheckResult(
            allowed=True,
            guard="ToolChainValidator",
            violations=[],
        )

    def filter_output(
        self, output: str, request_id: Optional[str] = None,
    ) -> str:
        """Filter LLM output before returning to the user."""
        if not self._filter_output:
            return output

        req_id = request_id or f"lc-out-{int(time.time() * 1000)}"
        result = self.output_filter.filter(output, request_id=req_id)

        if result.filtered_response != output:
            self._handle_violation("output_filtered", {
                "original_preview": output[:100],
                "pii_detected": len(result.pii_detected),
                "secrets_detected": len(result.secrets_detected),
            })

        if isinstance(result.filtered_response, str):
            return result.filtered_response
        return output

    # -- Convenience: secure processor per session --------------------------

    def create_secure_processor(self, session_id: str) -> Dict[str, Callable]:
        """Return a dict of helper functions bound to *session_id*.

        Keys: ``process_user_message``, ``process_context``,
        ``process_tool_call``, ``process_output``.
        """

        def process_user_message(message: str) -> Dict[str, Any]:
            result = self.validate_input(message)
            return {
                "allowed": result.allowed,
                "message": result.sanitized_input or message,
                "violations": result.violations,
            }

        def process_context(context: List[str]) -> Dict[str, Any]:
            result = self.validate_context(context, session_id)
            return {
                "allowed": result.allowed,
                "violations": result.violations,
            }

        def process_tool_call(tool: str, args: Any) -> Dict[str, Any]:
            result = self.validate_tool_call(tool, args, session_id)
            return {
                "allowed": result.allowed,
                "violations": result.violations,
            }

        def process_output(text: str) -> str:
            return self.filter_output(text)

        return {
            "process_user_message": process_user_message,
            "process_context": process_context,
            "process_tool_call": process_tool_call,
            "process_output": process_output,
        }

    # -- Internal -----------------------------------------------------------

    def _handle_violation(self, violation_type: str, details: Any) -> None:
        if self._on_violation is not None:
            self._on_violation(violation_type, details)

        if self._throw_on_violation:
            raise TrustGuardViolationError(violation_type, details)


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

def create_input_validator(
    sanitizer_config: Optional[Dict[str, Any]] = None,
) -> Callable[[str], Dict[str, Any]]:
    """Return a simple ``validate(text) -> dict`` function.

    Usage::

        validate = create_input_validator()
        result = validate(user_input)
        if not result["allowed"]:
            raise ValueError(result["violations"])
        safe_text = result["sanitized"]
    """
    sanitizer = InputSanitizer(**(sanitizer_config or {}))
    encoder = EncodingDetector()

    def validate(text: str) -> Dict[str, Any]:
        sanitize_result = sanitizer.sanitize(text)
        if not sanitize_result.allowed:
            return {
                "allowed": False,
                "sanitized": sanitize_result.sanitized_input,
                "violations": sanitize_result.violations,
            }

        encoding_result = encoder.detect(text)
        if not encoding_result.allowed:
            return {
                "allowed": False,
                "sanitized": text,
                "violations": encoding_result.violations,
            }

        return {
            "allowed": True,
            "sanitized": sanitize_result.sanitized_input,
            "violations": [],
        }

    return validate


def create_output_filter(
    output_config: Optional[Dict[str, Any]] = None,
) -> Callable[[str], str]:
    """Return a simple ``filter_output(text) -> str`` function."""
    filt = OutputFilter(**(output_config or {}))

    def filter_output(text: str) -> str:
        result = filt.filter(text)
        if isinstance(result.filtered_response, str):
            return result.filtered_response
        return text

    return filter_output
