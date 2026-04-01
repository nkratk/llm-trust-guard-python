"""
OpenAI Integration for llm-trust-guard.

Provides wrappers and utilities for securing OpenAI API calls.
Works with the official ``openai`` Python SDK and direct API usage alike.

Zero extra dependencies -- ``openai`` is never imported.

Usage::

    from openai import OpenAI
    from llm_trust_guard.integrations.openai_integration import (
        SecureOpenAI,
        wrap_openai_client,
    )

    client = OpenAI()
    secure = SecureOpenAI(validate_input=True, filter_output=True)

    # Option A: explicit validation
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_input},
    ]
    validated = secure.validate_messages(messages, session_id="sess-1")
    if not validated["allowed"]:
        raise ValueError(validated["violations"])

    completion = client.chat.completions.create(
        model="gpt-4", messages=validated["messages"],
    )
    safe = secure.filter_response(completion)

    # Option B: transparent wrapping
    secure_client = wrap_openai_client(client, validate_input=True)
    # Now secure_client.chat.completions.create() validates automatically.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Union

from llm_trust_guard import (
    InputSanitizer,
    EncodingDetector,
    MemoryGuard,
    OutputFilter,
    ToolChainValidator,
)


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Outcome of a single validation check."""
    allowed: bool
    violations: List[str]
    sanitized: Optional[str] = None
    details: Any = None


# ---------------------------------------------------------------------------
# Custom exception
# ---------------------------------------------------------------------------

class OpenAISecurityError(Exception):
    """Raised when ``throw_on_violation`` is ``True``."""

    def __init__(self, message: str, violations: Optional[List[str]] = None) -> None:
        self.violations = violations or []
        super().__init__(message)


# ---------------------------------------------------------------------------
# Secure wrapper
# ---------------------------------------------------------------------------

class SecureOpenAI:
    """Security wrapper for OpenAI API calls.

    Parameters
    ----------
    validate_input : bool
        Run ``InputSanitizer`` + ``EncodingDetector`` on user messages.
    filter_output : bool
        Run ``OutputFilter`` on completion responses.
    validate_functions : bool
        Inspect function / tool definitions and arguments.
    throw_on_violation : bool
        Raise ``OpenAISecurityError`` instead of returning violations.
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
        validate_functions: bool = True,
        throw_on_violation: bool = False,
        on_violation: Optional[Callable[[str, Any], None]] = None,
        sanitizer_config: Optional[Dict[str, Any]] = None,
        output_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self._validate_input = validate_input
        self._filter_output = filter_output
        self._validate_functions = validate_functions
        self._throw_on_violation = throw_on_violation
        self._on_violation = on_violation

        self.input_sanitizer = InputSanitizer(**(sanitizer_config or {}))
        self.encoding_detector = EncodingDetector()
        self.memory_guard = MemoryGuard()
        self.output_filter = OutputFilter(**(output_config or {}))
        self.tool_chain_validator = ToolChainValidator()

    # -- Single content validation ------------------------------------------

    def validate_content(
        self, content: str, request_id: Optional[str] = None,
    ) -> ValidationResult:
        """Validate a single piece of text (e.g. a user message body)."""
        req_id = request_id or f"oai-{int(time.time() * 1000)}"

        sanitize_result = self.input_sanitizer.sanitize(content)
        if not sanitize_result.allowed:
            self._handle_violation("input_sanitization", sanitize_result)
            return ValidationResult(
                allowed=False,
                violations=sanitize_result.violations,
                sanitized=sanitize_result.sanitized_input,
                details=sanitize_result,
            )

        encoding_result = self.encoding_detector.detect(content, req_id)
        if not encoding_result.allowed:
            self._handle_violation("encoding_attack", encoding_result)
            return ValidationResult(
                allowed=False,
                violations=encoding_result.violations,
                details=encoding_result,
            )

        return ValidationResult(
            allowed=True,
            violations=[],
            sanitized=sanitize_result.sanitized_input,
        )

    # -- Chat message array validation --------------------------------------

    def validate_messages(
        self,
        messages: List[Dict[str, Any]],
        session_id: str,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validate an array of chat-completion messages.

        Returns ``{"allowed": bool, "messages": [...], "violations": [...]}``.
        """
        req_id = request_id or f"oai-msgs-{int(time.time() * 1000)}"
        violations: List[str] = []
        validated: List[Dict[str, Any]] = []

        for i, msg in enumerate(messages):
            content = msg.get("content")
            role = msg.get("role", "")

            if content is None:
                validated.append(dict(msg))
                continue

            if role == "user":
                result = self.validate_content(content, f"{req_id}-{i}")
                if not result.allowed:
                    violations.append(
                        f"message[{i}]: {', '.join(result.violations)}"
                    )
                    if self._throw_on_violation:
                        raise OpenAISecurityError(
                            "Message validation failed", violations,
                        )
                validated.append({**msg, "content": result.sanitized or content})

            elif role in ("system", "assistant"):
                encoding_result = self.encoding_detector.detect(
                    content, f"{req_id}-{i}",
                )
                if not encoding_result.allowed:
                    violations.append(
                        f"message[{i}] ({role}): "
                        f"{', '.join(encoding_result.violations)}"
                    )
                validated.append(dict(msg))

            else:
                validated.append(dict(msg))

        # Context coherence check
        context_contents = [
            m["content"]
            for m in messages
            if m.get("role") in ("system", "assistant")
            and isinstance(m.get("content"), str)
        ]
        if context_contents:
            ctx_result = self.memory_guard.validate_context_injection(
                context_contents, session_id, req_id,
            )
            if not ctx_result.allowed:
                violations.append(
                    f"context: {', '.join(ctx_result.violations)}"
                )

        return {
            "allowed": len(violations) == 0,
            "messages": validated,
            "violations": violations,
        }

    # -- Function / tool validation -----------------------------------------

    def validate_functions(
        self,
        functions: List[Dict[str, Any]],
        session_id: str,
    ) -> ValidationResult:
        """Validate function / tool definitions for suspicious patterns."""
        violations: List[str] = []

        for func in functions:
            name = func.get("name", "")
            if re.match(r"^(system|admin|root|exec|eval|shell)", name, re.I):
                violations.append(f"Suspicious function name: {name}")

            description = func.get("description")
            if description:
                result = self.validate_content(description)
                if not result.allowed:
                    violations.append(
                        f"Function {name} description: "
                        f"{', '.join(result.violations)}"
                    )

        if violations:
            self._handle_violation("function_validation", {"violations": violations})

        return ValidationResult(
            allowed=len(violations) == 0,
            violations=violations,
        )

    def validate_function_call(
        self,
        name: str,
        args: Dict[str, Any],
        session_id: str,
    ) -> ValidationResult:
        """Validate a function / tool call before execution."""
        result = self.tool_chain_validator.validate(session_id, name)

        if not result.allowed:
            self._handle_violation("function_call", result)
            return ValidationResult(
                allowed=False,
                violations=result.violations,
                details=result,
            )

        # Check string arguments for injection
        for key, value in args.items():
            if isinstance(value, str):
                content_result = self.validate_content(value)
                if not content_result.allowed:
                    self._handle_violation(
                        "function_arg_injection",
                        {"key": key, "violations": content_result.violations},
                    )
                    return ValidationResult(
                        allowed=False,
                        violations=[
                            f"{key}: {', '.join(content_result.violations)}"
                        ],
                    )

        return ValidationResult(allowed=True, violations=[])

    # -- Response filtering -------------------------------------------------

    def filter_response(self, response: Any, request_id: Optional[str] = None) -> Any:
        """Filter an OpenAI ChatCompletion (or legacy Completion) response.

        Accepts any object with a ``choices`` attribute (or dict with a
        ``"choices"`` key).  Returns the same structure with filtered text.
        """
        if not self._filter_output:
            return response

        req_id = request_id or f"oai-resp-{int(time.time() * 1000)}"

        # Support both dict-style and object-style responses
        choices = (
            response.get("choices")
            if isinstance(response, dict)
            else getattr(response, "choices", None)
        )
        if not choices:
            return response

        for i, choice in enumerate(choices):
            # Chat completion
            message = (
                choice.get("message")
                if isinstance(choice, dict)
                else getattr(choice, "message", None)
            )
            if message is not None:
                content = (
                    message.get("content")
                    if isinstance(message, dict)
                    else getattr(message, "content", None)
                )
                if isinstance(content, str):
                    filtered = self.output_filter.filter(
                        content, request_id=f"{req_id}-{i}",
                    )
                    filtered_text = (
                        filtered.filtered_response
                        if isinstance(filtered.filtered_response, str)
                        else content
                    )
                    if isinstance(message, dict):
                        message["content"] = filtered_text
                    else:
                        try:
                            message.content = filtered_text
                        except AttributeError:
                            pass

            # Legacy completion (text field)
            text = (
                choice.get("text")
                if isinstance(choice, dict)
                else getattr(choice, "text", None)
            )
            if isinstance(text, str):
                filtered = self.output_filter.filter(
                    text, request_id=f"{req_id}-{i}",
                )
                filtered_text = (
                    filtered.filtered_response
                    if isinstance(filtered.filtered_response, str)
                    else text
                )
                if isinstance(choice, dict):
                    choice["text"] = filtered_text
                else:
                    try:
                        choice.text = filtered_text
                    except AttributeError:
                        pass

        return response

    # -- Convenience: per-session chat wrapper ------------------------------

    def create_secure_chat(self, session_id: str) -> Dict[str, Callable]:
        """Return helper functions bound to *session_id*.

        Keys: ``prepare_messages``, ``validate_function_call``,
        ``filter_response``.
        """

        def prepare_messages(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
            return self.validate_messages(messages, session_id)

        def validate_function_call(
            name: str, args: Dict[str, Any],
        ) -> ValidationResult:
            return self.validate_function_call(name, args, session_id)

        def filter_resp(response: Any) -> Any:
            return self.filter_response(response)

        return {
            "prepare_messages": prepare_messages,
            "validate_function_call": validate_function_call,
            "filter_response": filter_resp,
        }

    # -- Internal -----------------------------------------------------------

    def _handle_violation(self, violation_type: str, details: Any) -> None:
        if self._on_violation is not None:
            self._on_violation(violation_type, details)

        if self._throw_on_violation:
            viol_list = (
                getattr(details, "violations", None)
                or (details.get("violations") if isinstance(details, dict) else None)
                or [violation_type]
            )
            raise OpenAISecurityError(
                f"Security violation: {violation_type}", viol_list,
            )


# ---------------------------------------------------------------------------
# Standalone helpers
# ---------------------------------------------------------------------------

def create_message_validator(
    sanitizer_config: Optional[Dict[str, Any]] = None,
) -> Callable[[str], Dict[str, Any]]:
    """Return a simple ``validate(content) -> dict`` function.

    Usage::

        validate = create_message_validator()
        result = validate(user_text)
        if not result["allowed"]:
            print("Blocked:", result["violations"])
        safe = result["sanitized"]
    """
    sanitizer = InputSanitizer(**(sanitizer_config or {}))
    encoder = EncodingDetector()

    def validate(content: str) -> Dict[str, Any]:
        sanitize_result = sanitizer.sanitize(content)
        if not sanitize_result.allowed:
            return {
                "allowed": False,
                "sanitized": sanitize_result.sanitized_input,
                "violations": sanitize_result.violations,
            }

        encoding_result = encoder.detect(content)
        if not encoding_result.allowed:
            return {
                "allowed": False,
                "sanitized": content,
                "violations": encoding_result.violations,
            }

        return {
            "allowed": True,
            "sanitized": sanitize_result.sanitized_input,
            "violations": [],
        }

    return validate


def wrap_openai_client(
    client: Any,
    validate_input: bool = True,
    filter_output: bool = True,
    validate_functions: bool = True,
    throw_on_violation: bool = False,
    on_violation: Optional[Callable[[str, Any], None]] = None,
    sanitizer_config: Optional[Dict[str, Any]] = None,
    output_config: Optional[Dict[str, Any]] = None,
) -> Any:
    """Monkey-patch an OpenAI client so every ``chat.completions.create``
    call is automatically validated and filtered.

    Works with both sync and async OpenAI clients.  The original
    ``create`` method is preserved; the wrapper delegates to it after
    validation.

    Returns the *same* client object (mutated).

    Usage::

        from openai import OpenAI
        from llm_trust_guard.integrations.openai_integration import wrap_openai_client

        client = wrap_openai_client(OpenAI(), validate_input=True)
        # client.chat.completions.create(...) now validates automatically
    """
    import asyncio
    import functools

    secure = SecureOpenAI(
        validate_input=validate_input,
        filter_output=filter_output,
        validate_functions=validate_functions,
        throw_on_violation=throw_on_violation,
        on_violation=on_violation,
        sanitizer_config=sanitizer_config,
        output_config=output_config,
    )
    session_id = f"wrap-{int(time.time() * 1000)}"

    original_create = client.chat.completions.create

    if asyncio.iscoroutinefunction(original_create):
        @functools.wraps(original_create)
        async def _async_create(**kwargs: Any) -> Any:  # type: ignore[override]
            kwargs = _validate_params(secure, kwargs, session_id)
            response = await original_create(**kwargs)
            return secure.filter_response(response)

        client.chat.completions.create = _async_create  # type: ignore[assignment]
    else:
        @functools.wraps(original_create)
        def _sync_create(**kwargs: Any) -> Any:  # type: ignore[override]
            kwargs = _validate_params(secure, kwargs, session_id)
            response = original_create(**kwargs)
            return secure.filter_response(response)

        client.chat.completions.create = _sync_create  # type: ignore[assignment]

    return client


def _validate_params(
    secure: SecureOpenAI,
    params: Dict[str, Any],
    session_id: str,
) -> Dict[str, Any]:
    """Shared pre-call validation for ``wrap_openai_client``."""
    messages = params.get("messages")
    if messages is not None:
        validated = secure.validate_messages(list(messages), session_id)
        if not validated["allowed"] and secure._throw_on_violation:
            raise OpenAISecurityError(
                "Message validation failed", validated["violations"],
            )
        params = {**params, "messages": validated["messages"]}

    functions = params.get("functions")
    if functions is not None and secure._validate_functions:
        func_result = secure.validate_functions(list(functions), session_id)
        if not func_result.allowed and secure._throw_on_violation:
            raise OpenAISecurityError(
                "Function validation failed", func_result.violations,
            )

    return params
