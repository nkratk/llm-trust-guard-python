"""
FastAPI Middleware Integration for llm-trust-guard.

Provides ready-to-use ASGI middleware for FastAPI / Starlette applications
to protect LLM-powered endpoints.

Zero extra dependencies -- FastAPI / Starlette are imported at runtime only.

Usage::

    from fastapi import FastAPI
    from llm_trust_guard.integrations.fastapi_integration import TrustGuardMiddleware

    app = FastAPI()
    app.add_middleware(
        TrustGuardMiddleware,
        body_fields=["message", "prompt"],
        sanitize=True,
        detect_encoding=True,
    )

    @app.post("/api/chat")
    async def chat(request: dict):
        # request body fields have already been validated
        return {"response": "Safe response"}
"""

from __future__ import annotations

import json
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Sequence,
    Union,
)

from llm_trust_guard import InputSanitizer, EncodingDetector, MemoryGuard


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class GuardResult:
    """Result returned when a request is blocked."""
    allowed: bool
    guard: str
    violations: List[str]
    details: Any = None


# ---------------------------------------------------------------------------
# Main middleware
# ---------------------------------------------------------------------------

class TrustGuardMiddleware:
    """ASGI middleware that validates incoming request body fields.

    Parameters
    ----------
    app : ASGI application
    body_fields : list[str]
        JSON body keys to check (default: ``["message", "prompt", "input", "query", "content"]``).
    query_fields : list[str]
        Query-parameter names to check (default: ``[]``).
    sanitize : bool
        Enable ``InputSanitizer`` checks (default ``True``).
    detect_encoding : bool
        Enable ``EncodingDetector`` checks (default ``True``).
    validate_memory : bool
        Enable ``MemoryGuard`` context-injection checks (default ``False``).
    on_blocked : callable, optional
        ``async def on_blocked(scope, guard_result) -> (status, body)``
        Custom handler; must return an ``(int, dict)`` tuple.
    logger : callable, optional
        ``logger(message, data=None)``  -- defaults to ``print``.
    sanitizer_config : dict, optional
        Keyword arguments forwarded to ``InputSanitizer()``.
    encoding_config : dict, optional
        Keyword arguments forwarded to ``EncodingDetector()``.
    memory_config : dict, optional
        Keyword arguments forwarded to ``MemoryGuard()``.
    get_session_id : callable, optional
        ``get_session_id(scope) -> str`` to extract a session ID from the
        ASGI scope.  Defaults to a random per-request ID.
    path_prefix : str, optional
        Only apply the middleware to paths starting with this prefix
        (e.g. ``"/api/"``).  Default ``None`` means *all* paths.
    """

    def __init__(
        self,
        app: Any,
        body_fields: Optional[List[str]] = None,
        query_fields: Optional[List[str]] = None,
        sanitize: bool = True,
        detect_encoding: bool = True,
        validate_memory: bool = False,
        on_blocked: Optional[Callable] = None,
        logger: Optional[Callable] = None,
        sanitizer_config: Optional[Dict[str, Any]] = None,
        encoding_config: Optional[Dict[str, Any]] = None,
        memory_config: Optional[Dict[str, Any]] = None,
        get_session_id: Optional[Callable] = None,
        path_prefix: Optional[str] = None,
    ) -> None:
        self.app = app
        self.body_fields = body_fields or [
            "message", "prompt", "input", "query", "content",
        ]
        self.query_fields = query_fields or []
        self.on_blocked = on_blocked
        self.logger = logger or print
        self.get_session_id = get_session_id or self._default_session_id
        self.path_prefix = path_prefix

        # Lazily initialise only the requested guards
        self.input_sanitizer: Optional[InputSanitizer] = (
            InputSanitizer(**(sanitizer_config or {})) if sanitize else None
        )
        self.encoding_detector: Optional[EncodingDetector] = (
            EncodingDetector(**(encoding_config or {})) if detect_encoding else None
        )
        self.memory_guard: Optional[MemoryGuard] = (
            MemoryGuard(**(memory_config or {})) if validate_memory else None
        )

    # -- ASGI interface -----------------------------------------------------

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Optional path filtering
        path: str = scope.get("path", "")
        if self.path_prefix and not path.startswith(self.path_prefix):
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET")
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        # Read the full request body
        body_chunks: List[bytes] = []
        request_complete = False

        async def receive_wrapper() -> Dict[str, Any]:
            nonlocal request_complete
            message = await receive()
            if message["type"] == "http.request":
                body_chunks.append(message.get("body", b""))
                if not message.get("more_body", False):
                    request_complete = True
            return message

        # Consume the body
        while not request_complete:
            await receive_wrapper()

        raw_body = b"".join(body_chunks)

        # Parse JSON body (skip guard if body is not JSON)
        json_body: Optional[Dict[str, Any]] = None
        try:
            if raw_body:
                json_body = json.loads(raw_body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Parse query string
        query_string = scope.get("query_string", b"").decode("latin-1", errors="replace")
        query_params = self._parse_qs(query_string)

        # Collect texts to check
        texts_to_check: List[Dict[str, str]] = []

        if json_body and isinstance(json_body, dict):
            for fld in self.body_fields:
                value = json_body.get(fld)
                if isinstance(value, str) and value.strip():
                    texts_to_check.append({"field": fld, "value": value, "source": "body"})

        for fld in self.query_fields:
            value = query_params.get(fld)
            if isinstance(value, str) and value.strip():
                texts_to_check.append({"field": fld, "value": value, "source": "query"})

        request_id = f"req-{uuid.uuid4().hex[:12]}"
        session_id = self.get_session_id(scope)

        # Run guards
        for item in texts_to_check:
            fld = item["field"]
            value = item["value"]
            source = item["source"]

            if self.input_sanitizer is not None:
                result = self.input_sanitizer.sanitize(value)
                if not result.allowed:
                    guard_result = GuardResult(
                        allowed=False,
                        guard="InputSanitizer",
                        violations=result.violations,
                        details=result,
                    )
                    self.logger(
                        f"[TrustGuard] Blocked by InputSanitizer: {source}.{fld}",
                        {"request_id": request_id, "violations": result.violations},
                    )
                    await self._send_blocked(
                        send, scope, guard_result,
                        code="INPUT_SANITIZATION_FAILED",
                        field_name=f"{source}.{fld}",
                    )
                    return

            if self.encoding_detector is not None:
                result = self.encoding_detector.detect(value, request_id)
                if not result.allowed:
                    guard_result = GuardResult(
                        allowed=False,
                        guard="EncodingDetector",
                        violations=result.violations,
                        details=result,
                    )
                    self.logger(
                        f"[TrustGuard] Blocked by EncodingDetector: {source}.{fld}",
                        {"request_id": request_id, "violations": result.violations},
                    )
                    await self._send_blocked(
                        send, scope, guard_result,
                        code="ENCODING_ATTACK_DETECTED",
                        field_name=f"{source}.{fld}",
                    )
                    return

            if self.memory_guard is not None:
                result = self.memory_guard.validate_context_injection(
                    value, session_id, request_id,
                )
                if not result.allowed:
                    guard_result = GuardResult(
                        allowed=False,
                        guard="MemoryGuard",
                        violations=result.violations,
                        details=result,
                    )
                    self.logger(
                        f"[TrustGuard] Blocked by MemoryGuard: {source}.{fld}",
                        {"request_id": request_id, "violations": result.violations},
                    )
                    await self._send_blocked(
                        send, scope, guard_result,
                        code="CONTEXT_INJECTION_DETECTED",
                        field_name=f"{source}.{fld}",
                    )
                    return

        # All checks passed -- replay the already-consumed body for downstream
        body_sent = False

        async def replay_receive() -> Dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": raw_body, "more_body": False}
            return await receive()

        await self.app(scope, replay_receive, send)

    # -- Helpers ------------------------------------------------------------

    async def _send_blocked(
        self,
        send: Any,
        scope: Dict[str, Any],
        guard_result: GuardResult,
        code: str,
        field_name: str,
    ) -> None:
        if self.on_blocked is not None:
            status, body = await self.on_blocked(scope, guard_result)
        else:
            status = 400
            body = {
                "error": "Request blocked by security policy",
                "code": code,
                "field": field_name,
                "violations": guard_result.violations,
            }

        payload = json.dumps(body).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"content-length", str(len(payload)).encode()],
            ],
        })
        await send({
            "type": "http.response.body",
            "body": payload,
        })

    @staticmethod
    def _default_session_id(scope: Dict[str, Any]) -> str:
        return f"anon-{uuid.uuid4().hex[:12]}"

    @staticmethod
    def _parse_qs(qs: str) -> Dict[str, str]:
        params: Dict[str, str] = {}
        if not qs:
            return params
        for part in qs.split("&"):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v
        return params


# ---------------------------------------------------------------------------
# Tool rate-limit middleware
# ---------------------------------------------------------------------------

class _ToolRateLimitMiddleware:
    """ASGI middleware that rate-limits sensitive tool usage per session.

    Usage::

        app.add_middleware(
            create_tool_rate_limit_middleware,
            sensitive_tools=["delete", "admin", "execute"],
            max_sensitive_per_session=5,
            window_seconds=60,
        )
    """

    def __init__(
        self,
        app: Any,
        sensitive_tools: List[str],
        max_sensitive_per_session: int = 10,
        window_seconds: float = 60,
        get_session_id: Optional[Callable] = None,
        get_tool_name: Optional[Callable] = None,
    ) -> None:
        self.app = app
        self.sensitive_tools = [t.lower() for t in sensitive_tools]
        self.max_sensitive_per_session = max_sensitive_per_session
        self.window_seconds = window_seconds
        self.get_session_id = get_session_id or (lambda scope: "anonymous")
        self.get_tool_name = get_tool_name
        self._usage: Dict[str, Dict[str, Any]] = {}

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Read body to extract tool name
        body_chunks: List[bytes] = []
        done = False

        async def _recv() -> Dict[str, Any]:
            nonlocal done
            msg = await receive()
            if msg["type"] == "http.request":
                body_chunks.append(msg.get("body", b""))
                if not msg.get("more_body", False):
                    done = True
            return msg

        while not done:
            await _recv()

        raw = b"".join(body_chunks)
        json_body: Optional[Dict[str, Any]] = None
        try:
            if raw:
                json_body = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        tool_name: Optional[str] = None
        if self.get_tool_name and json_body:
            tool_name = self.get_tool_name(json_body)
        elif json_body and isinstance(json_body, dict):
            tool_name = json_body.get("tool") or json_body.get("tool_name")

        if tool_name and any(
            t in tool_name.lower() for t in self.sensitive_tools
        ):
            session_id = self.get_session_id(scope)
            now = time.monotonic()
            usage = self._usage.get(session_id)

            if usage is None or now > usage["reset_at"]:
                usage = {"count": 0, "reset_at": now + self.window_seconds}
                self._usage[session_id] = usage

            if usage["count"] >= self.max_sensitive_per_session:
                retry_after = max(1, int(usage["reset_at"] - now))
                payload = json.dumps({
                    "error": "Rate limit exceeded for sensitive tool usage",
                    "code": "TOOL_RATE_LIMIT_EXCEEDED",
                    "retry_after": retry_after,
                }).encode("utf-8")
                await send({
                    "type": "http.response.start",
                    "status": 429,
                    "headers": [
                        [b"content-type", b"application/json"],
                        [b"content-length", str(len(payload)).encode()],
                    ],
                })
                await send({"type": "http.response.body", "body": payload})
                return

            usage["count"] += 1

        # Replay body downstream
        body_sent = False

        async def replay() -> Dict[str, Any]:
            nonlocal body_sent
            if not body_sent:
                body_sent = True
                return {"type": "http.request", "body": raw, "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


def create_tool_rate_limit_middleware(
    app: Any,
    sensitive_tools: List[str],
    max_sensitive_per_session: int = 10,
    window_seconds: float = 60,
    get_session_id: Optional[Callable] = None,
    get_tool_name: Optional[Callable] = None,
) -> _ToolRateLimitMiddleware:
    """Factory that returns a tool-rate-limit ASGI middleware instance."""
    return _ToolRateLimitMiddleware(
        app,
        sensitive_tools=sensitive_tools,
        max_sensitive_per_session=max_sensitive_per_session,
        window_seconds=window_seconds,
        get_session_id=get_session_id,
        get_tool_name=get_tool_name,
    )


# ---------------------------------------------------------------------------
# Output filter middleware
# ---------------------------------------------------------------------------

class _OutputFilterMiddleware:
    """ASGI middleware that filters sensitive patterns from JSON responses."""

    def __init__(
        self,
        app: Any,
        patterns: List[str],
        replacement: str = "[REDACTED]",
        fields: Optional[List[str]] = None,
    ) -> None:
        self.app = app
        self.compiled = [re.compile(p) for p in patterns]
        self.replacement = replacement
        self.fields = fields or ["response", "message", "content", "text"]

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False
        response_body_chunks: List[bytes] = []
        saved_start_message: Optional[Dict[str, Any]] = None

        async def send_wrapper(message: Dict[str, Any]) -> None:
            nonlocal response_started, saved_start_message
            if message["type"] == "http.response.start":
                saved_start_message = message
                return
            if message["type"] == "http.response.body":
                body = message.get("body", b"")
                more_body = message.get("more_body", False)
                response_body_chunks.append(body)
                if not more_body:
                    # Reassemble, filter, and send
                    full_body = b"".join(response_body_chunks)
                    filtered = self._filter_body(full_body)
                    # Update content-length
                    if saved_start_message:
                        headers = [
                            h for h in saved_start_message.get("headers", [])
                            if h[0] != b"content-length"
                        ]
                        headers.append(
                            [b"content-length", str(len(filtered)).encode()]
                        )
                        saved_start_message["headers"] = headers
                        await send(saved_start_message)
                    await send({
                        "type": "http.response.body",
                        "body": filtered,
                    })
                return
            await send(message)

        await self.app(scope, receive, send_wrapper)

    def _filter_body(self, raw: bytes) -> bytes:
        try:
            obj = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw
        filtered = self._filter_obj(obj)
        return json.dumps(filtered).encode("utf-8")

    def _filter_obj(self, obj: Any) -> Any:
        if isinstance(obj, list):
            return [self._filter_obj(item) for item in obj]
        if isinstance(obj, dict):
            result: Dict[str, Any] = {}
            for key, value in obj.items():
                if key in self.fields and isinstance(value, str):
                    filtered = value
                    for pat in self.compiled:
                        filtered = pat.sub(self.replacement, filtered)
                    result[key] = filtered
                elif isinstance(value, (dict, list)):
                    result[key] = self._filter_obj(value)
                else:
                    result[key] = value
            return result
        return obj


def create_output_filter_middleware(
    app: Any,
    patterns: List[str],
    replacement: str = "[REDACTED]",
    fields: Optional[List[str]] = None,
) -> _OutputFilterMiddleware:
    """Factory that returns an output-filter ASGI middleware instance.

    ``patterns`` are regular-expression strings (not compiled ``re.Pattern``
    objects) so they can be serialised.
    """
    return _OutputFilterMiddleware(
        app,
        patterns=patterns,
        replacement=replacement,
        fields=fields,
    )
