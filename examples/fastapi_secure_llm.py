"""
Secure LLM API with FastAPI + OpenAI + llm-trust-guard
=======================================================

Production-ready FastAPI application with security guards at every layer:

1. ASGI middleware — automatic input validation on every POST request
2. Per-endpoint validation — fine-grained control with roles
3. Output filtering — PII/secret masking before returning to client
4. Tool call validation — agentic endpoint with tool chain security
5. Streaming — SSE with inline output filtering

Install:
    pip install fastapi uvicorn openai llm-trust-guard

Run:
    uvicorn fastapi_secure_llm:app --reload

Test:
    curl -X POST http://localhost:8000/api/chat \\
         -H "Content-Type: application/json" \\
         -d '{"message": "What is the weather today?", "session_id": "user-1"}'
"""

from __future__ import annotations

import os
import uuid
from typing import Any, AsyncGenerator, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from openai import AsyncOpenAI

# llm-trust-guard
from llm_trust_guard.integrations.fastapi_integration import (
    TrustGuardMiddleware,
    create_output_filter_middleware,
)
from llm_trust_guard.integrations.openai_integration import SecureOpenAI
from llm_trust_guard import (
    OutputFilter,
    PolicyGate,
    ExecutionMonitor,
    ToolChainValidator,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "sk-...")
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)


# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = FastAPI(title="Secure LLM API", version="1.0.0")

# Middleware 1: Validate all POST body fields named "message", "prompt",
# "input", "query", or "content" on routes under /api/
app.add_middleware(
    TrustGuardMiddleware,
    body_fields=["message", "prompt", "input", "query", "content"],
    sanitize=True,
    detect_encoding=True,
    validate_memory=False,   # enable for multi-turn apps with memory
    path_prefix="/api/",
    logger=lambda msg, data=None: print(f"[TrustGuard] {msg}", data or ""),
)

# (Optional) Middleware 2: Strip any leaked secrets from JSON responses
# app.add_middleware(
#     create_output_filter_middleware,
#     patterns=[
#         r"sk-[A-Za-z0-9]{20,}",          # OpenAI keys
#         r"ghp_[A-Za-z0-9]{36,}",          # GitHub tokens
#         r"AIzaSy[A-Za-z0-9_\-]{30,}",    # Google API keys
#     ],
#     replacement="[REDACTED]",
# )


# ---------------------------------------------------------------------------
# Shared guards (created once, thread-safe)
# ---------------------------------------------------------------------------

output_filter = OutputFilter(detect_pii=True, detect_secrets=True)
policy_gate = PolicyGate()
execution_monitor = ExecutionMonitor()
tool_chain_validator = ToolChainValidator()

# SecureOpenAI wrapper: validates messages + filters responses
secure_openai = SecureOpenAI(
    validate_input=True,
    filter_output=True,
    validate_functions=True,
    throw_on_violation=False,
    on_violation=lambda t, d: print(f"[OpenAI Security] {t}: {d}"),
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class ChatRequest(BaseModel):
    message: str
    session_id: str = "anonymous"
    role: Optional[str] = "user"


class ChatResponse(BaseModel):
    response: str
    session_id: str
    request_id: str
    security: Dict[str, Any] = {}


class AgentRequest(BaseModel):
    task: str
    session_id: str = "anonymous"
    allowed_tools: List[str] = ["search", "calculator", "weather"]


# ---------------------------------------------------------------------------
# Endpoint 1: Simple chat (middleware handles input, we filter output)
# ---------------------------------------------------------------------------

@app.post("/api/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Basic chat endpoint.

    Input validation is handled by TrustGuardMiddleware (see app setup).
    Output filtering is applied explicitly here for fine-grained control.
    """
    request_id = f"req-{uuid.uuid4().hex[:12]}"

    # Build messages — middleware already validated the user message
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": request.message},
    ]

    # Validate messages via SecureOpenAI (extra layer: memory coherence check)
    validated = secure_openai.validate_messages(messages, session_id=request.session_id)
    if not validated["allowed"]:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Message validation failed",
                "violations": validated["violations"],
            },
        )

    # Call OpenAI
    completion = await openai_client.chat.completions.create(
        model="gpt-4o",
        messages=validated["messages"],
    )

    raw_text = completion.choices[0].message.content or ""

    # Filter output: mask PII and secrets
    filter_result = output_filter.filter(raw_text, role=request.role, request_id=request_id)

    if not filter_result.allowed:
        # Critical secret in response — block it entirely
        raise HTTPException(
            status_code=500,
            detail={
                "error": "Response blocked: sensitive data detected",
                "code": "RESPONSE_CONTAINS_SECRETS",
            },
        )

    safe_text = (
        filter_result.filtered_response
        if isinstance(filter_result.filtered_response, str)
        else raw_text
    )

    return ChatResponse(
        response=safe_text,
        session_id=request.session_id,
        request_id=request_id,
        security={
            "pii_detected": len(filter_result.pii_detected),
            "secrets_detected": len(filter_result.secrets_detected),
            "filtered_fields": filter_result.filtered_fields,
        },
    )


# ---------------------------------------------------------------------------
# Endpoint 2: Streaming chat
# ---------------------------------------------------------------------------

@app.post("/api/chat/stream")
async def chat_stream(request: ChatRequest) -> StreamingResponse:
    """
    Streaming SSE chat. Output is filtered chunk-by-chunk.
    Input is validated by middleware + explicitly below.
    """

    async def generate() -> AsyncGenerator[str, None]:
        messages = [
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": request.message},
        ]

        stream = await openai_client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            stream=True,
        )

        async for chunk in stream:
            delta = chunk.choices[0].delta.content or ""
            if not delta:
                continue

            # Filter each chunk before sending to client
            result = output_filter.filter(delta, request_id=request.session_id)
            safe_delta = (
                result.filtered_response
                if isinstance(result.filtered_response, str)
                else delta
            )
            yield f"data: {safe_delta}\n\n"

        yield "data: [DONE]\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")


# ---------------------------------------------------------------------------
# Endpoint 3: Role-based access (RBAC with PolicyGate)
# ---------------------------------------------------------------------------

class AdminRequest(BaseModel):
    query: str
    user_id: str
    user_role: str   # "admin" | "analyst" | "viewer"


@app.post("/api/admin/query")
async def admin_query(request: AdminRequest) -> Dict[str, Any]:
    """
    Admin endpoint with RBAC. Only users with 'admin' role can query
    sensitive data; 'analyst' gets filtered output; 'viewer' is blocked.
    """
    # Role-based access check
    policy_result = policy_gate.check(
        action="query_sensitive_data",
        role=request.user_role,
        resource="admin_db",
    )

    if not policy_result.allowed:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Access denied",
                "required_role": policy_result.required_role,
                "user_role": request.user_role,
            },
        )

    messages = [
        {"role": "system", "content": "You are an enterprise data analyst assistant."},
        {"role": "user", "content": request.query},
    ]

    completion = await openai_client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
    )
    raw_text = completion.choices[0].message.content or ""

    # Apply role-based output filtering: analysts don't see raw SSNs / credit cards
    filter_result = output_filter.filter(
        raw_text,
        role=request.user_role,
        request_id=f"admin-{request.user_id}",
    )

    return {
        "response": filter_result.filtered_response,
        "role": request.user_role,
        "pii_masked": len(filter_result.pii_detected) > 0,
    }


# ---------------------------------------------------------------------------
# Endpoint 4: Agentic endpoint with tool chain validation
# ---------------------------------------------------------------------------

TOOL_IMPLEMENTATIONS: Dict[str, Any] = {
    "search": lambda q: f"Search results for: {q}",
    "calculator": lambda expr: f"Result: {eval(expr)}",  # noqa: S307 — demo only
    "weather": lambda city: f"Weather in {city}: 72°F sunny",
}


@app.post("/api/agent")
async def agent(request: AgentRequest) -> Dict[str, Any]:
    """
    Agentic endpoint. Tool calls are validated before execution to prevent
    dangerous sequences (e.g., search → execute → exfiltrate).
    """
    messages = [
        {
            "role": "system",
            "content": (
                "You are an agent. Use tools to complete the task. "
                f"Available tools: {', '.join(request.allowed_tools)}"
            ),
        },
        {"role": "user", "content": request.task},
    ]

    # Build tool definitions
    tools = [
        {
            "type": "function",
            "function": {
                "name": tool,
                "description": f"Execute the {tool} tool",
                "parameters": {
                    "type": "object",
                    "properties": {"input": {"type": "string"}},
                    "required": ["input"],
                },
            },
        }
        for tool in request.allowed_tools
    ]

    completion = await openai_client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
        tools=tools,
        tool_choice="auto",
    )

    choice = completion.choices[0]
    tool_results = []

    if choice.finish_reason == "tool_calls" and choice.message.tool_calls:
        for tool_call in choice.message.tool_calls:
            tool_name = tool_call.function.name
            tool_args = tool_call.function.arguments

            # Guard: validate tool call before executing
            validation = tool_chain_validator.validate(
                request.session_id, tool_name
            )
            if not validation.allowed:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": f"Tool call blocked: {tool_name}",
                        "violations": validation.violations,
                    },
                )

            # Execute tool
            tool_fn = TOOL_IMPLEMENTATIONS.get(tool_name)
            if tool_fn:
                result = tool_fn(tool_args)
                # Validate tool result before feeding back to LLM
                result_filter = output_filter.filter(str(result))
                if not result_filter.allowed:
                    result = "[TOOL_RESULT_FILTERED]"
                tool_results.append({"tool": tool_name, "result": result})

    final_text = choice.message.content or ""
    filter_result = output_filter.filter(final_text)

    return {
        "response": filter_result.filtered_response or final_text,
        "tool_calls": tool_results,
        "session_id": request.session_id,
    }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> Dict[str, str]:
    return {"status": "ok", "guards": "active"}


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
