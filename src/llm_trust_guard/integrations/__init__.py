"""
Integration helpers for llm-trust-guard.

Provides ready-to-use wrappers for FastAPI, LangChain, and OpenAI.
All integrations are zero-dependency: FastAPI, LangChain, and OpenAI
are optional imports that are only required at runtime if the
integration is actually used.
"""

from llm_trust_guard.integrations.fastapi_integration import (
    TrustGuardMiddleware,
    create_tool_rate_limit_middleware,
    create_output_filter_middleware,
)
from llm_trust_guard.integrations.langchain_integration import (
    TrustGuardLangChain,
    TrustGuardViolationError,
    create_input_validator,
    create_output_filter,
)
from llm_trust_guard.integrations.openai_integration import (
    SecureOpenAI,
    OpenAISecurityError,
    create_message_validator,
    wrap_openai_client,
)

__all__ = [
    # FastAPI
    "TrustGuardMiddleware",
    "create_tool_rate_limit_middleware",
    "create_output_filter_middleware",
    # LangChain
    "TrustGuardLangChain",
    "TrustGuardViolationError",
    "create_input_validator",
    "create_output_filter",
    # OpenAI
    "SecureOpenAI",
    "OpenAISecurityError",
    "create_message_validator",
    "wrap_openai_client",
]
