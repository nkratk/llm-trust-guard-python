"""
TrustGuard — Main facade that wires all 31 guards together.

Usage:
    from llm_trust_guard import TrustGuard

    guard = TrustGuard({
        "sanitizer": {"threshold": 0.7},
        "registry": {"tools": [...]},
        "policy": {"role_hierarchy": {"customer": 0, "admin": 1}},
    })

    result = guard.check("tool_name", {"key": "value"}, session)
    if not result.allowed:
        print(f"Blocked: {result.block_reason}")

Zero dependencies. Config is a plain dict — more Pythonic for a facade with many optional params.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional, Sequence
from uuid import uuid4

# Import all 31 guards
from llm_trust_guard.guards.input_sanitizer import InputSanitizer
from llm_trust_guard.guards.encoding_detector import EncodingDetector
from llm_trust_guard.guards.compression_detector import CompressionDetector
from llm_trust_guard.guards.heuristic_analyzer import HeuristicAnalyzer
from llm_trust_guard.guards.prompt_leakage_guard import PromptLeakageGuard
from llm_trust_guard.guards.conversation_guard import ConversationGuard
from llm_trust_guard.guards.context_budget_guard import ContextBudgetGuard
from llm_trust_guard.guards.multimodal_guard import MultiModalGuard

from llm_trust_guard.guards.tool_registry import ToolRegistry
from llm_trust_guard.guards.policy_gate import PolicyGate
from llm_trust_guard.guards.tenant_boundary import TenantBoundary
from llm_trust_guard.guards.schema_validator import SchemaValidator
from llm_trust_guard.guards.execution_monitor import ExecutionMonitor
from llm_trust_guard.guards.token_cost_guard import TokenCostGuard

from llm_trust_guard.guards.output_filter import OutputFilter
from llm_trust_guard.guards.output_schema_guard import OutputSchemaGuard
from llm_trust_guard.guards.tool_result_guard import ToolResultGuard

from llm_trust_guard.guards.tool_chain_validator import ToolChainValidator
from llm_trust_guard.guards.agent_communication_guard import AgentCommunicationGuard
from llm_trust_guard.guards.trust_exploitation_guard import TrustExploitationGuard
from llm_trust_guard.guards.autonomy_escalation_guard import AutonomyEscalationGuard
from llm_trust_guard.guards.mcp_security_guard import MCPSecurityGuard
from llm_trust_guard.guards.code_execution_guard import CodeExecutionGuard

from llm_trust_guard.guards.memory_guard import MemoryGuard
from llm_trust_guard.guards.rag_guard import RAGGuard
from llm_trust_guard.guards.state_persistence_guard import StatePersistenceGuard

from llm_trust_guard.guards.external_data_guard import ExternalDataGuard
from llm_trust_guard.guards.agent_skill_guard import AgentSkillGuard
from llm_trust_guard.guards.session_integrity_guard import SessionIntegrityGuard

from llm_trust_guard.guards.circuit_breaker import CircuitBreaker
from llm_trust_guard.guards.drift_detector import DriftDetector

# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------

BlockLayer = Literal[
    "L1", "L2", "L3", "L4", "L5", "L6", "L7",
    "CONV", "CHAIN", "ENCODING", "MEMORY", "PROMPT_LEAKAGE",
    "AUTONOMY", "STATE", "CIRCUIT_BREAKER", "GUARD_ERROR",
]

FailMode = Literal["open", "closed"]


@dataclass
class SessionContext:
    """Session context for authenticated users."""
    user_id: str
    tenant_id: str
    role: str
    authenticated: bool
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class TrustGuardResult:
    """Combined result from all guard checks."""
    allowed: bool
    request_id: str
    all_violations: List[str] = field(default_factory=list)
    block_layer: Optional[BlockLayer] = None
    block_reason: Optional[str] = None
    # Per-guard results (populated when that guard runs)
    sanitizer: Optional[Any] = None
    registry: Optional[Any] = None
    policy: Optional[Any] = None
    tenant: Optional[Any] = None
    schema: Optional[Any] = None
    execution: Optional[Any] = None
    output: Optional[Any] = None
    conversation: Optional[Any] = None
    chain: Optional[Any] = None
    encoding: Optional[Any] = None


@dataclass
class FilterOutputResult:
    """Result from filter_output()."""
    allowed: bool
    filtered: Any
    pii_detected: bool
    secrets_detected: bool
    prompt_leakage_detected: bool


@dataclass
class ValidateToolResultOutput:
    """Result from validate_tool_result()."""
    allowed: bool
    violations: List[str]
    filtered: Optional[Any] = None


@dataclass
class ValidateOutputResult:
    """Result from validate_output()."""
    allowed: bool
    violations: List[str]
    threats: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class GuardMetrics:
    """Runtime metrics snapshot."""
    total_checks: int
    blocked_checks: int
    block_rate: float
    avg_execution_time_ms: float
    errors: int


# ---------------------------------------------------------------------------
# TrustGuardConfig type alias (documented dict keys)
# ---------------------------------------------------------------------------
# Config is intentionally a plain dict rather than a dataclass so callers can
# pass only the keys they care about without importing anything extra.
#
# Supported top-level keys (all optional):
#
#   sanitizer        — dict  (threshold, custom_patterns, detect_pap, ...)
#   encoding         — dict  (max_decoding_depth, max_encoded_ratio)
#   compression      — dict  (enabled)
#   heuristic        — dict  (enabled)
#   registry         — dict  (tools=[...])
#   policy           — dict  (role_hierarchy={...})
#   tenant           — dict  (resource_ownership={...})
#   schema           — dict  (strict_types)
#   execution        — dict  (max_requests_per_minute, ...)
#   output           — dict  (detect_pii, detect_secrets, role_filters)
#   conversation     — dict  (max_conversation_length, escalation_threshold)
#   chain            — dict  (max_tools_per_request, ...)
#   multimodal       — dict  (scan_metadata, ...)
#   memory           — dict  (enable_integrity_check, ...)
#   rag              — dict  (detect_injections, ...)
#   code_execution   — dict  (allowed_languages, ...)
#   agent_communication — dict (allowed_agents, ...)
#   circuit_breaker  — dict  (failure_threshold, ...)
#   drift_detector   — dict  (minimum_samples, ...)
#   mcp_security     — dict  (detect_tool_shadowing, ...)
#   prompt_leakage   — dict  (detect_leetspeak, ...)
#   trust_exploitation — dict (human_approval_required, ...)
#   autonomy_escalation — dict (max_autonomy_level, ...)
#   state_persistence — dict (enable_integrity_check, ...)
#   tool_result      — dict  (scan_for_injection, ...)
#   context_budget   — dict  (max_total_tokens, ...)
#   output_schema    — dict  (scan_for_injection, ...)
#   token_cost       — dict  (max_tokens_per_session, ...)
#   external_data    — dict  (enabled)
#   agent_skill      — dict  (enabled)
#   session_integrity — dict (enabled)
#
#   classifier       — async callable(input, context) -> result
#   max_input_length — int (default 100_000)
#   fail_mode        — "open" | "closed" (default "closed")
#   on_block         — callable(guard_name, result, request_id)
#   on_alert         — callable(guard_name, message, request_id)
#   on_error         — callable(guard_name, error, request_id)
#   logger           — logging.Logger or callable(msg, level)
#
TrustGuardConfig = Dict[str, Any]


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _enabled(section: Optional[Dict[str, Any]]) -> bool:
    """Return True if a config section is present and not explicitly disabled."""
    if section is None:
        return False
    return section.get("enabled", True) is not False


def _make_logger(cfg_logger: Any) -> Callable[[str, str], None]:
    """Normalise logger config into a (message, level) callable."""
    if cfg_logger is None:
        _log = logging.getLogger("llm_trust_guard")
        def _default(msg: str, level: str) -> None:
            getattr(_log, level, _log.info)(msg)
        return _default
    if isinstance(cfg_logger, logging.Logger):
        def _wrap(msg: str, level: str) -> None:
            getattr(cfg_logger, level, cfg_logger.info)(msg)
        return _wrap
    # Assume callable(msg, level)
    return cfg_logger


# ---------------------------------------------------------------------------
# TrustGuard facade
# ---------------------------------------------------------------------------

class TrustGuard:
    """Main facade for all 31 security guards.

    Protection Layers (Original):
      L1  Input Sanitizer     — prompt injection & PAP detection
      L2  Tool Registry       — tool hallucination prevention
      L3  Policy Gate         — RBAC with constraint validation
      L4  Tenant Boundary     — multi-tenant isolation
      L5  Schema Validator    — parameter validation & injection detection
      L6  Execution Monitor   — rate limiting & resource quotas
      L7  Output Filter       — PII scrubbing & secret detection
      Conversation Guard      — multi-turn manipulation detection
      Tool Chain Validator    — dangerous tool sequence detection
      Encoding Detector       — encoding bypass attack detection

    Protection Layers (2026):
      MultiModal Guard        — image/audio injection prevention
      Memory Guard            — memory poisoning prevention (ASI06)
      RAG Guard               — RAG document & embedding attack prevention
      Code Execution Guard    — safe code execution sandboxing
      Agent Communication     — multi-agent message security
      Circuit Breaker         — cascading failure prevention
      Drift Detector          — behavioral anomaly detection
      MCP Security Guard      — MCP tool shadowing prevention
      Prompt Leakage Guard    — system prompt extraction prevention
      Trust Exploitation      — trust boundary enforcement (ASI09)
      Autonomy Escalation     — unauthorized autonomy prevention (ASI10)
      State Persistence       — state corruption prevention (ASI08)

    Threat Coverage Guards:
      Tool Result Guard       — tool return-value validation
      Context Budget Guard    — context window budget enforcement
      Output Schema Guard     — structured output validation
      Token Cost Guard        — token/cost budget enforcement
      Heuristic Analyzer      — statistical feature analysis
      Compression Detector    — NCD-based payload detection

    Architectural Guards (v4.13):
      External Data Guard     — external data provenance
      Agent Skill Guard       — agent skill boundary enforcement
      Session Integrity Guard — session state integrity
    """

    def __init__(self, config: TrustGuardConfig | None = None) -> None:
        config = config or {}

        # Logger (set up first so guards can use it)
        self._log = _make_logger(config.get("logger"))

        # Top-level settings
        self._max_input_length: int = config.get("max_input_length", 100_000)
        self._fail_mode: FailMode = config.get("fail_mode", "closed")
        self._on_block: Optional[Callable] = config.get("on_block")
        self._on_alert: Optional[Callable] = config.get("on_alert")
        self._on_error: Optional[Callable] = config.get("on_error")

        # Metrics
        self._metrics = {
            "total_checks": 0,
            "blocked_checks": 0,
            "total_time_ms": 0.0,
            "errors": 0,
        }

        # Guard logger passthrough (some guards accept a logger kwarg)
        guard_logger = config.get("logger")

        # ----------------------------------------------------------------
        # Initialise guards — original layers
        # ----------------------------------------------------------------
        san_cfg = config.get("sanitizer") or {}
        self._sanitizer: Optional[InputSanitizer] = None
        if _enabled(san_cfg) or "sanitizer" not in config:
            self._sanitizer = InputSanitizer(
                threshold=san_cfg.get("threshold", 0.3),
                logger=guard_logger,
            )

        enc_cfg = config.get("encoding") or {}
        self._encoding: Optional[EncodingDetector] = None
        if _enabled(enc_cfg) or "encoding" not in config:
            self._encoding = EncodingDetector()

        # All guards use default constructors (no args).
        # The facade controls behavior via its own config, not by passing
        # config dicts to each guard. Guards are initialized with defaults.

        self._registry: Optional[ToolRegistry] = None
        self._policy: Optional[PolicyGate] = None

        reg_cfg = config.get("registry") or {}
        if _enabled(reg_cfg) and reg_cfg.get("tools"):
            from llm_trust_guard.guards.tool_registry import ToolRegistryConfig, ToolDefinition as TRToolDef
            tools = []
            for t in reg_cfg["tools"]:
                if isinstance(t, dict):
                    tools.append(TRToolDef(name=t.get("name", ""), description=t.get("description", ""), roles=t.get("roles", [])))
                else:
                    tools.append(t)
            self._registry = ToolRegistry(ToolRegistryConfig(tools=tools))
        if config.get("policy") is None or _enabled(config.get("policy")):
            self._policy = PolicyGate()

        self._tenant: Optional[TenantBoundary] = None
        self._schema: Optional[SchemaValidator] = None
        self._execution: Optional[ExecutionMonitor] = None
        self._output: Optional[OutputFilter] = None
        self._conversation: Optional[ConversationGuard] = None
        self._chain: Optional[ToolChainValidator] = None

        if config.get("tenant") is None or _enabled(config.get("tenant")):
            self._tenant = TenantBoundary()
        if config.get("schema") is None or _enabled(config.get("schema")):
            self._schema = SchemaValidator()
        if config.get("execution") is None or _enabled(config.get("execution")):
            self._execution = ExecutionMonitor()
        if config.get("output") is None or _enabled(config.get("output")):
            self._output = OutputFilter()
        if config.get("conversation") is None or _enabled(config.get("conversation")):
            self._conversation = ConversationGuard()
        if config.get("chain") is None or _enabled(config.get("chain")):
            self._chain = ToolChainValidator()

        # ----------------------------------------------------------------
        # 2026 guards (opt-in: only initialised when config section present)
        # ----------------------------------------------------------------
        self._multimodal: Optional[MultiModalGuard] = None
        self._memory_guard: Optional[MemoryGuard] = None
        self._rag_guard: Optional[RAGGuard] = None
        self._code_execution: Optional[CodeExecutionGuard] = None
        self._agent_communication: Optional[AgentCommunicationGuard] = None
        self._circuit_breaker: Optional[CircuitBreaker] = None

        self._drift_detector: Optional[DriftDetector] = None
        self._mcp_security: Optional[MCPSecurityGuard] = None
        self._prompt_leakage: Optional[PromptLeakageGuard] = None
        self._trust_exploitation: Optional[TrustExploitationGuard] = None
        self._autonomy_escalation: Optional[AutonomyEscalationGuard] = None
        self._state_persistence: Optional[StatePersistenceGuard] = None

        if _enabled(config.get("multimodal")):
            self._multimodal = MultiModalGuard()
        if _enabled(config.get("memory")):
            self._memory_guard = MemoryGuard()
        if _enabled(config.get("rag")):
            self._rag_guard = RAGGuard()
        if _enabled(config.get("code_execution")):
            self._code_execution = CodeExecutionGuard()
        if _enabled(config.get("agent_communication")):
            self._agent_communication = AgentCommunicationGuard()
        if _enabled(config.get("circuit_breaker")):
            self._circuit_breaker = CircuitBreaker()
        if _enabled(config.get("drift_detector")):
            self._drift_detector = DriftDetector()
        if _enabled(config.get("mcp_security")):
            self._mcp_security = MCPSecurityGuard()
        if _enabled(config.get("prompt_leakage")):
            self._prompt_leakage = PromptLeakageGuard()
        if _enabled(config.get("trust_exploitation")):
            self._trust_exploitation = TrustExploitationGuard()
        if _enabled(config.get("autonomy_escalation")):
            self._autonomy_escalation = AutonomyEscalationGuard()
        if _enabled(config.get("state_persistence")):
            self._state_persistence = StatePersistenceGuard()

        # ----------------------------------------------------------------
        # Threat coverage guards (opt-in)
        # ----------------------------------------------------------------
        self._tool_result: Optional[ToolResultGuard] = None
        self._context_budget: Optional[ContextBudgetGuard] = None
        self._output_schema: Optional[OutputSchemaGuard] = None
        self._token_cost: Optional[TokenCostGuard] = None
        self._heuristic: Optional[HeuristicAnalyzer] = None
        self._compression: Optional[CompressionDetector] = None

        if _enabled(config.get("tool_result")):
            self._tool_result = ToolResultGuard()
        if _enabled(config.get("context_budget")):
            self._context_budget = ContextBudgetGuard()
        if _enabled(config.get("output_schema")):
            self._output_schema = OutputSchemaGuard()
        if _enabled(config.get("token_cost")):
            self._token_cost = TokenCostGuard()
        if _enabled(config.get("heuristic")):
            self._heuristic = HeuristicAnalyzer()
        if _enabled(config.get("compression")):
            self._compression = CompressionDetector()

        # ----------------------------------------------------------------
        # Architectural guards (v4.13, opt-in)
        # ----------------------------------------------------------------
        self._external_data: Optional[ExternalDataGuard] = None
        self._agent_skill: Optional[AgentSkillGuard] = None
        self._session_integrity: Optional[SessionIntegrityGuard] = None

        if _enabled(config.get("external_data")):
            self._external_data = ExternalDataGuard()
        if _enabled(config.get("agent_skill")):
            self._agent_skill = AgentSkillGuard()
        if _enabled(config.get("session_integrity")):
            self._session_integrity = SessionIntegrityGuard()

        # Pluggable ML/API classifier (async callable)
        self._classifier: Optional[Callable] = config.get("classifier")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session: Optional[SessionContext] = None,
        *,
        user_input: Optional[str] = None,
        claimed_role: Optional[str] = None,
        all_tools_in_request: Optional[List[str]] = None,
    ) -> TrustGuardResult:
        """Run all enabled guards on a tool call (synchronous)."""
        request_id = f"req-{uuid4()}"
        self._log(f"[TrustGuard:{request_id}] Checking: {tool_name}", "info")

        start = time.monotonic()
        self._metrics["total_checks"] += 1

        try:
            result = self._run_checks(
                tool_name, params, session,
                user_input=user_input,
                claimed_role=claimed_role,
                all_tools_in_request=all_tools_in_request,
                request_id=request_id,
            )
            self._metrics["total_time_ms"] += (time.monotonic() - start) * 1000
            if not result.allowed:
                self._metrics["blocked_checks"] += 1
                if self._on_block:
                    self._on_block(result.block_layer or "UNKNOWN", result, request_id)
            return result

        except Exception as exc:
            self._metrics["total_time_ms"] += (time.monotonic() - start) * 1000
            self._metrics["errors"] += 1
            err_msg = str(exc)
            self._log(f"[TrustGuard:{request_id}] Guard error: {err_msg}", "error")
            if self._on_error:
                self._on_error("TrustGuard", exc, request_id)

            if self._fail_mode == "open":
                return TrustGuardResult(
                    allowed=True,
                    all_violations=["GUARD_ERROR"],
                    request_id=request_id,
                )
            return TrustGuardResult(
                allowed=False,
                block_reason=f"Internal guard error: {err_msg}",
                all_violations=["GUARD_ERROR"],
                request_id=request_id,
            )

    async def check_async(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session: Optional[SessionContext] = None,
        *,
        user_input: Optional[str] = None,
        claimed_role: Optional[str] = None,
        all_tools_in_request: Optional[List[str]] = None,
    ) -> TrustGuardResult:
        """Async version of check() that also runs the pluggable classifier.

        Falls back to sync check() when no classifier is configured.
        """
        sync_result = self.check(
            tool_name, params, session,
            user_input=user_input,
            claimed_role=claimed_role,
            all_tools_in_request=all_tools_in_request,
        )

        # If no classifier, or sync already blocked, return early
        if not self._classifier or not sync_result.allowed or not user_input:
            return sync_result

        try:
            classifier_result = await self._classifier(user_input, {
                "type": "user_input",
                "session_id": session.session_id if session else None,
            })

            if not classifier_result.get("safe", True):
                threats = classifier_result.get("threats", [])
                categories = [t.get("category", "unknown") for t in threats]
                return TrustGuardResult(
                    allowed=False,
                    block_layer="L1",
                    block_reason=f"Classifier detected threat: {', '.join(categories)}",
                    all_violations=[
                        *sync_result.all_violations,
                        *[f"CLASSIFIER_{c.upper()}" for c in categories],
                    ],
                    request_id=sync_result.request_id,
                )
        except Exception as exc:
            self._log(f"[TrustGuard] Classifier error: {exc}", "error")
            # Classifier failure doesn't block (sync guards already passed)

        return sync_result

    def filter_output(
        self,
        output: Any,
        role: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> FilterOutputResult:
        """Filter output for PII, secrets, and prompt leakage (L7 + Prompt Leakage)."""
        filtered = output
        pii_detected = False
        secrets_detected = False
        prompt_leakage_detected = False
        allowed = True

        output_str = output if isinstance(output, str) else ""
        if len(output_str) > self._max_input_length:
            self._log(
                f"[TrustGuard] Output too long ({len(output_str)}), truncating for filter",
                "warn",
            )

        # L7: PII and secret filtering
        if self._output:
            result = self._output.filter(output, role, request_id)
            filtered = getattr(result, "filtered_response", filtered)
            pii_detected = bool(getattr(result, "pii_detected", []))
            secrets_detected = bool(getattr(result, "secrets_detected", []))
            if not getattr(result, "allowed", True):
                allowed = False

        # Prompt leakage output check
        if self._prompt_leakage:
            out_str = filtered if isinstance(filtered, str) else json.dumps(filtered)
            leakage_result = self._prompt_leakage.check_output(out_str, request_id)
            if getattr(leakage_result, "leaked", False):
                allowed = False
                prompt_leakage_detected = True
                sanitized = getattr(leakage_result, "sanitized_output", None)
                if sanitized:
                    filtered = sanitized

        return FilterOutputResult(
            allowed=allowed,
            filtered=filtered,
            pii_detected=pii_detected,
            secrets_detected=secrets_detected,
            prompt_leakage_detected=prompt_leakage_detected,
        )

    def validate_tool_result(
        self,
        tool_name: str,
        result: Any,
        request_id: Optional[str] = None,
    ) -> ValidateToolResultOutput:
        """Validate a tool's return value before feeding it back to the LLM context."""
        if not self._tool_result:
            return ValidateToolResultOutput(allowed=True, violations=[])

        guard_result = self._tool_result.validate_result(tool_name, result, request_id)
        return ValidateToolResultOutput(
            allowed=guard_result.allowed,
            violations=guard_result.violations,
        )

    def validate_output(
        self,
        output: Any,
        schema_name: Optional[str] = None,
        request_id: Optional[str] = None,
    ) -> ValidateOutputResult:
        """Validate LLM structured output before sending to downstream systems."""
        if not self._output_schema:
            return ValidateOutputResult(allowed=True, violations=[])

        result = self._output_schema.validate(output, schema_name, request_id)
        return ValidateOutputResult(
            allowed=result.allowed,
            violations=result.violations,
            threats=getattr(result, "threats", []),
        )

    def complete_operation(
        self,
        session: Optional[SessionContext] = None,
        tool_name: Optional[str] = None,
        success: bool = True,
    ) -> None:
        """Mark an operation as complete (for rate limiting and circuit breaker)."""
        if self._execution:
            self._execution.complete_operation(
                getattr(session, "user_id", None),
                getattr(session, "session_id", None),
            )
        if self._circuit_breaker and tool_name:
            if success:
                self._circuit_breaker.record_success(tool_name)
            else:
                self._circuit_breaker.record_failure(tool_name)

    def get_tools_for_role(self, role: str) -> List[Any]:
        """Get tools available for a role."""
        if self._registry:
            return self._registry.get_tools_for_role(role)
        return []

    def get_metrics(self) -> GuardMetrics:
        """Get runtime metrics for monitoring."""
        total = self._metrics["total_checks"]
        avg = (self._metrics["total_time_ms"] / total) if total > 0 else 0.0
        return GuardMetrics(
            total_checks=total,
            blocked_checks=self._metrics["blocked_checks"],
            block_rate=self._metrics["blocked_checks"] / total if total > 0 else 0.0,
            avg_execution_time_ms=round(avg * 100) / 100,
            errors=self._metrics["errors"],
        )

    def get_guards(self) -> Dict[str, Any]:
        """Get individual guard instances for advanced usage."""
        return {
            # Original guards
            "sanitizer": self._sanitizer,
            "registry": self._registry,
            "policy": self._policy,
            "tenant": self._tenant,
            "schema": self._schema,
            "execution": self._execution,
            "output": self._output,
            "conversation": self._conversation,
            "chain": self._chain,
            "encoding": self._encoding,
            # 2026 guards
            "multimodal": self._multimodal,
            "memory": self._memory_guard,
            "rag": self._rag_guard,
            "code_execution": self._code_execution,
            "agent_communication": self._agent_communication,
            "circuit_breaker": self._circuit_breaker,
            "drift_detector": self._drift_detector,
            "mcp_security": self._mcp_security,
            "prompt_leakage": self._prompt_leakage,
            "trust_exploitation": self._trust_exploitation,
            "autonomy_escalation": self._autonomy_escalation,
            "state_persistence": self._state_persistence,
            # Threat coverage guards
            "tool_result": self._tool_result,
            "context_budget": self._context_budget,
            "output_schema": self._output_schema,
            "token_cost": self._token_cost,
            "heuristic": self._heuristic,
            "compression": self._compression,
            # Architectural guards
            "external_data": self._external_data,
            "agent_skill": self._agent_skill,
            "session_integrity": self._session_integrity,
        }

    def reset_session(self, session_id: str) -> None:
        """Reset session state across all session-aware guards."""
        if self._conversation:
            self._conversation.reset_session(session_id)
        if self._chain:
            self._chain.reset_session(session_id)
        if self._execution:
            self._execution.reset(None, session_id)
        if self._memory_guard:
            self._memory_guard.clear_session(session_id)
        if self._trust_exploitation:
            self._trust_exploitation.reset_session(session_id)
        if self._autonomy_escalation:
            self._autonomy_escalation.reset_session(session_id)
        if self._state_persistence:
            self._state_persistence.reset_session(session_id)
        if self._context_budget:
            self._context_budget.reset_session(session_id)

    def destroy(self) -> None:
        """Destroy all guards and release resources.

        Call on server shutdown or when the guard instance is no longer needed.
        """
        if self._conversation:
            self._conversation.destroy()
        if self._agent_communication:
            self._agent_communication.destroy()
        if self._context_budget:
            self._context_budget.destroy()
        if self._token_cost:
            self._token_cost.destroy()
        if self._execution:
            self._execution.reset()
        if self._circuit_breaker:
            self._circuit_breaker.reset_all()
        if self._drift_detector and hasattr(self._drift_detector, "reset_agent"):
            self._drift_detector.reset_agent("*")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _run_checks(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session: Optional[SessionContext],
        *,
        user_input: Optional[str],
        claimed_role: Optional[str],
        all_tools_in_request: Optional[List[str]],
        request_id: str,
    ) -> TrustGuardResult:
        all_violations: List[str] = []

        # Input length limit
        if user_input and len(user_input) > self._max_input_length:
            self._log(
                f"[TrustGuard:{request_id}] BLOCKED: Input too long "
                f"({len(user_input)} > {self._max_input_length})",
                "warn",
            )
            return TrustGuardResult(
                allowed=False,
                block_layer="L1",
                block_reason=(
                    f"Input length {len(user_input)} exceeds maximum {self._max_input_length}"
                ),
                all_violations=["INPUT_TOO_LONG"],
                request_id=request_id,
            )

        # Encoding Detection (pre-L1)
        if self._encoding and user_input:
            enc_result = self._encoding.detect(user_input)
            if not enc_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by Encoding Detector", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="ENCODING",
                    block_reason=enc_result.reason,
                    all_violations=enc_result.violations,
                    encoding=enc_result,
                    request_id=request_id,
                )
            all_violations.extend(enc_result.violations)

        # L1: Input Sanitization
        if self._sanitizer and user_input:
            san_result = self._sanitizer.sanitize(user_input)
            if not san_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by L1", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="L1",
                    block_reason=san_result.reason,
                    all_violations=san_result.violations,
                    sanitizer=san_result,
                    request_id=request_id,
                )
            all_violations.extend(san_result.violations)

        # Prompt Leakage Guard (input extraction attempts)
        if self._prompt_leakage and user_input:
            leak_result = self._prompt_leakage.check(user_input, request_id)
            if not leak_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by Prompt Leakage Guard", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="PROMPT_LEAKAGE",
                    block_reason=leak_result.reason,
                    all_violations=[*all_violations, *leak_result.violations],
                    request_id=request_id,
                )
            all_violations.extend(leak_result.violations)

        # Memory Guard (context injection in user input)
        session_id = getattr(session, "session_id", None)
        if self._memory_guard and user_input and session_id:
            mem_result = self._memory_guard.validate_context_injection(
                user_input, session_id, request_id,
            )
            if not mem_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by Memory Guard", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="MEMORY",
                    block_reason=mem_result.reason,
                    all_violations=[*all_violations, *mem_result.violations],
                    request_id=request_id,
                )
            all_violations.extend(mem_result.violations)

        # Conversation Guard
        if self._conversation and user_input and session_id:
            conv_result = self._conversation.check(
                session_id, user_input, [tool_name], claimed_role, request_id,
            )
            if not conv_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by Conversation Guard", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="CONV",
                    block_reason=conv_result.reason,
                    all_violations=[*all_violations, *conv_result.violations],
                    conversation=conv_result,
                    request_id=request_id,
                )
            all_violations.extend(conv_result.violations)

        # L2: Tool Registry
        tool = None
        if self._registry:
            reg_result = self._registry.check(
                tool_name, getattr(session, "role", ""), request_id,
            )
            if not reg_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by L2", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="L2",
                    block_reason=reg_result.reason,
                    all_violations=[*all_violations, *reg_result.violations],
                    registry=reg_result,
                    request_id=request_id,
                )
            tool = getattr(reg_result, "tool", None)
            all_violations.extend(reg_result.violations)

        # Tool Chain Validator
        if self._chain and session_id:
            if all_tools_in_request:
                chain_result = self._chain.validate_batch(
                    session_id, all_tools_in_request, request_id,
                )
            else:
                chain_result = self._chain.validate(
                    session_id, tool_name, None, request_id,
                )
            if not chain_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by Tool Chain Validator", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="CHAIN",
                    block_reason=chain_result.reason,
                    all_violations=[*all_violations, *chain_result.violations],
                    chain=chain_result,
                    request_id=request_id,
                )
            all_violations.extend(chain_result.violations)

        # L3: Policy Gate
        if self._policy and tool:
            pol_result = self._policy.check(
                tool, params, session, claimed_role, request_id,
            )
            if not pol_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by L3", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="L3",
                    block_reason=pol_result.reason,
                    all_violations=[*all_violations, *pol_result.violations],
                    policy=pol_result,
                    request_id=request_id,
                )
            all_violations.extend(pol_result.violations)
        elif self._policy and not tool:
            self._log(
                f"[TrustGuard:{request_id}] Policy gate skipped: no tool definition "
                "(registry disabled or tool not found)",
                "warn",
            )

        # Autonomy Escalation Guard (after tool validation)
        if self._autonomy_escalation and session_id:
            auto_result = self._autonomy_escalation.validate(
                tool_name, session_id, params, request_id,
            )
            if not auto_result.allowed:
                self._log(
                    f"[TrustGuard:{request_id}] BLOCKED by Autonomy Escalation Guard", "warn",
                )
                return TrustGuardResult(
                    allowed=False,
                    block_layer="AUTONOMY",
                    block_reason=auto_result.reason,
                    all_violations=[*all_violations, *auto_result.violations],
                    request_id=request_id,
                )
            all_violations.extend(auto_result.violations)

        # L4: Tenant Boundary (skip if no session — don't block for missing context)
        enforced_params = params
        if self._tenant and session is not None:
            ten_result = self._tenant.check(tool_name, params, session, request_id)
            if not ten_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by L4", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="L4",
                    block_reason=ten_result.reason,
                    all_violations=[*all_violations, *ten_result.violations],
                    tenant=ten_result,
                    request_id=request_id,
                )
            if getattr(ten_result, "enforced_params", None):
                enforced_params = ten_result.enforced_params
            all_violations.extend(ten_result.violations)

        # L5: Schema Validation
        if self._schema and tool:
            sch_result = self._schema.validate(tool, enforced_params, request_id)
            if not sch_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by L5", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="L5",
                    block_reason=sch_result.reason,
                    all_violations=[*all_violations, *sch_result.violations],
                    schema=sch_result,
                    request_id=request_id,
                )
            all_violations.extend(sch_result.violations)

        # L6: Execution Monitor (rate limiting)
        if self._execution:
            exec_result = self._execution.check(
                tool_name,
                getattr(session, "user_id", None),
                session_id,
                request_id,
            )
            if not exec_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by L6", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="L6",
                    block_reason=exec_result.reason,
                    all_violations=[*all_violations, *exec_result.violations],
                    execution=exec_result,
                    request_id=request_id,
                )
            all_violations.extend(exec_result.violations)

        # Circuit Breaker check
        if self._circuit_breaker:
            cb_result = self._circuit_breaker.check(tool_name, request_id)
            if not cb_result.allowed:
                self._log(f"[TrustGuard:{request_id}] BLOCKED by Circuit Breaker", "warn")
                return TrustGuardResult(
                    allowed=False,
                    block_layer="CIRCUIT_BREAKER",
                    block_reason=cb_result.reason,
                    all_violations=[*all_violations, "CIRCUIT_OPEN"],
                    request_id=request_id,
                )

        self._log(f"[TrustGuard:{request_id}] All checks PASSED", "info")

        return TrustGuardResult(
            allowed=True,
            all_violations=all_violations,
            request_id=request_id,
        )
