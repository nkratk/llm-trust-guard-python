"""
llm-trust-guard — 31 security guards for LLM-powered applications.

Zero dependencies. Covers OWASP Top 10 for LLMs 2025, Agentic AI 2026, and MCP Security.
"""

# Input Guards
from llm_trust_guard.guards.input_sanitizer import InputSanitizer, SanitizerResult
from llm_trust_guard.guards.encoding_detector import EncodingDetector, EncodingDetectorConfig
from llm_trust_guard.guards.compression_detector import CompressionDetector, CompressionDetectorResult
from llm_trust_guard.guards.heuristic_analyzer import HeuristicAnalyzer, HeuristicResult, HeuristicFeatures, HeuristicAnalyzerConfig
from llm_trust_guard.guards.prompt_leakage_guard import PromptLeakageGuard, PromptLeakageResult
from llm_trust_guard.guards.conversation_guard import ConversationGuard, ConversationGuardConfig
from llm_trust_guard.guards.context_budget_guard import ContextBudgetGuard, ContextBudgetResult
from llm_trust_guard.guards.multimodal_guard import MultiModalGuard, MultiModalGuardConfig, MultiModalContent, MultiModalGuardResult

# Access Control Guards
from llm_trust_guard.guards.tool_registry import ToolRegistry, ToolRegistryConfig
from llm_trust_guard.guards.policy_gate import PolicyGate, PolicyGateConfig
from llm_trust_guard.guards.tenant_boundary import TenantBoundary, TenantBoundaryConfig
from llm_trust_guard.guards.schema_validator import SchemaValidator, SchemaValidatorConfig
from llm_trust_guard.guards.execution_monitor import ExecutionMonitor, ExecutionMonitorConfig
from llm_trust_guard.guards.token_cost_guard import TokenCostGuard, TokenCostResult

# Output Guards
from llm_trust_guard.guards.output_filter import OutputFilter, OutputFilterResult
from llm_trust_guard.guards.output_schema_guard import OutputSchemaGuard, OutputSchemaResult
from llm_trust_guard.guards.tool_result_guard import ToolResultGuard, ToolResultGuardResult

# Agentic Guards
from llm_trust_guard.guards.tool_chain_validator import ToolChainValidator, ToolChainValidatorConfig
from llm_trust_guard.guards.agent_communication_guard import AgentCommunicationGuard, AgentCommunicationGuardConfig
from llm_trust_guard.guards.trust_exploitation_guard import TrustExploitationGuard, TrustExploitationResult
from llm_trust_guard.guards.autonomy_escalation_guard import AutonomyEscalationGuard, AutonomyEscalationResult
from llm_trust_guard.guards.mcp_security_guard import MCPSecurityGuard, MCPSecurityResult, MCPToolCall, MCPServerIdentity
from llm_trust_guard.guards.code_execution_guard import CodeExecutionGuard, CodeAnalysisResult

# Data Guards
from llm_trust_guard.guards.memory_guard import MemoryGuard, MemoryGuardResult
from llm_trust_guard.guards.rag_guard import RAGGuard, RAGGuardResult, RAGDocument
from llm_trust_guard.guards.state_persistence_guard import StatePersistenceGuard, StatePersistenceResult

# Architectural Guards (v4.13)
from llm_trust_guard.guards.external_data_guard import ExternalDataGuard, ExternalDataGuardResult, DataProvenance
from llm_trust_guard.guards.agent_skill_guard import AgentSkillGuard, AgentSkillGuardResult, SkillDefinition, SkillThreat
from llm_trust_guard.guards.session_integrity_guard import SessionIntegrityGuard, SessionIntegrityResult, SessionState

# Infrastructure Guards
from llm_trust_guard.guards.circuit_breaker import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerResult
from llm_trust_guard.guards.drift_detector import DriftDetector, DriftDetectorResult

# Facade
from llm_trust_guard.trust_guard import TrustGuard, TrustGuardResult, SessionContext, FilterOutputResult, ValidateToolResultOutput, ValidateOutputResult, GuardMetrics

# Detection Backend
from llm_trust_guard.detection_backend import DetectionClassifier, DetectionContext, DetectionResult, DetectionThreat, create_regex_classifier, merge_detection_results

# Integrations
from llm_trust_guard.integrations.fastapi_integration import TrustGuardMiddleware, create_tool_rate_limit_middleware, create_output_filter_middleware
from llm_trust_guard.integrations.langchain_integration import TrustGuardLangChain, TrustGuardViolationError, create_input_validator, create_output_filter
from llm_trust_guard.integrations.openai_integration import SecureOpenAI, OpenAISecurityError, create_message_validator, wrap_openai_client

__version__ = "0.4.0"

__all__ = [
    # Input Guards
    "InputSanitizer", "SanitizerResult",
    "EncodingDetector", "EncodingDetectorConfig",
    "CompressionDetector", "CompressionDetectorResult",
    "HeuristicAnalyzer", "HeuristicResult", "HeuristicFeatures", "HeuristicAnalyzerConfig",
    "PromptLeakageGuard", "PromptLeakageResult",
    "ConversationGuard", "ConversationGuardConfig",
    "ContextBudgetGuard", "ContextBudgetResult",
    "MultiModalGuard", "MultiModalGuardConfig", "MultiModalContent", "MultiModalGuardResult",
    # Access Control
    "ToolRegistry", "ToolRegistryConfig",
    "PolicyGate", "PolicyGateConfig",
    "TenantBoundary", "TenantBoundaryConfig",
    "SchemaValidator", "SchemaValidatorConfig",
    "ExecutionMonitor", "ExecutionMonitorConfig",
    "TokenCostGuard", "TokenCostResult",
    # Output
    "OutputFilter", "OutputFilterResult",
    "OutputSchemaGuard", "OutputSchemaResult",
    "ToolResultGuard", "ToolResultGuardResult",
    # Agentic
    "ToolChainValidator", "ToolChainValidatorConfig",
    "AgentCommunicationGuard", "AgentCommunicationGuardConfig",
    "TrustExploitationGuard", "TrustExploitationResult",
    "AutonomyEscalationGuard", "AutonomyEscalationResult",
    "MCPSecurityGuard", "MCPSecurityResult", "MCPToolCall", "MCPServerIdentity",
    "CodeExecutionGuard", "CodeAnalysisResult",
    # Data
    "MemoryGuard", "MemoryGuardResult",
    "RAGGuard", "RAGGuardResult", "RAGDocument",
    "StatePersistenceGuard", "StatePersistenceResult",
    # Architectural
    "ExternalDataGuard", "ExternalDataGuardResult", "DataProvenance",
    "AgentSkillGuard", "AgentSkillGuardResult", "SkillDefinition", "SkillThreat",
    "SessionIntegrityGuard", "SessionIntegrityResult", "SessionState",
    # Infrastructure
    "CircuitBreaker", "CircuitBreakerConfig", "CircuitBreakerResult",
    "DriftDetector", "DriftDetectorResult",
    # Facade
    "TrustGuard", "TrustGuardResult", "SessionContext",
    "FilterOutputResult", "ValidateToolResultOutput", "ValidateOutputResult", "GuardMetrics",
    # Detection Backend
    "DetectionClassifier", "DetectionContext", "DetectionResult", "DetectionThreat",
    "create_regex_classifier", "merge_detection_results",
    # Integrations
    "TrustGuardMiddleware", "create_tool_rate_limit_middleware", "create_output_filter_middleware",
    "TrustGuardLangChain", "TrustGuardViolationError", "create_input_validator", "create_output_filter",
    "SecureOpenAI", "OpenAISecurityError", "create_message_validator", "wrap_openai_client",
]
