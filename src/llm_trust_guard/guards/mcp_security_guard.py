"""
MCPSecurityGuard (L16)

Secures Model Context Protocol (MCP) tool integrations.
Prevents tool shadowing, server impersonation, supply chain attacks,
and MCP Sampling channel attacks.

Threat Model:
- ASI04: Agentic Supply Chain Vulnerabilities
- CVE-2025-68145, CVE-2025-68143, CVE-2025-68144: MCP RCE vulnerabilities
- CVE-2025-6514: mcp-remote command injection
- CVE-2025-32711: EchoLeak - silent data exfiltration
- Tool Shadowing: Malicious MCP servers impersonating legitimate tools
- MCP Sampling Attacks (Unit42 + Blueinfy, Feb 2026): Three concrete vectors
  delivered through the MCP sampling response channel:
  (1) Resource drain -- hidden prompt appends that trigger infinite tool loops
      or token exhaustion to degrade or DoS the agent runtime
  (2) Conversation hijacking -- injecting fake user/assistant turns or system
      prompt overrides into the sampling response body to redirect agent behavior
  (3) Covert tool invocation -- embedding tool-call syntax (Anthropic XML,
      OpenAI JSON, bracket notation) in plain-text sampling responses to cause
      the agent to invoke tools without user awareness

Protection Capabilities:
- MCP server identity verification (signature-based)
- Tool registration allowlist enforcement
- Dynamic tool registration monitoring
- OAuth endpoint validation
- Tool shadowing detection
- Server reputation scoring
- Command injection prevention
- Sampling response scanning (resource drain, conversation hijack, covert tool calls)

Upstream SDK advisory -- cannot be mitigated at the detection layer:
- CVE-2026-25536 (@modelcontextprotocol/sdk 1.10.0-1.25.3, CVSS 7.1):
  Cross-client response data leak when a single McpServer/Server and
  transport instance is reused across multiple client connections
  (common in stateless StreamableHTTPServerTransport deployments).
  Fix: upgrade @modelcontextprotocol/sdk to >=1.26.0. This guard cannot
  prevent the leak -- it is a server-library bug -- but tool-response
  session-binding violations caught here can surface related symptoms.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def _now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class MCPServerIdentity:
    """MCP server identity."""
    server_id: str
    name: str
    version: Optional[str] = None
    public_key: Optional[str] = None
    trusted_domains: Optional[List[str]] = None
    allowed_tools: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None
    registered_at: Optional[int] = None
    reputation_score: Optional[int] = None


@dataclass
class MCPToolDefinition:
    """MCP tool definition."""
    name: str
    description: str
    server_id: str
    parameters: Optional[Dict[str, Any]] = None
    capabilities: Optional[List[str]] = None
    risk_level: Optional[str] = None  # "low" | "medium" | "high" | "critical"


@dataclass
class MCPOAuthConfig:
    """OAuth configuration."""
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    scopes: Optional[List[str]] = None


@dataclass
class MCPServerRegistration:
    """MCP server registration request."""
    server: MCPServerIdentity
    tools: List[MCPToolDefinition]
    oauth: Optional[MCPOAuthConfig] = None
    signature: Optional[str] = None
    timestamp: int = 0


@dataclass
class MCPToolCall:
    """MCP tool call request."""
    tool_name: str
    server_id: str
    parameters: Dict[str, Any]
    context: Optional[Dict[str, str]] = None


@dataclass
class MCPSamplingResponse:
    """Represents a response received from an MCP server via the sampling channel."""
    content: str
    server_id: str
    requested_by: Optional[str] = None
    conversation_id: Optional[str] = None


@dataclass
class MCPSamplingAnalysis:
    """Sampling attack analysis sub-result."""
    resource_drain_detected: bool
    conversation_hijack_detected: bool
    covert_tool_invocation_detected: bool
    pattern_matches: List[str]


@dataclass
class MCPServerAnalysis:
    """Server analysis sub-result."""
    server_verified: bool
    signature_valid: bool
    reputation_score: int
    is_shadowing: bool
    tools_allowed: bool


@dataclass
class MCPToolAnalysis:
    """Tool analysis sub-result."""
    tool_registered: bool
    tool_allowed: bool
    parameters_safe: bool
    injection_detected: bool
    risk_level: str


@dataclass
class MCPSecurityResult:
    """Result of MCP security validation."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    server_analysis: Optional[MCPServerAnalysis] = None
    tool_analysis: Optional[MCPToolAnalysis] = None
    sampling_analysis: Optional[MCPSamplingAnalysis] = None
    recommendations: List[str] = field(default_factory=list)


@dataclass
class MCPSecurityGuardConfig:
    """Configuration for MCPSecurityGuard."""
    require_server_signature: bool = False
    trusted_servers: List[MCPServerIdentity] = field(default_factory=list)
    blocked_servers: List[str] = field(default_factory=list)
    allow_dynamic_registration: bool = True
    tool_allowlist: List[str] = field(default_factory=list)
    tool_blocklist: List[str] = field(default_factory=list)
    validate_oauth_endpoints: bool = True
    allowed_oauth_domains: List[str] = field(default_factory=list)
    detect_tool_shadowing: bool = True
    min_server_reputation: int = 30
    strict_mode: bool = False
    custom_injection_patterns: List[re.Pattern[str]] = field(default_factory=list)


@dataclass
class _InjectionPattern:
    name: str
    pattern: re.Pattern[str]
    severity: int


@dataclass
class _ShadowingIndicator:
    legitimate: str
    suspicious: re.Pattern[str]


class MCPSecurityGuard:
    """Secures Model Context Protocol (MCP) tool integrations."""

    # MCP Sampling attack patterns (Unit42 + Blueinfy, Feb 2026)
    SAMPLING_ATTACK_PATTERNS: List[Dict[str, Any]] = [
        # Resource drain — instructions to loop or exhaust agent resources
        {"name": "sd_call_again", "type": "resource_drain",
         "pattern": re.compile(r'call\s+this\s+(?:again|once\s+more|repeatedly)|repeat\s+this\s+(?:call|request)|run\s+this\s+(?:again|tool\s+again)', re.IGNORECASE)},
        {"name": "sd_loop_until", "type": "resource_drain",
         "pattern": re.compile(r'loop\s+until|continue\s+(?:calling|running|until)|keep\s+(?:calling|running|generating|going)\s', re.IGNORECASE)},
        {"name": "sd_do_not_stop", "type": "resource_drain",
         "pattern": re.compile(r"do\s+not\s+stop\s+until|don'?t\s+stop\s+until|never\s+stop\s+generating|generate\s+as\s+many\s+as\s+possible", re.IGNORECASE)},
        {"name": "sd_n_times", "type": "resource_drain",
         "pattern": re.compile(r'\b\d{2,}\s+times\b|repeat\s+\d+\s+times|call\s+\d+\s+more\s+times', re.IGNORECASE)},
        {"name": "sd_exhaust_resources", "type": "resource_drain",
         "pattern": re.compile(r'exhaust\s+(?:all|resources|quota|rate.?limit)|max\s+out\s+(?:the\s+)?(?:quota|rate\s+limit)|use\s+all\s+(?:remaining\s+)?tokens', re.IGNORECASE)},
        # Conversation hijacking — role injection and system prompt override
        {"name": "sd_fake_user_turn", "type": "conversation_hijack",
         "pattern": re.compile(r'\n\s*(?:User|Human)\s*:\s*(?=\S)', re.IGNORECASE)},
        {"name": "sd_fake_assistant_turn", "type": "conversation_hijack",
         "pattern": re.compile(r'\n\s*(?:Assistant|AI|Bot|Claude|GPT)\s*:\s*(?=\S)', re.IGNORECASE)},
        {"name": "sd_role_json", "type": "conversation_hijack",
         "pattern": re.compile(r'"role"\s*:\s*"(?:system|user|assistant)"', re.IGNORECASE)},
        {"name": "sd_system_xml", "type": "conversation_hijack",
         "pattern": re.compile(r'<(?:system|user|assistant)\s*>|</(?:system|user|assistant)>', re.IGNORECASE)},
        {"name": "sd_from_now_on", "type": "conversation_hijack",
         "pattern": re.compile(r'from\s+now\s+on\s+you\s+(?:are|will|must)|henceforth\s+you|for\s+the\s+rest\s+of\s+(?:this\s+)?(?:conversation|session)\s+you', re.IGNORECASE)},
        {"name": "sd_new_instructions", "type": "conversation_hijack",
         "pattern": re.compile(r'your\s+new\s+(?:instructions|system\s+prompt|directives?)\s+(?:are|is)|updated\s+system\s+prompt|override\s+your\s+(?:system|instructions)', re.IGNORECASE)},
        {"name": "sd_ignore_previous", "type": "conversation_hijack",
         "pattern": re.compile(r'ignore\s+(?:all\s+)?(?:previous|prior|earlier)\s+instructions|disregard\s+(?:your\s+)?instructions', re.IGNORECASE)},
        # Covert tool invocation — tool call syntax embedded in plain-text response
        {"name": "sd_anthropic_tool_xml", "type": "covert_tool_invocation",
         "pattern": re.compile(r'<(?:tool_use|function_calls|invoke)[\s>]', re.IGNORECASE)},
        {"name": "sd_tool_result_xml", "type": "covert_tool_invocation",
         "pattern": re.compile(r'<(?:tool_result|function_result)[\s>]', re.IGNORECASE)},
        {"name": "sd_openai_tool_call", "type": "covert_tool_invocation",
         "pattern": re.compile(r'"type"\s*:\s*"tool_use"|"tool_calls"\s*:\s*\[', re.IGNORECASE)},
        {"name": "sd_bracket_tool_call", "type": "covert_tool_invocation",
         "pattern": re.compile(r'\[(?:TOOL|FUNCTION|CALL)\s*:', re.IGNORECASE)},
        {"name": "sd_double_brace_call", "type": "covert_tool_invocation",
         "pattern": re.compile(r'\{\{\s*(?:call|tool|function|invoke)\s*:', re.IGNORECASE)},
        {"name": "sd_invoke_name_attr", "type": "covert_tool_invocation",
         "pattern": re.compile(r'<invoke\s+name\s*=', re.IGNORECASE)},
    ]

    COMMAND_INJECTION_PATTERNS: List[_InjectionPattern] = [
        _InjectionPattern("shell_injection", re.compile(r'[;&|`$]|\$\(|\)\s*[;&|]|`[^`]+`'), 50),
        _InjectionPattern("command_substitution", re.compile(r'\$\{[^}]+\}|\$\([^)]+\)'), 50),
        _InjectionPattern("pipe_injection", re.compile(r'\|\s*(?:cat|rm|curl|wget|nc|bash|sh|exec)', re.IGNORECASE), 55),
        _InjectionPattern("path_traversal", re.compile(r'\.\.[/\\]|\.\.%2[fF]'), 45),
        _InjectionPattern("absolute_path", re.compile(r'^/(?:etc|usr|var|tmp|bin|root)', re.IGNORECASE), 40),
        _InjectionPattern("oauth_injection", re.compile(r'authorization_endpoint.*[;&|`$]', re.IGNORECASE), 55),
        _InjectionPattern("redirect_manipulation", re.compile(r'redirect_uri.*[^\w\-_.~:/?#\[\]@!$&\'()*+,;=%]', re.IGNORECASE), 45),
        _InjectionPattern("applescript_injection", re.compile(r'osascript|do\s+shell\s+script|tell\s+application', re.IGNORECASE), 55),
        _InjectionPattern("git_injection", re.compile(r'--upload-pack|--receive-pack|-c\s+core\.', re.IGNORECASE), 50),
        _InjectionPattern("git_url_injection", re.compile(r'ext::|file://|ssh://.*@', re.IGNORECASE), 45),
        _InjectionPattern("argument_injection", re.compile(r'\s--[a-z]+=.*[;&|`$]', re.IGNORECASE), 45),
        _InjectionPattern("env_injection", re.compile(r'\bLD_PRELOAD\b|\bPATH\s*=', re.IGNORECASE), 50),
    ]

    SHADOWING_INDICATORS: List[_ShadowingIndicator] = [
        _ShadowingIndicator("file_reader", re.compile(r'file[-_]?read(?:er)?s?|read[-_]?files?', re.IGNORECASE)),
        _ShadowingIndicator("database_query", re.compile(r'db[-_]?query|sql[-_]?query|query[-_]?db', re.IGNORECASE)),
        _ShadowingIndicator("email_sender", re.compile(r'send[-_]?emails?|email[-_]?send(?:er)?', re.IGNORECASE)),
        _ShadowingIndicator("api_caller", re.compile(r'call[-_]?api|api[-_]?call(?:er)?', re.IGNORECASE)),
        _ShadowingIndicator("code_executor", re.compile(r'exec[-_]?code|run[-_]?code|code[-_]?run', re.IGNORECASE)),
    ]

    MALICIOUS_SERVER_PATTERNS: List[re.Pattern[str]] = [
        re.compile(r'postmark-mcp.*fake', re.IGNORECASE),
        re.compile(r'unofficial', re.IGNORECASE),
        re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'),
        re.compile(r'pastebin|gist\.github', re.IGNORECASE),
        re.compile(r'temp|tmp|test.*mcp', re.IGNORECASE),
    ]

    def __init__(self, config: Optional[MCPSecurityGuardConfig] = None) -> None:
        cfg = config or MCPSecurityGuardConfig()
        self._require_server_signature = cfg.require_server_signature
        self._trusted_servers = list(cfg.trusted_servers)
        self._blocked_servers = list(cfg.blocked_servers)
        self._allow_dynamic_registration = cfg.allow_dynamic_registration
        self._tool_allowlist = list(cfg.tool_allowlist)
        self._tool_blocklist = list(cfg.tool_blocklist)
        self._validate_oauth_endpoints = cfg.validate_oauth_endpoints
        self._allowed_oauth_domains = list(cfg.allowed_oauth_domains)
        self._detect_tool_shadowing = cfg.detect_tool_shadowing
        self._min_server_reputation = cfg.min_server_reputation
        self._strict_mode = cfg.strict_mode
        self._custom_injection_patterns = list(cfg.custom_injection_patterns)

        self._registered_servers: Dict[str, MCPServerIdentity] = {}
        self._registered_tools: Dict[str, MCPToolDefinition] = {}
        self._server_reputation: Dict[str, int] = {}
        self._tool_to_server: Dict[str, str] = {}
        self._server_violations: Dict[str, int] = {}
        self._tool_definition_hashes: Dict[str, str] = {}

        # Pre-register trusted servers
        for server in self._trusted_servers:
            rep = server.reputation_score if server.reputation_score is not None else 90
            self._registered_servers[server.server_id] = MCPServerIdentity(
                server_id=server.server_id,
                name=server.name,
                version=server.version,
                public_key=server.public_key,
                trusted_domains=server.trusted_domains,
                allowed_tools=server.allowed_tools,
                metadata=server.metadata,
                registered_at=_now_ms(),
                reputation_score=rep,
            )
            self._server_reputation[server.server_id] = rep

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_server_registration(
        self,
        registration: MCPServerRegistration,
        request_id: Optional[str] = None,
    ) -> MCPSecurityResult:
        req_id = request_id or f"mcp-reg-{_now_ms()}"
        violations: List[str] = []
        server_verified = False
        signature_valid = False
        is_shadowing = False
        tools_allowed = True
        reputation_score = 50

        server = registration.server
        tools = registration.tools
        oauth = registration.oauth
        signature = registration.signature
        timestamp = registration.timestamp

        # Check if server is blocked
        if self._is_server_blocked(server.server_id, server.name):
            violations.append("server_blocked")
            reputation_score = 0

        # Check for malicious server patterns
        malicious_check = self._check_malicious_patterns(server)
        if malicious_check["suspicious"]:
            violations.extend(malicious_check["violations"])
            reputation_score -= 30

        # Verify server signature if required
        if self._require_server_signature:
            if not signature or not server.public_key:
                violations.append("missing_server_signature")
            else:
                signature_valid = self._verify_server_signature(server, signature)
                if not signature_valid:
                    violations.append("invalid_server_signature")
                    reputation_score -= 40
                else:
                    server_verified = True
                    reputation_score += 20
        else:
            server_verified = True

        # Check for tool shadowing
        if self._detect_tool_shadowing:
            shadowing_check = self._detect_tool_shadowing_fn(tools, server.server_id)
            if shadowing_check["detected"]:
                is_shadowing = True
                violations.extend(shadowing_check["violations"])
                reputation_score -= 50

        # Validate tools
        for tool in tools:
            if self._tool_allowlist and tool.name not in self._tool_allowlist:
                violations.append(f"tool_not_in_allowlist: {tool.name}")
                tools_allowed = False
            if tool.name in self._tool_blocklist:
                violations.append(f"tool_blocked: {tool.name}")
                tools_allowed = False

            desc_injection = self._detect_injection(tool.description)
            if desc_injection["detected"]:
                violations.append(f"injection_in_tool_description: {tool.name}")
                reputation_score -= 20

        # Validate OAuth endpoints if present
        if oauth and self._validate_oauth_endpoints:
            oauth_check = self._validate_oauth_config(oauth)
            if not oauth_check["valid"]:
                violations.extend(oauth_check["violations"])
                reputation_score -= 30

        # Check timestamp
        age = _now_ms() - timestamp
        if age < 0:
            violations.append("future_timestamp")
        elif age > 5 * 60 * 1000:
            violations.append("stale_registration")

        # Check dynamic registration policy
        if not self._allow_dynamic_registration and not self._is_trusted_server(server.server_id):
            violations.append("dynamic_registration_disabled")

        # Final reputation score
        reputation_score = max(0, min(100, reputation_score))
        blocked = (
            reputation_score < self._min_server_reputation
            or (self._strict_mode and len(violations) > 0)
            or is_shadowing
        )

        # Register server if allowed
        if not blocked:
            self._register_server(server, tools, reputation_score)

        return MCPSecurityResult(
            allowed=not blocked,
            reason=(
                f"Server registration blocked: {', '.join(violations[:3])}"
                if blocked
                else "Server registration validated"
            ),
            violations=violations,
            request_id=req_id,
            server_analysis=MCPServerAnalysis(
                server_verified=server_verified,
                signature_valid=signature_valid,
                reputation_score=reputation_score,
                is_shadowing=is_shadowing,
                tools_allowed=tools_allowed,
            ),
            recommendations=self._generate_recommendations(violations, "registration"),
        )

    def validate_tool_call(
        self,
        tool_call: "Any",
        request_id: Optional[str] = None,
    ) -> MCPSecurityResult:
        req_id = request_id or f"mcp-call-{_now_ms()}"
        violations: List[str] = []
        tool_registered = False
        tool_allowed = True
        parameters_safe = True
        injection_detected = False
        risk_level = "low"

        # Accept both dataclass and dict
        if isinstance(tool_call, dict):
            tool_name = tool_call.get("tool_name", "")
            server_id = tool_call.get("server_id", "")
            parameters = tool_call.get("parameters", {})
        else:
            tool_name = tool_call.tool_name
            server_id = tool_call.server_id
            parameters = tool_call.parameters

        # Check if tool is registered
        tool = self._registered_tools.get(tool_name)
        if tool:
            tool_registered = True
            risk_level = tool.risk_level or "low"

            expected_server = self._tool_to_server.get(tool_name)
            if expected_server and expected_server != server_id:
                violations.append("server_tool_mismatch")
                injection_detected = True
        else:
            violations.append("tool_not_registered")

        # Check server reputation
        server_rep = self._server_reputation.get(server_id, 0)
        if server_rep < self._min_server_reputation:
            violations.append("low_server_reputation")

        # Check tool allowlist/blocklist
        if self._tool_allowlist and tool_name not in self._tool_allowlist:
            violations.append("tool_not_in_allowlist")
            tool_allowed = False
        if tool_name in self._tool_blocklist:
            violations.append("tool_blocked")
            tool_allowed = False

        # Scan parameters for injection
        param_check = self._scan_parameters(parameters)
        if param_check["injection_detected"]:
            injection_detected = True
            parameters_safe = False
            violations.extend(param_check["violations"])

        # Check for high-risk operations
        if self._is_high_risk_operation(tool_name, parameters):
            risk_level = "high"
            if server_rep < 70:
                violations.append("high_risk_low_reputation")

        # Update server violation count
        if violations:
            current_violations = self._server_violations.get(server_id, 0)
            self._server_violations[server_id] = current_violations + len(violations)
            current_rep = self._server_reputation.get(server_id, 50)
            self._server_reputation[server_id] = max(0, current_rep - len(violations) * 5)

        blocked = (
            not tool_registered
            or not tool_allowed
            or injection_detected
            or (self._strict_mode and len(violations) > 0)
        )

        return MCPSecurityResult(
            allowed=not blocked,
            reason=(
                f"Tool call blocked: {', '.join(violations[:3])}"
                if blocked
                else "Tool call validated"
            ),
            violations=violations,
            request_id=req_id,
            tool_analysis=MCPToolAnalysis(
                tool_registered=tool_registered,
                tool_allowed=tool_allowed,
                parameters_safe=parameters_safe,
                injection_detected=injection_detected,
                risk_level=risk_level,
            ),
            server_analysis=MCPServerAnalysis(
                server_verified=server_id in self._registered_servers,
                signature_valid=True,
                reputation_score=server_rep,
                is_shadowing=False,
                tools_allowed=tool_allowed,
            ),
            recommendations=self._generate_recommendations(violations, "tool_call"),
        )

    def validate_sampling_response(
        self,
        response: MCPSamplingResponse,
        request_id: Optional[str] = None,
    ) -> MCPSecurityResult:
        """Validate an MCP sampling response for attack patterns.

        Covers the three Unit42/Blueinfy (Feb 2026) sampling attack vectors:
        resource drain, conversation hijacking, and covert tool invocation.
        """
        req_id = request_id or f"mcp-sampling-{_now_ms()}"
        violations: List[str] = []
        resource_drain_detected = False
        conversation_hijack_detected = False
        covert_tool_invocation_detected = False
        pattern_matches: List[str] = []

        content = response.content
        server_id = response.server_id

        # Check server reputation
        server_rep = self._server_reputation.get(server_id, 50)
        if server_rep < self._min_server_reputation:
            violations.append("low_server_reputation")

        # Scan for sampling-specific attack patterns
        for entry in self.SAMPLING_ATTACK_PATTERNS:
            name: str = entry["name"]
            attack_type: str = entry["type"]
            pattern: re.Pattern[str] = entry["pattern"]
            if pattern.search(content):
                pattern_matches.append(name)
                # Embed attack type so recommendation logic can match by type substring
                violations.append(f"sampling_{attack_type}_{name}")
                if attack_type == "resource_drain":
                    resource_drain_detected = True
                elif attack_type == "conversation_hijack":
                    conversation_hijack_detected = True
                elif attack_type == "covert_tool_invocation":
                    covert_tool_invocation_detected = True

        # Also apply general command-injection scan to the response text
        injection_check = self._detect_injection(content[:2000])
        if injection_check["detected"]:
            violations.extend(f"sampling_cmd_{p}" for p in injection_check["patterns"])

        # Degrade server reputation on detected attack
        if violations and server_id:
            current_rep = self._server_reputation.get(server_id, 50)
            self._server_reputation[server_id] = max(0, current_rep - len(violations) * 10)
            current_violations = self._server_violations.get(server_id, 0)
            self._server_violations[server_id] = current_violations + len(violations)

        blocked = (
            resource_drain_detected
            or conversation_hijack_detected
            or covert_tool_invocation_detected
            or (self._strict_mode and len(violations) > 0)
        )

        return MCPSecurityResult(
            allowed=not blocked,
            reason=(
                f"Sampling response blocked: {', '.join(violations[:3])}"
                if blocked
                else "Sampling response validated"
            ),
            violations=violations,
            request_id=req_id,
            sampling_analysis=MCPSamplingAnalysis(
                resource_drain_detected=resource_drain_detected,
                conversation_hijack_detected=conversation_hijack_detected,
                covert_tool_invocation_detected=covert_tool_invocation_detected,
                pattern_matches=pattern_matches,
            ),
            recommendations=self._generate_recommendations(violations, "sampling"),
        )

    def register_trusted_server(self, server: MCPServerIdentity, tools: List[MCPToolDefinition]) -> None:
        self._register_server(server, tools, 90)

    def block_server(self, server_id_or_pattern: str) -> None:
        if server_id_or_pattern not in self._blocked_servers:
            self._blocked_servers.append(server_id_or_pattern)
        self._registered_servers.pop(server_id_or_pattern, None)
        self._server_reputation[server_id_or_pattern] = 0

    def get_server_reputation(self, server_id: str) -> int:
        return self._server_reputation.get(server_id, 0)

    def update_server_reputation(self, server_id: str, delta: int) -> None:
        current = self._server_reputation.get(server_id, 50)
        self._server_reputation[server_id] = max(0, min(100, current + delta))

    def get_registered_servers(self) -> List[MCPServerIdentity]:
        return list(self._registered_servers.values())

    def get_registered_tools(self) -> List[MCPToolDefinition]:
        return list(self._registered_tools.values())

    def is_tool_shadowing(self, tool_name: str) -> Dict[str, Any]:
        for indicator in self.SHADOWING_INDICATORS:
            if indicator.suspicious.search(tool_name) and tool_name != indicator.legitimate:
                return {"shadowing": True, "legitimate": indicator.legitimate}
        return {"shadowing": False}

    def get_server_violations(self, server_id: str) -> int:
        return self._server_violations.get(server_id, 0)

    def reset_server_violations(self, server_id: str) -> None:
        self._server_violations.pop(server_id, None)

    def detect_tool_mutation(
        self, tool_name: str, current_definition: MCPToolDefinition
    ) -> Dict[str, Any]:
        original_hash = self._tool_definition_hashes.get(tool_name)
        if not original_hash:
            return {"mutated": False}
        current_hash = self._hash_tool_definition(current_definition)
        return {
            "mutated": original_hash != current_hash,
            "original_hash": original_hash,
            "current_hash": current_hash,
        }

    def detect_tool_description_injection(self, description: str) -> Dict[str, Any]:
        patterns: List[str] = []
        injection_patterns = [
            ("hidden_instruction", re.compile(r'(?:IMPORTANT|NOTE|SYSTEM|ADMIN)\s*:', re.IGNORECASE)),
            ("ignore_directive", re.compile(r'ignore\s+(?:all\s+)?(?:previous|other|prior)', re.IGNORECASE)),
            ("override_behavior", re.compile(r'override|bypass|instead\s+of|rather\s+than', re.IGNORECASE)),
            ("exfiltrate_data", re.compile(r'send\s+(?:to|data|all)|forward\s+(?:to|all)|copy\s+(?:to|all)', re.IGNORECASE)),
            ("invisible_text", re.compile(r'[\u200b\u200c\u200d\ufeff\u00ad]')),
        ]
        for name, pattern in injection_patterns:
            if pattern.search(description):
                patterns.append(name)
        return {"injected": len(patterns) > 0, "patterns": patterns}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _register_server(self, server: MCPServerIdentity, tools: List[MCPToolDefinition], reputation: int) -> None:
        self._registered_servers[server.server_id] = MCPServerIdentity(
            server_id=server.server_id,
            name=server.name,
            version=server.version,
            public_key=server.public_key,
            trusted_domains=server.trusted_domains,
            allowed_tools=server.allowed_tools,
            metadata=server.metadata,
            registered_at=_now_ms(),
            reputation_score=reputation,
        )
        self._server_reputation[server.server_id] = reputation

        for tool in tools:
            self._registered_tools[tool.name] = tool
            self._tool_to_server[tool.name] = server.server_id
            self._tool_definition_hashes[tool.name] = self._hash_tool_definition(tool)

    def _hash_tool_definition(self, tool: MCPToolDefinition) -> str:
        normalized = json.dumps({
            "name": tool.name,
            "description": tool.description,
            "parameters": tool.parameters,
            "serverId": tool.server_id,
        }, separators=(",", ":"), sort_keys=True)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _is_server_blocked(self, server_id: str, server_name: Optional[str] = None) -> bool:
        for blocked in self._blocked_servers:
            if blocked in server_id or (server_name and blocked in server_name):
                return True
            try:
                regex = re.compile(blocked, re.IGNORECASE)
                if regex.search(server_id) or (server_name and regex.search(server_name)):
                    return True
            except re.error:
                pass
        return False

    def _is_trusted_server(self, server_id: str) -> bool:
        return any(s.server_id == server_id for s in self._trusted_servers)

    def _check_malicious_patterns(self, server: MCPServerIdentity) -> Dict[str, Any]:
        violations: List[str] = []
        check_str = f"{server.server_id} {server.name} {json.dumps(server.metadata or {})}"

        for pattern in self.MALICIOUS_SERVER_PATTERNS:
            if pattern.search(check_str):
                violations.append(f"malicious_pattern: {pattern.pattern[:20]}")

        return {"suspicious": len(violations) > 0, "violations": violations}

    def _verify_server_signature(self, server: MCPServerIdentity, signature: str) -> bool:
        """
        Verify server signature.
        The TS version uses crypto.createVerify with asymmetric keys.
        Here we use HMAC-SHA256 with the public_key as shared secret for simplicity
        since we are stdlib-only. For production, use proper asymmetric verification.
        """
        if not server.public_key:
            return False
        try:
            data = json.dumps({
                "serverId": server.server_id,
                "name": server.name,
                "version": server.version,
            }, separators=(",", ":"), ensure_ascii=False)
            import hmac as _hmac
            expected = _hmac.new(
                server.public_key.encode("utf-8"), data.encode("utf-8"), hashlib.sha256
            ).hexdigest()
            return _hmac.compare_digest(expected, signature)
        except Exception:
            return False

    def _detect_tool_shadowing_fn(
        self, tools: List[MCPToolDefinition], server_id: str
    ) -> Dict[str, Any]:
        violations: List[str] = []
        for tool in tools:
            existing_server = self._tool_to_server.get(tool.name)
            if existing_server and existing_server != server_id:
                violations.append(f"tool_shadowing: {tool.name} (already registered by {existing_server})")

            shadow_check = self.is_tool_shadowing(tool.name)
            if shadow_check["shadowing"]:
                violations.append(f"suspicious_tool_name: {tool.name} (similar to {shadow_check['legitimate']})")

        return {"detected": len(violations) > 0, "violations": violations}

    def _validate_oauth_config(self, oauth: MCPOAuthConfig) -> Dict[str, Any]:
        violations: List[str] = []

        if oauth.authorization_endpoint:
            injection = self._detect_injection(oauth.authorization_endpoint)
            if injection["detected"]:
                violations.append("oauth_authorization_endpoint_injection")

            if self._allowed_oauth_domains:
                try:
                    parsed = urlparse(oauth.authorization_endpoint)
                    hostname = parsed.hostname or ""
                    domain_allowed = any(hostname.endswith(d) for d in self._allowed_oauth_domains)
                    if not domain_allowed:
                        violations.append(f"oauth_domain_not_allowed: {hostname}")
                except Exception:
                    violations.append("invalid_oauth_authorization_url")

        if oauth.token_endpoint:
            injection = self._detect_injection(oauth.token_endpoint)
            if injection["detected"]:
                violations.append("oauth_token_endpoint_injection")

        return {"valid": len(violations) == 0, "violations": violations}

    def _detect_injection(self, value: str) -> Dict[str, Any]:
        patterns: List[str] = []
        all_patterns = list(self.COMMAND_INJECTION_PATTERNS) + [
            _InjectionPattern(f"custom_{i}", p, 50)
            for i, p in enumerate(self._custom_injection_patterns)
        ]

        for pat in all_patterns:
            if pat.pattern.search(value):
                patterns.append(pat.name)

        return {"detected": len(patterns) > 0, "patterns": patterns}

    def _scan_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        violations: List[str] = []
        param_str = json.dumps(parameters)

        injection = self._detect_injection(param_str)
        if injection["detected"]:
            violations.extend(f"param_injection_{p}" for p in injection["patterns"])

        for key, value in parameters.items():
            if isinstance(value, str) and len(value) > 10_000:
                violations.append(f"oversized_parameter: {key}")

        suspicious_keys = ["__proto__", "constructor", "prototype", "eval", "exec"]
        for key in parameters:
            if key.lower() in suspicious_keys:
                violations.append(f"suspicious_parameter_key: {key}")

        # SSRF detection
        for key, value in parameters.items():
            if isinstance(value, str):
                if re.search(
                    r'^https?://(?:127\.|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|0\.|localhost|169\.254\.|0\.0\.0\.0|\[?::1\]?)',
                    value, re.IGNORECASE
                ):
                    violations.append(f"ssrf_internal_ip: {key}")
                if re.search(r'^(?:file|gopher|dict|ftp|ldap|ssh|telnet)://', value, re.IGNORECASE):
                    violations.append(f"ssrf_dangerous_protocol: {key}")
                if re.search(r'%252e%252e|%c0%ae%c0%ae|%2e%2e%5c|\.\.%255c|\.\.%c0%af|\.\.%c1%9c', value, re.IGNORECASE):
                    violations.append(f"encoded_path_traversal: {key}")
                if re.search(
                    r'/etc/(?:passwd|shadow|hosts)|/proc/self|/dev/(?:null|random)|\.ssh/|\.env',
                    value, re.IGNORECASE
                ):
                    violations.append(f"sensitive_file_access: {key}")

        return {"injection_detected": len(violations) > 0, "violations": violations}

    def _is_high_risk_operation(self, tool_name: str, parameters: Dict[str, Any]) -> bool:
        high_risk_tools = [
            "execute_code", "run_command", "shell_exec", "eval",
            "file_write", "file_delete", "database_write", "database_delete",
            "send_email", "make_payment", "transfer_funds",
            "modify_permissions", "create_user", "delete_user",
        ]

        tool_lower = tool_name.lower()
        if any(t in tool_lower for t in high_risk_tools):
            return True

        param_str = json.dumps(parameters).lower()
        if any(kw in param_str for kw in ("delete", "drop", "truncate", "exec")):
            return True

        return False

    def _generate_recommendations(self, violations: List[str], context: str) -> List[str]:
        recommendations: List[str] = []

        if context == "registration":
            if any("signature" in v for v in violations):
                recommendations.append("Enable server signature verification for production")
            if any("shadowing" in v for v in violations):
                recommendations.append("Review tool names for potential shadowing attacks")
            if any("oauth" in v for v in violations):
                recommendations.append("Configure OAuth domain allowlist")
            if any("malicious" in v for v in violations):
                recommendations.append("Block suspicious servers and review server sources")
        elif context == "tool_call":
            if any("injection" in v for v in violations):
                recommendations.append("Sanitize tool parameters before execution")
            if any("reputation" in v for v in violations):
                recommendations.append("Only use tools from high-reputation servers")
            if any("not_registered" in v for v in violations):
                recommendations.append("Register tools before allowing execution")
        else:
            if any("resource_drain" in v for v in violations):
                recommendations.append("Block this MCP server — sampling response contains resource exhaustion directives (Unit42/Blueinfy Feb 2026)")
            if any("conversation_hijack" in v for v in violations):
                recommendations.append("Block this MCP server — sampling response attempts conversation hijacking via role injection")
            if any("covert_tool_invocation" in v for v in violations):
                recommendations.append("Block this MCP server — sampling response embeds covert tool-call syntax")

        if not recommendations:
            if context == "registration":
                recommendations.append("Server registration validated successfully")
            elif context == "tool_call":
                recommendations.append("Tool call validated successfully")
            else:
                recommendations.append("Sampling response validated successfully")

        return recommendations
