"""
AgentSkillGuard

Detects malicious agent plugins, tools, and skills before registration/execution.
Inspired by OpenClaw research which discovered 824 backdoored plugins across
npm, PyPI, and GitHub ecosystems.

This is an ARCHITECTURAL guard — it prevents malicious tools from being
registered regardless of whether the agent itself was compromised.

Threat Model:
- Backdoored tool definitions with hidden eval/exec calls
- Exfiltration patterns embedded in tool descriptions
- Privilege escalation chains across tool combinations
- Typosquatting / deceptive naming of trusted tools
- Hidden prompt injection in tool metadata
- Capability mismatch (read-only tools with write permissions)
- Overly broad or suspicious parameter definitions

Port of the TypeScript AgentSkillGuard.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

LoggerFn = Optional[Callable[[str, str], None]]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class SkillDefinition:
    """Definition of an agent skill/tool to analyze."""
    name: str
    description: str
    parameters: Optional[Dict[str, Any]] = None
    permissions: Optional[List[str]] = None
    source: Optional[str] = None
    version: Optional[str] = None
    author: Optional[str] = None


@dataclass
class AgentSkillGuardConfig:
    """Configuration for AgentSkillGuard."""
    trusted_tools: Optional[List[str]] = None
    blocked_patterns: Optional[List[str]] = None
    max_description_length: int = 2000
    detect_exfiltration: bool = True
    detect_hidden_instructions: bool = True
    detect_privilege_escalation: bool = True
    detect_deceptive_naming: bool = True
    logger: LoggerFn = None


@dataclass
class SkillThreat:
    """A detected threat in a skill definition."""
    type: str
    detail: str
    severity: str  # "low" | "medium" | "high" | "critical"


@dataclass
class AgentSkillGuardResult:
    """Result from analyzing a skill definition."""
    allowed: bool
    violations: List[str]
    risk_score: float
    threats: List[SkillThreat]
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

@dataclass
class _BackdoorPattern:
    pattern: re.Pattern
    label: str
    severity: str


@dataclass
class _LabeledPattern:
    pattern: re.Pattern
    label: str


BACKDOOR_PATTERNS: List[_BackdoorPattern] = [
    _BackdoorPattern(re.compile(r"\beval\s*\(", re.I), "eval() call", "critical"),
    _BackdoorPattern(re.compile(r"\bexec\s*\(", re.I), "exec() call", "critical"),
    _BackdoorPattern(re.compile(r"\bFunction\s*\(", re.I), "Function() constructor", "critical"),
    _BackdoorPattern(re.compile(r"\bchild_process\b", re.I), "child_process reference", "critical"),
    _BackdoorPattern(re.compile(r"\bspawn\s*\(", re.I), "spawn() call", "high"),
    _BackdoorPattern(re.compile(r"\bexecSync\s*\(", re.I), "execSync() call", "critical"),
    _BackdoorPattern(re.compile(r"\brequire\s*\(\s*['\"][^'\"]*['\"]\s*\)", re.I), "dynamic require()", "high"),
    _BackdoorPattern(re.compile(r"\bimport\s*\(\s*['\"][^'\"]*['\"]\s*\)", re.I), "dynamic import()", "high"),
    _BackdoorPattern(re.compile(r"\b__proto__\b"), "prototype pollution indicator", "high"),
    _BackdoorPattern(re.compile(r"\bconstructor\s*\["), "constructor bracket access", "high"),
    _BackdoorPattern(re.compile(r"process\.env", re.I), "environment variable access", "medium"),
    _BackdoorPattern(re.compile(r"\.ssh\b|\.aws\b|\.kube\b", re.I), "credential directory reference", "critical"),
    _BackdoorPattern(re.compile(r"base64[_\-]?(?:encode|decode)", re.I), "base64 encoding (obfuscation)", "medium"),
    _BackdoorPattern(re.compile(r"\batob\s*\(|\bbtoa\s*\(", re.I), "base64 function call", "medium"),
]

EXFILTRATION_PATTERNS: List[_LabeledPattern] = [
    _LabeledPattern(re.compile(r"https?://[^\s\"')\]]+", re.I), "hardcoded URL"),
    _LabeledPattern(re.compile(r"\bfetch\s*\(", re.I), "fetch() call"),
    _LabeledPattern(re.compile(r"\bXMLHttpRequest\b", re.I), "XMLHttpRequest reference"),
    _LabeledPattern(re.compile(r"\baxios\b", re.I), "axios reference"),
    _LabeledPattern(re.compile(r"\bwebsocket\b", re.I), "WebSocket reference"),
    _LabeledPattern(re.compile(r"\bnet\.connect\b", re.I), "net.connect call"),
    _LabeledPattern(re.compile(r"\bdns\.resolve\b", re.I), "DNS exfiltration indicator"),
    _LabeledPattern(re.compile(r"\bsendBeacon\b", re.I), "sendBeacon() call"),
    _LabeledPattern(re.compile(r"webhook[_\-.]?url", re.I), "webhook URL reference"),
    _LabeledPattern(re.compile(r"\bcurl\b|\bwget\b", re.I), "shell download command"),
]

HIDDEN_INSTRUCTION_PATTERNS: List[_LabeledPattern] = [
    _LabeledPattern(re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions", re.I), "instruction override"),
    _LabeledPattern(re.compile(r"you\s+(?:are|must|should)\s+now", re.I), "role reassignment"),
    _LabeledPattern(re.compile(r"system\s*:\s*", re.I), "system prompt injection"),
    _LabeledPattern(re.compile(r"\[INST\]|\[/INST\]", re.I), "instruction tag injection"),
    _LabeledPattern(re.compile(r"<\|(?:im_start|im_end|system|user|assistant)\|>", re.I), "chat template injection"),
    _LabeledPattern(re.compile(r"\bdo\s+not\s+(?:tell|reveal|show|mention)", re.I), "concealment instruction"),
    _LabeledPattern(re.compile(r"\bsecretly\b|\bcovertly\b|\bsilently\b", re.I), "covert action instruction"),
    _LabeledPattern(re.compile(r"\boverride\s+(?:security|safety|guard|filter)", re.I), "security override"),
    _LabeledPattern(re.compile(r"\bpretend\s+(?:to\s+be|you\s+are)", re.I), "identity spoofing"),
    _LabeledPattern(re.compile(r"<!--[\s\S]*?-->", re.I), "HTML comment (hidden content)"),
]

DANGEROUS_PERMISSION_COMBOS: List[Dict[str, Any]] = [
    {"permissions": ["read", "execute"], "reason": "read+execute enables read-then-run attacks"},
    {"permissions": ["read", "network"], "reason": "read+network enables data exfiltration"},
    {"permissions": ["write", "execute"], "reason": "write+execute enables payload drop+run"},
    {"permissions": ["admin", "network"], "reason": "admin+network enables remote takeover"},
    {"permissions": ["filesystem", "network"], "reason": "filesystem+network enables file exfiltration"},
]

READ_ONLY_INTENTS = re.compile(r"\b(?:read|view|list|get|fetch|search|query|lookup|check|inspect|show|display)\b", re.I)
WRITE_EXEC_PERMISSIONS = re.compile(r"\b(?:write|execute|delete|admin|modify|create|update|remove|drop)\b", re.I)

WELL_KNOWN_TOOLS = [
    "read_file", "write_file", "list_directory", "search", "execute",
    "bash", "python", "node", "calculator", "web_search", "browser",
    "code_interpreter", "retrieval", "dall_e", "wolfram",
]

SUSPICIOUS_PARAM_PATTERNS = [
    re.compile(r"^_"), re.compile(r"^__"), re.compile(r"callback_url", re.I),
    re.compile(r"webhook", re.I), re.compile(r"exfil", re.I),
    re.compile(r"^cmd$", re.I), re.compile(r"^command$", re.I),
    re.compile(r"^shell$", re.I), re.compile(r"^code$", re.I),
    re.compile(r"^eval$", re.I), re.compile(r"^exec$", re.I),
    re.compile(r"^payload$", re.I), re.compile(r"^inject$", re.I),
    re.compile(r"^hidden", re.I), re.compile(r"^internal", re.I),
    re.compile(r"^debug", re.I), re.compile(r"^bypass", re.I),
]


# ---------------------------------------------------------------------------
# Guard implementation
# ---------------------------------------------------------------------------

class AgentSkillGuard:
    """Detects malicious agent plugins, tools, and skills."""

    guard_name = "AgentSkillGuard"
    guard_layer = "L-AGENT"

    def __init__(self, config: Optional[AgentSkillGuardConfig] = None) -> None:
        self.config = config or AgentSkillGuardConfig()
        if self.config.trusted_tools is None:
            self.config.trusted_tools = []
        if self.config.blocked_patterns is None:
            self.config.blocked_patterns = []

    def analyze(self, skill: SkillDefinition) -> AgentSkillGuardResult:
        """Analyze a skill definition for threats."""
        threats: List[SkillThreat] = []
        violations: List[str] = []

        # Fast path: trusted tool allowlist
        if skill.name in (self.config.trusted_tools or []):
            return AgentSkillGuardResult(allowed=True, violations=[], risk_score=0.0, threats=[])

        corpus = self._build_corpus(skill)

        # 1. Backdoor signature detection (OpenClaw patterns)
        self._detect_backdoors(corpus, threats, violations)

        # 2. Exfiltration patterns
        if self.config.detect_exfiltration:
            self._detect_exfiltration_patterns(corpus, threats, violations)

        # 3. Hidden instructions / prompt injection in metadata
        if self.config.detect_hidden_instructions:
            self._detect_hidden_instructions(corpus, threats, violations)

        # 4. Capability mismatch
        self._detect_capability_mismatch(skill, threats, violations)

        # 5. Privilege escalation via permission combos
        if self.config.detect_privilege_escalation:
            self._detect_privilege_escalation(skill, threats, violations)

        # 6. Deceptive naming / typosquatting
        if self.config.detect_deceptive_naming:
            self._detect_deceptive_naming(skill, threats, violations)

        # 7. Suspicious description length
        if len(skill.description) > self.config.max_description_length:
            threats.append(SkillThreat(
                type="suspicious_description",
                detail=f"Description length {len(skill.description)} exceeds limit {self.config.max_description_length}",
                severity="medium",
            ))
            violations.append("description_too_long")

        # 8. Hidden parameters (parameters with suspicious names)
        self._detect_suspicious_parameters(skill, threats, violations)

        # 9. Custom blocked patterns
        for pat in (self.config.blocked_patterns or []):
            regex = re.compile(pat, re.I)
            if regex.search(corpus):
                threats.append(SkillThreat(type="custom_blocked_pattern", detail=f"Matched blocked pattern: {pat}", severity="high"))
                violations.append(f"blocked_pattern:{pat}")

        # Compute risk score
        risk_score = self._compute_risk_score(threats)
        allowed = risk_score < 0.7 and not any(t.severity == "critical" for t in threats)
        reason = None if allowed else self._build_reason(threats)

        if not allowed:
            self._log(f'Blocked skill "{skill.name}": {reason}', "warn")

        return AgentSkillGuardResult(
            allowed=allowed,
            reason=reason,
            violations=violations,
            risk_score=risk_score,
            threats=threats,
        )

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _build_corpus(self, skill: SkillDefinition) -> str:
        """Concatenate all inspectable text from the skill definition."""
        parts = [skill.name, skill.description]
        if skill.source:
            parts.append(skill.source)
        if skill.author:
            parts.append(skill.author)
        if skill.parameters:
            parts.append(json.dumps(skill.parameters))
        return " ".join(parts)

    def _detect_backdoors(self, corpus: str, threats: List[SkillThreat], violations: List[str]) -> None:
        for bp in BACKDOOR_PATTERNS:
            if bp.pattern.search(corpus):
                threats.append(SkillThreat(type="backdoor_signature", detail=f"Detected {bp.label}", severity=bp.severity))
                violations.append(f"backdoor:{bp.label}")

    def _detect_exfiltration_patterns(self, corpus: str, threats: List[SkillThreat], violations: List[str]) -> None:
        for ep in EXFILTRATION_PATTERNS:
            if ep.pattern.search(corpus):
                threats.append(SkillThreat(type="exfiltration", detail=f"Detected {ep.label}", severity="high"))
                violations.append(f"exfiltration:{ep.label}")

    def _detect_hidden_instructions(self, corpus: str, threats: List[SkillThreat], violations: List[str]) -> None:
        for hp in HIDDEN_INSTRUCTION_PATTERNS:
            if hp.pattern.search(corpus):
                threats.append(SkillThreat(type="hidden_instruction", detail=f"Detected {hp.label}", severity="critical"))
                violations.append(f"hidden_instruction:{hp.label}")

    def _detect_capability_mismatch(self, skill: SkillDefinition, threats: List[SkillThreat], violations: List[str]) -> None:
        if not skill.permissions or len(skill.permissions) == 0:
            return

        name_and_desc = f"{skill.name} {skill.description.lower()}"

        # Tool claims read-only intent but requests write/exec permissions
        if READ_ONLY_INTENTS.search(name_and_desc):
            for perm in skill.permissions:
                if WRITE_EXEC_PERMISSIONS.search(perm):
                    threats.append(SkillThreat(
                        type="capability_mismatch",
                        detail=f'Tool "{skill.name}" claims read-only intent but requests "{perm}" permission',
                        severity="high",
                    ))
                    violations.append(f"capability_mismatch:{perm}")

    def _detect_privilege_escalation(self, skill: SkillDefinition, threats: List[SkillThreat], violations: List[str]) -> None:
        if not skill.permissions or len(skill.permissions) < 2:
            return

        perm_set = {p.lower() for p in skill.permissions}
        for combo in DANGEROUS_PERMISSION_COMBOS:
            if all(p in perm_set for p in combo["permissions"]):
                threats.append(SkillThreat(
                    type="privilege_escalation",
                    detail=f"Dangerous permission combination: {combo['reason']}",
                    severity="high",
                ))
                violations.append(f"privilege_escalation:{'+'.join(combo['permissions'])}")

    def _detect_deceptive_naming(self, skill: SkillDefinition, threats: List[SkillThreat], violations: List[str]) -> None:
        name = re.sub(r"[-_\s]", "", skill.name.lower())

        all_known = WELL_KNOWN_TOOLS + (self.config.trusted_tools or [])
        for trusted in all_known:
            normalized_trusted = re.sub(r"[-_\s]", "", trusted.lower())
            if name == normalized_trusted:
                continue  # exact match is fine

            distance = self._levenshtein_distance(name, normalized_trusted)
            max_len = max(len(name), len(normalized_trusted))

            # Flag if edit distance is 1-2 (likely typosquatting)
            if 0 < distance <= 2 and max_len > 3:
                threats.append(SkillThreat(
                    type="deceptive_naming",
                    detail=f'"{skill.name}" is suspiciously similar to trusted tool "{trusted}" (edit distance: {distance})',
                    severity="high",
                ))
                violations.append(f"deceptive_naming:{skill.name}~{trusted}")

    def _detect_suspicious_parameters(self, skill: SkillDefinition, threats: List[SkillThreat], violations: List[str]) -> None:
        if not skill.parameters:
            return

        for param_name in skill.parameters:
            for regex in SUSPICIOUS_PARAM_PATTERNS:
                if regex.search(param_name):
                    threats.append(SkillThreat(
                        type="suspicious_parameter",
                        detail=f'Parameter "{param_name}" matches suspicious pattern {regex.pattern}',
                        severity="medium",
                    ))
                    violations.append(f"suspicious_param:{param_name}")
                    break

        # Check for excessive parameter count
        param_count = len(skill.parameters)
        if param_count > 20:
            threats.append(SkillThreat(
                type="excessive_parameters",
                detail=f"Tool defines {param_count} parameters (threshold: 20)",
                severity="medium",
            ))
            violations.append("excessive_parameters")

    @staticmethod
    def _compute_risk_score(threats: List[SkillThreat]) -> float:
        if not threats:
            return 0.0

        severity_weights = {
            "low": 0.1,
            "medium": 0.25,
            "high": 0.45,
            "critical": 0.8,
        }

        score = 0.0
        for t in threats:
            score += severity_weights.get(t.severity, 0.1)
        return min(score, 1.0)

    @staticmethod
    def _build_reason(threats: List[SkillThreat]) -> str:
        critical = [t for t in threats if t.severity == "critical"]
        high = [t for t in threats if t.severity == "high"]

        if critical:
            return f"Critical threats detected: {'; '.join(t.detail for t in critical)}"
        if high:
            return f"High-risk threats detected: {'; '.join(t.detail for t in high)}"
        return "Multiple threats detected (risk score exceeded threshold)"

    @staticmethod
    def _levenshtein_distance(a: str, b: str) -> int:
        """Levenshtein distance for typosquatting detection."""
        m, n = len(a), len(b)
        dp = [[0] * (n + 1) for _ in range(m + 1)]

        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j

        for i in range(1, m + 1):
            for j in range(1, n + 1):
                cost = 0 if a[i - 1] == b[j - 1] else 1
                dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)

        return dp[m][n]

    def _log(self, message: str, level: str) -> None:
        if self.config.logger:
            self.config.logger(message, level)
