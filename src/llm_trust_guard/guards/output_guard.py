"""
OutputGuard (L35)

Detects dangerous payloads in LLM/tool output *before* it reaches a downstream
sink (browser/DOM, SQL engine, OS shell, markdown renderer, spreadsheet/CSV
importer). This closes OWASP **LLM05:2025 — Improper Output Handling**, which the
existing OutputFilter (PII/secret egress) does not cover.

    "Treat model output as untrusted input to the next system."

This is a CONTENT guard — it inspects the text the model produced, not the user
input. It does not understand intent; it flags syntactic payloads that are
dangerous when interpolated unescaped into a downstream interpreter.

Maps to: OWASP LLM05:2025, OWASP ASI02:2026 (Tool Misuse), CWE-79/89/78/1236.
Refs: https://genai.owasp.org/llmrisk/llm052025-improper-output-handling/
      https://arxiv.org/abs/2507.13169 (Prompt Injection 2.0)

Port of the TypeScript OutputGuard.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, List, Optional

LoggerFn = Optional[Callable[[str, str], None]]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class OutputGuardConfig:
    """Configuration for OutputGuard."""
    detect_html: bool = True
    detect_sql: bool = True
    detect_shell: bool = True
    detect_markdown_exfil: bool = True
    detect_csv_formula: bool = True
    allowed_domains: Optional[List[str]] = None
    blocked_patterns: Optional[List[str]] = None
    risk_threshold: float = 0.7
    sanitize: bool = False
    logger: LoggerFn = None


@dataclass
class OutputThreat:
    """A detected payload in model output."""
    sink: str  # "html" | "sql" | "shell" | "markdown" | "csv" | "custom"
    type: str
    detail: str
    severity: str  # "low" | "medium" | "high" | "critical"


@dataclass
class OutputGuardResult:
    """Result from scanning model/tool output."""
    allowed: bool
    violations: List[str]
    risk_score: float
    threats: List[OutputThreat]
    reason: Optional[str] = None
    sanitized: Optional[str] = None


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

@dataclass
class _SeverityPattern:
    pattern: re.Pattern
    label: str
    severity: str


HTML_PATTERNS: List[_SeverityPattern] = [
    _SeverityPattern(re.compile(r"<script\b[^>]*>", re.I), "<script> tag", "critical"),
    _SeverityPattern(re.compile(r"<iframe\b[^>]*>", re.I), "<iframe> tag", "high"),
    _SeverityPattern(re.compile(r"<object\b[^>]*>|<embed\b[^>]*>", re.I), "<object>/<embed> tag", "high"),
    _SeverityPattern(re.compile(r"javascript:\s*[^\s\"']", re.I), "javascript: URI", "high"),
    _SeverityPattern(re.compile(r"\bon(?:error|load|click|mouseover|focus|submit|toggle|animationstart)\s*=", re.I), "inline event handler", "high"),
    _SeverityPattern(re.compile(r"<svg\b[^>]*\bon\w+\s*=", re.I), "<svg> with event handler", "high"),
    _SeverityPattern(re.compile(r"\bdocument\.(?:cookie|location|write)\b", re.I), "document.cookie/location/write", "high"),
    _SeverityPattern(re.compile(r"\bdata:text/html", re.I), "data:text/html URI", "high"),
    _SeverityPattern(re.compile(r"<img\b[^>]*\bonerror\s*=", re.I), "<img onerror=>", "critical"),
]

SQL_PATTERNS: List[_SeverityPattern] = [
    _SeverityPattern(re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.I), "UNION SELECT", "critical"),
    _SeverityPattern(re.compile(r"'\s*OR\s+'?\d+'?\s*=\s*'?\d+", re.I), "tautology ' OR 1=1", "critical"),
    _SeverityPattern(re.compile(r"\bOR\s+1\s*=\s*1\b", re.I), "OR 1=1 tautology", "high"),
    _SeverityPattern(re.compile(r";\s*DROP\s+(?:TABLE|DATABASE)\b", re.I), ";DROP TABLE/DATABASE", "critical"),
    _SeverityPattern(re.compile(r";\s*DELETE\s+FROM\b", re.I), ";DELETE FROM", "critical"),
    _SeverityPattern(re.compile(r";\s*(?:INSERT\s+INTO|UPDATE)\b", re.I), ";INSERT/UPDATE statement", "high"),
    _SeverityPattern(re.compile(r"\bxp_cmdshell\b", re.I), "xp_cmdshell", "critical"),
    _SeverityPattern(re.compile(r"--\s*$|/\*.*?\*/", re.I | re.M), "SQL comment terminator", "low"),
]

SHELL_PATTERNS: List[_SeverityPattern] = [
    _SeverityPattern(re.compile(r"\$\([^)]+\)"), "command substitution $(...)", "high"),
    _SeverityPattern(re.compile(r"`[^`]+`"), "backtick command substitution", "high"),
    _SeverityPattern(re.compile(r";\s*rm\s+-[rf]", re.I), ";rm -rf", "critical"),
    _SeverityPattern(re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b", re.I), "curl|wget piped to shell", "critical"),
    _SeverityPattern(re.compile(r"\|\s*(?:bash|sh|zsh|powershell|cmd)\b", re.I), "pipe to shell interpreter", "high"),
    _SeverityPattern(re.compile(r"&&\s*(?:rm|curl|wget|nc|chmod|chown)\b", re.I), "chained destructive command", "high"),
    _SeverityPattern(re.compile(r"\bIFS\s*=|\$\{IFS\}"), "IFS manipulation", "medium"),
]

MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)", re.I)
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)", re.I)

CSV_TRIGGER = re.compile(r"(?:^|[\n\r,;\t])\s*([=+\-@][^\n\r,;\t]{0,200})")
CSV_DANGEROUS_FN = re.compile(
    r"\b(?:HYPERLINK|IMPORTXML|IMPORTDATA|IMPORTHTML|IMPORTFEED|IMPORTRANGE|WEBSERVICE|DDE|MSEXCEL)\b"
    r"|cmd\s*\||^\s*=[\w.]+\s*\(",
    re.I,
)

_SEVERITY_WEIGHTS = {"low": 0.1, "medium": 0.25, "high": 0.45, "critical": 0.8}


# ---------------------------------------------------------------------------
# Guard implementation
# ---------------------------------------------------------------------------

class OutputGuard:
    """Detects dangerous downstream-sink payloads in model output (LLM05)."""

    guard_name = "OutputGuard"
    guard_layer = "L35"

    def __init__(self, config: Optional[OutputGuardConfig] = None) -> None:
        self.config = config or OutputGuardConfig()
        if self.config.allowed_domains is None:
            self.config.allowed_domains = []
        if self.config.blocked_patterns is None:
            self.config.blocked_patterns = []

    def scan(self, output: str) -> OutputGuardResult:
        """Scan model/tool output for downstream-sink payloads."""
        threats: List[OutputThreat] = []
        violations: List[str] = []

        if not isinstance(output, str) or output == "":
            return OutputGuardResult(allowed=True, violations=[], risk_score=0.0, threats=[])

        if self.config.detect_html:
            self._match(output, HTML_PATTERNS, "html", threats, violations)
        if self.config.detect_sql:
            self._match(output, SQL_PATTERNS, "sql", threats, violations)
        if self.config.detect_shell:
            self._match(output, SHELL_PATTERNS, "shell", threats, violations)
        if self.config.detect_markdown_exfil:
            self._detect_markdown_exfil(output, threats, violations)
        if self.config.detect_csv_formula:
            self._detect_csv_formula(output, threats, violations)

        for pat in self.config.blocked_patterns or []:
            if re.search(pat, output, re.I):
                threats.append(OutputThreat("custom", "custom_blocked_pattern", f"Matched blocked pattern: {pat}", "high"))
                violations.append(f"blocked_pattern:{pat}")

        risk_score = self._compute_risk_score(threats)
        allowed = risk_score < self.config.risk_threshold and not any(t.severity == "critical" for t in threats)
        reason = None if allowed else self._build_reason(threats)

        if not allowed and self.config.logger:
            self.config.logger(f"OutputGuard blocked output: {reason}", "warn")

        result = OutputGuardResult(
            allowed=allowed, violations=violations, risk_score=risk_score, threats=threats, reason=reason
        )
        if self.config.sanitize:
            result.sanitized = self._neutralize(output)
        return result

    def _match(self, output, patterns, sink, threats, violations) -> None:
        for sp in patterns:
            if sp.pattern.search(output):
                threats.append(OutputThreat(sink, f"{sink}_payload", f"Detected {sp.label}", sp.severity))
                violations.append(f"{sink}:{sp.label}")

    def _detect_markdown_exfil(self, output, threats, violations) -> None:
        allow = [d.lower() for d in (self.config.allowed_domains or [])]

        def flag_url(url: str, kind: str) -> bool:
            host = self._host_of(url)
            has_query = bool(re.search(r"[?&]", url))
            if allow:
                return bool(host) and not any(host == d or host.endswith("." + d) for d in allow)
            return kind == "image" and has_query

        for m in MARKDOWN_IMAGE.finditer(output):
            if flag_url(m.group(1), "image"):
                host = self._host_of(m.group(1)) or m.group(1)
                threats.append(OutputThreat("markdown", "markdown_image_exfil", f"Auto-fetched image leaks data to {host}", "high"))
                violations.append(f"markdown:image_exfil:{host}")

        if allow:
            for m in MARKDOWN_LINK.finditer(output):
                if flag_url(m.group(1), "link"):
                    host = self._host_of(m.group(1)) or m.group(1)
                    threats.append(OutputThreat("markdown", "markdown_link_offdomain", f"Link to non-allowlisted domain {host}", "medium"))
                    violations.append(f"markdown:offdomain:{host}")

    def _detect_csv_formula(self, output, threats, violations) -> None:
        for m in CSV_TRIGGER.finditer(output):
            cell = m.group(1)
            leader = cell[0]
            # '=' is always a formula; +,-,@ only flag with a dangerous function.
            if leader == "=" or CSV_DANGEROUS_FN.search(cell):
                threats.append(OutputThreat("csv", "csv_formula_injection", f'Cell begins with formula trigger "{leader}": {cell[:40]}', "high"))
                violations.append(f"csv:formula:{leader}")

    @staticmethod
    def _host_of(url: str) -> str:
        m = re.match(r"^https?://([^/?#:\s]+)", url, re.I)
        return m.group(1).lower() if m else ""

    @staticmethod
    def _compute_risk_score(threats: List[OutputThreat]) -> float:
        if not threats:
            return 0.0
        return min(sum(_SEVERITY_WEIGHTS.get(t.severity, 0.1) for t in threats), 1.0)

    @staticmethod
    def _build_reason(threats: List[OutputThreat]) -> str:
        critical = [t for t in threats if t.severity == "critical"]
        high = [t for t in threats if t.severity == "high"]
        if critical:
            return "Critical output payloads detected: " + "; ".join(t.detail for t in critical)
        if high:
            return "High-risk output payloads detected: " + "; ".join(t.detail for t in high)
        return "Multiple output payloads detected (risk score exceeded threshold)"

    @staticmethod
    def _neutralize(output: str) -> str:
        out = re.sub(r"<script\b[^>]*>[\s\S]*?</script\s*>", "", output, flags=re.I)
        out = re.sub(r"<script\b[^>]*>", "", out, flags=re.I)
        out = re.sub(r"javascript:", "blocked:", out, flags=re.I)
        out = re.sub(r"\son(?:error|load|click|mouseover|focus|submit|toggle)\s*=", " data-blocked-handler=", out, flags=re.I)

        def _quote(m: re.Match) -> str:
            cell = m.group(1)
            if cell[0] == "=" or CSV_DANGEROUS_FN.search(cell):
                return m.group(0).replace(cell, "'" + cell)
            return m.group(0)

        return CSV_TRIGGER.sub(_quote, out)
