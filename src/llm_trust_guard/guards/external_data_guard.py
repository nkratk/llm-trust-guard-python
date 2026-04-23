"""
ExternalDataGuard

Validates ALL external data before it enters LLM context.
Covers API responses, tool outputs, RAG results, file contents,
webhook payloads, and any other untrusted data source.

This is an ARCHITECTURAL guard — it enforces boundaries on what
external data can reach the LLM, regardless of whether the LLM
itself has been compromised. Defense-in-depth at the data boundary.

Threat model:
- Indirect prompt injection via API responses or RAG documents
- Context stuffing via oversized payloads
- Data exfiltration via embedded URLs in external content
- Secret/credential leakage through external data
- Poisoned data from compromised or unknown sources

Port of the TypeScript ExternalDataGuard.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Union

LoggerFn = Optional[Callable[[str, str], None]]


# ---------------------------------------------------------------------------
# Config & Result types
# ---------------------------------------------------------------------------

@dataclass
class ExternalDataGuardConfig:
    """Configuration for ExternalDataGuard."""
    allowed_sources: Optional[List[str]] = None
    blocked_sources: Optional[List[str]] = None
    max_content_length: int = 50_000
    scan_for_injection: bool = True
    scan_for_secrets: bool = True
    scan_for_exfiltration: bool = True
    require_provenance: bool = False
    logger: LoggerFn = None


@dataclass
class ExternalDataGuardResult:
    """Result from validating external data."""
    allowed: bool
    violations: List[str]
    content_length: int
    threats: List[str]
    reason: Optional[str] = None
    source: Optional[str] = None


@dataclass
class DataProvenance:
    """Provenance metadata callers attach to external data."""
    source: str
    content_type: Optional[str] = None
    retrieved_at: Optional[Union[str, int, float]] = None
    max_age_sec: Optional[int] = None


# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

@dataclass
class _Pattern:
    name: str
    pattern: re.Pattern


INJECTION_PATTERNS: List[_Pattern] = [
    _Pattern("system_tag", re.compile(r"</?system>|</?admin>|\[system\]|\[admin\]", re.I)),
    _Pattern("ignore_instructions", re.compile(r"ignore\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions|rules|prompts?)", re.I)),
    _Pattern("new_instructions", re.compile(r"new\s+instructions?\s*:", re.I)),
    _Pattern("role_override", re.compile(r"you\s+are\s+now|from\s+now\s+on|act\s+as\s+(?:a|an)\s", re.I)),
    _Pattern("hidden_instruction", re.compile(r"HIDDEN_PROMPT|HIDDEN_INSTRUCTION|INVISIBLE_TEXT", re.I)),
    _Pattern("jailbreak", re.compile(r"jailbreak|DAN\s*mode|developer\s+mode|unrestricted\s+mode", re.I)),
    _Pattern("bypass_safety", re.compile(r"bypass\s+(?:security|safety|filters|restrictions|guardrails)", re.I)),
    _Pattern("instruction_delimiter", re.compile(r"={3,}\s*(?:SYSTEM|INSTRUCTIONS?|BEGIN)\s*={3,}", re.I)),
    _Pattern("prompt_leak_request", re.compile(r"(?:print|show|reveal|output)\s+(?:your|the|system)\s+(?:prompt|instructions)", re.I)),
    _Pattern("base64_injection", re.compile(r"(?:decode|eval|execute)\s+(?:the\s+)?(?:following\s+)?base64", re.I)),
]

SECRET_PATTERNS: List[_Pattern] = [
    _Pattern("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    _Pattern("generic_api_key", re.compile(r"(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*[\"']?[A-Za-z0-9_\-]{20,}", re.I)),
    _Pattern("bearer_token", re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
    _Pattern("private_key", re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE\s+KEY-----")),
    _Pattern("github_token", re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}")),
    _Pattern("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    _Pattern("password_field", re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*[\"'][^\"']{8,}", re.I)),
    _Pattern("connection_string", re.compile(r"(?:mongodb|postgres|mysql|redis)://[^\s]{10,}", re.I)),
]

EXFILTRATION_PATTERNS: List[_Pattern] = [
    # Named-key exfil: markdown image URL whose query param key hints at data smuggling
    _Pattern("markdown_image_exfil", re.compile(r"!\[.*?\]\(https?://[^)]*\?[^)]*(?:token|key|secret|data|q|payload|p|prompt|ctx|context|info|msg|body|session|conv)=", re.I)),
    # "Reprompt"-style exfil (CVE-2026-24307): markdown image with any long query-param value (>=30 chars).
    # Legitimate cache-busters are typically short version strings / short hashes; exfiltrated content runs longer.
    _Pattern("markdown_image_exfil_long_value", re.compile(r"!\[.*?\]\(https?://[^)]+\?[^)]*=[^)&]{30,}")),
    _Pattern("tracking_pixel", re.compile(r"<img[^>]+src=[\"']https?://[^\"']*\?[^\"']*[\"'][^>]*(?:width|height)\s*=\s*[\"']?[01]px", re.I)),
    _Pattern("encoded_url_exfil", re.compile(r"https?://[^\s]*(?:callback|webhook|exfil|collect)[^\s]*\?[^\s]*(?:data|payload|d)=", re.I)),
    _Pattern("data_send_instruction", re.compile(r"send\s+(?:this|the|all)\s+(?:data|information|content|context)\s+to", re.I)),
    _Pattern("fetch_url", re.compile(r"(?:fetch|request|call|curl|wget)\s+https?://", re.I)),
]

PII_PATTERNS: List[_Pattern] = [
    _Pattern("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    _Pattern("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")),
    _Pattern("email_address", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z]{2,}\b", re.I)),
]


# ---------------------------------------------------------------------------
# Guard implementation
# ---------------------------------------------------------------------------

class ExternalDataGuard:
    """Validates external data before it enters LLM context."""

    def __init__(self, config: Optional[ExternalDataGuardConfig] = None) -> None:
        self.config = config or ExternalDataGuardConfig()

    def validate(
        self,
        content: Union[str, Dict[str, Any]],
        provenance: Optional[DataProvenance] = None,
    ) -> ExternalDataGuardResult:
        """Validate external data before it enters LLM context."""
        violations: List[str] = []
        threats: List[str] = []
        content_str = content if isinstance(content, str) else self._safe_stringify(content)
        source = provenance.source if provenance else None

        # 1. Provenance requirement
        if self.config.require_provenance and (not provenance or not provenance.source):
            violations.append("MISSING_PROVENANCE")
            threats.append("no_source_metadata")

        # 2. Source verification
        if source:
            if self._is_blocked_source(source):
                violations.append("BLOCKED_SOURCE")
                threats.append("blocked_data_source")
            if self.config.allowed_sources and len(self.config.allowed_sources) > 0:
                if not self._is_allowed_source(source):
                    violations.append("UNAPPROVED_SOURCE")
                    threats.append("source_not_in_allowlist")

        # 3. Size limits — prevent context stuffing
        if len(content_str) > self.config.max_content_length:
            violations.append("CONTENT_TOO_LARGE")
            threats.append("context_stuffing")

        # 4. Metadata validation — freshness check
        if provenance and provenance.retrieved_at is not None and provenance.max_age_sec is not None:
            if isinstance(provenance.retrieved_at, str):
                # Parse ISO format string to epoch ms
                import datetime
                try:
                    dt = datetime.datetime.fromisoformat(provenance.retrieved_at.replace("Z", "+00:00"))
                    retrieved_ms = dt.timestamp() * 1000
                except (ValueError, TypeError):
                    retrieved_ms = 0
            else:
                retrieved_ms = float(provenance.retrieved_at)

            now_ms = time.time() * 1000
            age_ms = now_ms - retrieved_ms
            if age_ms > provenance.max_age_sec * 1000:
                violations.append("STALE_DATA")
                threats.append("data_expired")

        # 5. Content injection detection
        if self.config.scan_for_injection:
            for p in INJECTION_PATTERNS:
                if p.pattern.search(content_str):
                    violations.append("INJECTION_DETECTED")
                    threats.append(f"injection:{p.name}")

        # 6. Secret / credential detection
        if self.config.scan_for_secrets:
            for p in SECRET_PATTERNS:
                if p.pattern.search(content_str):
                    violations.append("SECRET_DETECTED")
                    threats.append(f"secret:{p.name}")
            for p in PII_PATTERNS:
                if p.pattern.search(content_str):
                    violations.append("PII_DETECTED")
                    threats.append(f"pii:{p.name}")

        # 7. Data exfiltration URL detection
        if self.config.scan_for_exfiltration:
            for p in EXFILTRATION_PATTERNS:
                if p.pattern.search(content_str):
                    violations.append("EXFILTRATION_ATTEMPT")
                    threats.append(f"exfil:{p.name}")

        # Deduplicate
        unique_violations = list(dict.fromkeys(violations))
        unique_threats = list(dict.fromkeys(threats))
        allowed = len(unique_violations) == 0

        result = ExternalDataGuardResult(
            allowed=allowed,
            reason=None if allowed else f"External data rejected: {', '.join(unique_violations)}",
            violations=unique_violations,
            source=source,
            content_length=len(content_str),
            threats=unique_threats,
        )

        if not allowed:
            self._log(f"Blocked external data: {', '.join(unique_violations)}", "warn")

        return result

    def validate_batch(
        self,
        items: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Validate a batch of external data items (e.g. multiple RAG chunks).
        Each item should have 'content' and optionally 'provenance'.
        Returns individual results and a combined summary.
        """
        results = [
            self.validate(
                item["content"],
                item.get("provenance"),
            )
            for item in items
        ]
        return {
            "results": results,
            "all_allowed": all(r.allowed for r in results),
            "total_threats": sum(len(r.threats) for r in results),
        }

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _is_blocked_source(self, source: str) -> bool:
        if not self.config.blocked_sources:
            return False
        lower = source.lower()
        return any(b.lower() in lower for b in self.config.blocked_sources)

    def _is_allowed_source(self, source: str) -> bool:
        if not self.config.allowed_sources:
            return True
        lower = source.lower()
        return any(lower.startswith(a.lower()) for a in self.config.allowed_sources)

    def _log(self, message: str, level: str) -> None:
        if self.config.logger:
            self.config.logger(message, level)

    @staticmethod
    def _safe_stringify(value: Any) -> str:
        try:
            return json.dumps(value)
        except (TypeError, ValueError):
            return str(value)
