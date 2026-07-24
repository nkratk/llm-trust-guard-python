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

from ..decode_variants import build_decode_variants

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
    # "act as a/an X" only counts as a role-override attempt when X is an
    # authority/system-impersonation noun (admin, root, system, ...) — bare
    # "we act as an intermediary"-style business language uses the same
    # phrase with an ordinary noun and must not be flagged. Parity port of
    # npm's external-data-guard.ts (commit 0f3e868, survived independent
    # adversarial review — that review dropped "developer"/"moderator"/
    # "system" from an earlier draft of this list for being too generic,
    # matching "act as a developer advocate"/"act as a moderator for the
    # panel"; this port uses the post-review, safe list).
    _Pattern("role_override", re.compile(r"you\s+are\s+now|from\s+now\s+on|act\s+as\s+(?:a|an)\s+(?:admin|administrator|root|superuser|sudo|unrestricted|jailbroken|dan)\b", re.I)),
    _Pattern("hidden_instruction", re.compile(r"HIDDEN_PROMPT|HIDDEN_INSTRUCTION|INVISIBLE_TEXT", re.I)),
    _Pattern("jailbreak", re.compile(r"jailbreak|DAN\s*mode|developer\s+mode|unrestricted\s+mode", re.I)),
    _Pattern("bypass_safety", re.compile(r"bypass\s+(?:security|safety|filters|restrictions|guardrails)", re.I)),
    # Bounded — unbounded ={3,}/\s* was severely quadratic-time ReDoS on long
    # runs of "=" with no SYSTEM/INSTRUCTIONS/BEGIN literal (parity with npm sibling).
    _Pattern("instruction_delimiter", re.compile(r"={3,20}\s{0,10}(?:SYSTEM|INSTRUCTIONS?|BEGIN)\s{0,10}={3,20}", re.I)),
    _Pattern("prompt_leak_request", re.compile(r"(?:print|show|reveal|output)\s+(?:your|the|system)\s+(?:prompt|instructions)", re.I)),
    _Pattern("base64_injection", re.compile(r"(?:decode|eval|execute)\s+(?:the\s+)?(?:following\s+)?base64", re.I)),
    # Passive instruction-void forms (CSS-hidden, HTML-attr, and plain text injections)
    # Whitespace quantifiers bounded — same ReDoS shape as instruction_delimiter above.
    _Pattern("instructions_void", re.compile(r"(?:your|the|previous|prior|all\s{1,5}(?:previous|prior))?\s{0,20}instructions?\s{1,10}(?:are|have\s{1,5}been|is)\s{1,10}(?:void|cancelled?|overridden?|revoked|rescinded|superseded)", re.I)),
    _Pattern("forget_instructions", re.compile(r"forget\s+(?:your|all|the|my|these|every|each)\s*(?:previous\s+|prior\s+)?(?:instructions?|rules?|guidelines?|directives?|prompts?)", re.I)),
    _Pattern("disregard_directives", re.compile(r"disregard\s+(?:all\s+)?(?:previous|prior|above|your)?\s*(?:instructions?|rules?|directives?|guidelines?|prompts?)", re.I)),
    # Structured document injection (RAG/file/email pipelines)
    _Pattern("xxe_entity", re.compile(r'<!ENTITY\s+%?\s*\w+\s+SYSTEM\s+["\'][^"\']+["\']', re.I)),
    _Pattern("doctype_entity", re.compile(r"<!DOCTYPE\s+\w+\s*\[[\s\S]*<!ENTITY", re.I)),
    _Pattern("path_traversal", re.compile(r"(?:\.\.\/){3,}|(?:\.\.\\){3,}|(?:\.\.\/){2,}(?:etc|tmp|root|proc|sys|dev|usr|win)\b|(?:\.\.\\){2,}(?:windows|system32|users)\b", re.I)),
    # Hex-encoded path traversal (zip-slip: hex of ../../)
    _Pattern("path_traversal_hex", re.compile(r"(?:2e2e2f){2,}|(?:2e2e5c){2,}", re.I)),
    _Pattern("office_xml_script", re.compile(r"<(?:office|o):\w+[^>]*>[\s\S]*?<script", re.I)),
    _Pattern("rtf_ole_object", re.compile(r"\\object\\obj(?:emb|link|auto)|\\objdata\s", re.I)),
    _Pattern("html_comment_directive", re.compile(r"<!--\s*(?:BOT|AGENT|ASSISTANT|AI|LLM)\s*:\s*(?:execute|run|call|invoke|perform|fetch|send|ignore|bypass|forget|override|disregard|print|reveal|output|delete|drop)\b", re.I)),
    _Pattern("embedded_tool_call", re.compile(r"<tool[_-]?call[^>]*>|</tool[_-]?call>", re.I)),
    _Pattern("langchain_gadget", re.compile(r'\{["\']lc["\']\s*:\s*[12]\s*,\s*["\']type["\']\s*:\s*["\'](?:constructor|secret|not_implemented)', re.I)),
    _Pattern("email_agent_directive", re.compile(r"<!--\s*(?:assistant|system)\s*:\s*execute\s+tool", re.I)),
    # JSON hidden agent directive keys (_system, _directive, etc.)
    _Pattern("json_system_key", re.compile(r'"_(?:system|directive|instruction|prompt|admin|command)"\s*:', re.I)),
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
    # Bounds widened to 2000/1000/500 after review found a tighter first pass
    # would itself create a detection gap for long alt-text — stays fast (parity with npm sibling).
    _Pattern("markdown_image_exfil", re.compile(r"!\[.{0,2000}?\]\(https?://[^)]{0,1000}\?[^)]{0,500}(?:token|key|secret|data|q|payload|p|prompt|ctx|context|info|msg|body|session|conv)=", re.I)),
    # "Reprompt"-style exfil (CVE-2026-24307): markdown image with any long query-param value (>=30 chars).
    _Pattern("markdown_image_exfil_long_value", re.compile(r"!\[.{0,2000}?\]\(https?://[^)]{1,1000}\?[^)]{0,500}=[^)&]{30,}")),
    # Markdown exfil using URL-encoded path separators (%2F=/, %5C=\) in query values
    _Pattern("markdown_image_exfil_urlenc", re.compile(r"!\[.{0,2000}?\]\(https?://[^)]{1,1000}\?[^)]{0,500}=[^)]{0,500}%(?:2[Ff]|5[Cc])", re.I)),
    _Pattern("tracking_pixel", re.compile(r"<img[^>]+src=[\"']https?://[^\"']*\?[^\"']*[\"'][^>]*(?:width|height)\s*=\s*[\"']?[01]px", re.I)),
    _Pattern("encoded_url_exfil", re.compile(r"https?://[^\s]*(?:callback|webhook|exfil|collect)[^\s]*\?[^\s]*(?:data|payload|d)=", re.I)),
    _Pattern("data_send_instruction", re.compile(r"send\s+(?:this|the|all)\s+(?:data|information|content|context)\s+to", re.I)),
    _Pattern("fetch_url", re.compile(r"(?:fetch|request|call|curl|wget)\s+https?://", re.I)),
]

# SSRF attack surface detection — private/link-local IPs and dangerous URL schemes
SSRF_PATTERNS: List[_Pattern] = [
    # AWS link-local metadata, GCP metadata, ECS metadata
    _Pattern("cloud_metadata_endpoint", re.compile(r"169\.254\.169\.254|metadata\.google\.internal|169\.254\.170\.2", re.I)),
    # Loopback and RFC-1918 private IPs inside an http(s) URL
    _Pattern("ssrf_private_ip", re.compile(r"https?://(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|0\.0\.0\.0)\b", re.I)),
    # file:// scheme — local file read via SSRF
    _Pattern("file_scheme", re.compile(r"file://", re.I)),
    # Gopher protocol — Redis/memcache SSRF smuggling
    _Pattern("gopher_scheme", re.compile(r"gopher://", re.I)),
    # Other dangerous non-HTTP schemes
    _Pattern("dangerous_scheme", re.compile(r"(?:dict|ldap|ldaps|sftp|tftp|jar|netdoc)://", re.I)),
]

PII_PATTERNS: List[_Pattern] = [
    _Pattern("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    _Pattern("credit_card", re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")),
    # Bounded local-part/label/TLD lengths and a label-grouped domain — same
    # ReDoS fix as the npm sibling's matching pattern (10s+ on an 80KB
    # string with no valid email in it).
    _Pattern("email_address", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.){1,8}[A-Za-z]{2,24}\b", re.I)),
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

        # Content checks 5-8 also scan de-obfuscated variants (URL/hex/
        # base64/ROT13/reversed/homoglyph-normalized) — a raw pattern match
        # alone is trivially bypassed by wrapping the payload in any of
        # these encodings.
        scan_targets = [content_str] + build_decode_variants(content_str)

        # 5. Content injection detection
        if self.config.scan_for_injection:
            for target in scan_targets:
                for p in INJECTION_PATTERNS:
                    if p.pattern.search(target):
                        violations.append("INJECTION_DETECTED")
                        threats.append(f"injection:{p.name}")

        # 6. Secret / credential detection
        if self.config.scan_for_secrets:
            for target in scan_targets:
                for p in SECRET_PATTERNS:
                    if p.pattern.search(target):
                        violations.append("SECRET_DETECTED")
                        threats.append(f"secret:{p.name}")
                for p in PII_PATTERNS:
                    if p.pattern.search(target):
                        violations.append("PII_DETECTED")
                        threats.append(f"pii:{p.name}")

        # 7. Data exfiltration URL detection
        if self.config.scan_for_exfiltration:
            for target in scan_targets:
                for p in EXFILTRATION_PATTERNS:
                    if p.pattern.search(target):
                        violations.append("EXFILTRATION_ATTEMPT")
                        threats.append(f"exfil:{p.name}")

        # 8. SSRF detection — private IPs, cloud metadata, dangerous schemes
        for target in scan_targets:
            for p in SSRF_PATTERNS:
                if p.pattern.search(target):
                    violations.append("SSRF_ATTEMPT")
                    threats.append(f"ssrf:{p.name}")

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
