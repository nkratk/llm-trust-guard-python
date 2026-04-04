"""
L7: Output Filter

Prevents sensitive data leakage by:
- Detecting and masking PII (emails, phone numbers, SSN, credit cards)
- Filtering sensitive fields from responses
- Blocking responses that contain secrets or credentials
- Applying role-based output filtering

Zero dependencies - uses only Python stdlib (re, dataclasses, json).
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional


@dataclass
class PIIPattern:
    name: str
    pattern: str  # regex pattern string
    flags: int = 0  # re flags
    mask_as: Optional[str] = None  # e.g., "[EMAIL]", "[SSN]"


@dataclass
class SecretPattern:
    name: str
    pattern: str  # regex pattern string
    flags: int = 0  # re flags
    severity: str = "high"  # "low" | "medium" | "high" | "critical"


@dataclass
class PIIDetection:
    type: str
    count: int
    masked: bool
    locations: List[str]


@dataclass
class SecretDetection:
    type: str
    severity: str
    blocked: bool
    location: str


@dataclass
class OutputFilterResult:
    allowed: bool
    reason: Optional[str] = None
    violations: List[str] = field(default_factory=list)
    pii_detected: List[PIIDetection] = field(default_factory=list)
    secrets_detected: List[SecretDetection] = field(default_factory=list)
    filtered_fields: List[str] = field(default_factory=list)
    original_response: Any = None
    filtered_response: Any = None
    blocking_reason: Optional[str] = None

    @property
    def filtered(self) -> Any:
        """Alias for filtered_response — matches Node API property name."""
        return self.filtered_response


# Logger type: Callable that takes message and level
LoggerFunc = Callable[[str, str], None]

# Default no-op logger
_noop_logger: LoggerFunc = lambda msg, level: None


DEFAULT_PII_PATTERNS: List[PIIPattern] = [
    PIIPattern(
        name="email",
        pattern=r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        mask_as="[EMAIL]",
    ),
    PIIPattern(
        name="phone_us",
        pattern=r"\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        mask_as="[PHONE]",
    ),
    PIIPattern(
        name="ssn",
        pattern=r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
        mask_as="[SSN]",
    ),
    PIIPattern(
        name="credit_card",
        pattern=r"\b(?:\d{4}[-.\s]?){3}\d{4}\b",
        mask_as="[CREDIT_CARD]",
    ),
    PIIPattern(
        name="credit_card_amex",
        pattern=r"\b3[47]\d{2}[-.\s]?\d{6}[-.\s]?\d{5}\b",
        mask_as="[CREDIT_CARD]",
    ),
    PIIPattern(
        name="ip_address",
        pattern=r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        mask_as="[IP_ADDRESS]",
    ),
    PIIPattern(
        name="date_of_birth",
        pattern=r"\b(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12]\d|3[01])[/\-](?:19|20)\d{2}\b",
        mask_as="[DOB]",
    ),
    PIIPattern(
        name="passport",
        pattern=r"\b[A-Z]{1,2}\d{6,9}\b",
        mask_as="[PASSPORT]",
    ),
    PIIPattern(
        name="bank_account",
        pattern=r"\b(?:account|acct|routing|iban)[#:\s]*\d{8,17}\b",
        flags=re.IGNORECASE,
        mask_as="[BANK_ACCOUNT]",
    ),
]

DEFAULT_SECRET_PATTERNS: List[SecretPattern] = [
    SecretPattern(
        name="api_key",
        pattern=r"(?:api[_\-\s]?key|apikey)(?:\s+is)?\s*[=:\s]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?",
        flags=re.IGNORECASE,
        severity="critical",
    ),
    SecretPattern(
        name="api_key_prefix",
        pattern=r"\b(?:sk|pk|rk|ak)[_-][a-zA-Z0-9]{8,}\b",
        severity="critical",
    ),
    SecretPattern(
        name="aws_secret",
        pattern=r"(?:aws[_\-]?secret|secret[_\-]?key)[=:\s][\"']?[A-Za-z0-9/+=]{40}[\"']?",
        flags=re.IGNORECASE,
        severity="critical",
    ),
    SecretPattern(
        name="password",
        pattern=r"(?:password|passwd|pwd)\s*(?:[=:]|is\s*:?)\s*[\"']?[^\s\"']{6,}[\"']?",
        flags=re.IGNORECASE,
        severity="critical",
    ),
    SecretPattern(
        name="private_key",
        pattern=r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        severity="critical",
    ),
    SecretPattern(
        name="jwt_token",
        pattern=r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+",
        severity="high",
    ),
    SecretPattern(
        name="bearer_token",
        pattern=r"Bearer\s+[A-Za-z0-9_\-.]+",
        flags=re.IGNORECASE,
        severity="high",
    ),
    SecretPattern(
        name="database_url",
        pattern=r"(?:mongodb|mysql|postgres|redis)://[^\s]+",
        flags=re.IGNORECASE,
        severity="critical",
    ),
    SecretPattern(
        name="github_token",
        pattern=r"gh[pousr]_[A-Za-z0-9_]{36,}",
        severity="critical",
    ),
    SecretPattern(
        name="google_api_key",
        pattern=r"AIzaSy[A-Za-z0-9_\-]{30,}",
        severity="critical",
    ),
    # Slack tokens
    SecretPattern(
        name="slack_token",
        pattern=r"xox[bporas]-[A-Za-z0-9\-]{10,}",
        severity="critical",
    ),
    # AWS access key ID
    SecretPattern(
        name="aws_access_key",
        pattern=r"\bAKIA[0-9A-Z]{16}\b",
        severity="critical",
    ),
    # OpenAI API key
    SecretPattern(
        name="openai_api_key",
        pattern=r"\bsk-[a-zA-Z0-9_\-]{20,}\b",
        severity="critical",
    ),
    # OpenAI project keys (sk-proj-...)
    SecretPattern(
        name="openai_project_key",
        pattern=r"\bsk-proj-[a-zA-Z0-9_\-]{20,}\b",
        severity="critical",
    ),
    # Stripe keys (sk_live_, sk_test_)
    SecretPattern(
        name="stripe_key",
        pattern=r"\bsk_(?:live|test)_[a-zA-Z0-9]{24,}\b",
        severity="critical",
    ),
    # GitHub fine-grained PAT (github_pat_)
    SecretPattern(
        name="github_fine_grained_pat",
        pattern=r"\bgithub_pat_[A-Za-z0-9_]{30,}\b",
        severity="critical",
    ),
    # XML/HTML password tags
    SecretPattern(
        name="xml_password",
        pattern=r"<(?:password|secret|token|apikey)>[^<]{3,}</(?:password|secret|token|apikey)>",
        flags=re.IGNORECASE,
        severity="critical",
    ),
    # Basic auth header (Base64 encoded credentials)
    SecretPattern(
        name="basic_auth",
        pattern=r"Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}",
        flags=re.IGNORECASE,
        severity="critical",
    ),
    # npm registry token
    SecretPattern(
        name="npm_token",
        pattern=r"//[^:]+/:_authToken=[^\s]{8,}",
        severity="critical",
    ),
    # URL-embedded passwords (e.g., https://user:pass@host)
    SecretPattern(
        name="url_password",
        pattern=r"://[^:]+:[^@\s]{3,}@",
        severity="critical",
    ),
    # Connection strings with passwords
    SecretPattern(
        name="connection_string_password",
        pattern=r"(?:Password|Pwd)\s*=\s*[^\s;]{3,}",
        flags=re.IGNORECASE,
        severity="critical",
    ),
    # curl -u user:password
    SecretPattern(
        name="curl_password",
        pattern=r"curl\s+.*-u\s+\S+:\S+",
        flags=re.IGNORECASE,
        severity="high",
    ),
    # Anthropic API key
    SecretPattern(
        name="anthropic_api_key",
        pattern=r"\bsk-ant-[a-zA-Z0-9\-]{20,}\b",
        severity="critical",
    ),
]

DEFAULT_SENSITIVE_FIELDS: List[str] = [
    "password",
    "secret",
    "token",
    "api_key",
    "apiKey",
    "private_key",
    "privateKey",
    "ssn",
    "social_security",
    "credit_card",
    "creditCard",
    "card_number",
    "cardNumber",
    "cvv",
    "pin",
    "account_number",
    "accountNumber",
    "routing_number",
    "routingNumber",
]


class OutputFilter:
    """Filters LLM output to prevent sensitive data leakage."""

    def __init__(
        self,
        *,
        detect_pii: bool = True,
        pii_patterns: Optional[List[PIIPattern]] = None,
        sensitive_fields: Optional[List[str]] = None,
        detect_secrets: bool = True,
        secret_patterns: Optional[List[SecretPattern]] = None,
        role_filters: Optional[Dict[str, List[str]]] = None,
        masking_char: str = "*",
        preserve_length: bool = False,
        logger: Optional[LoggerFunc] = None,
    ) -> None:
        self.detect_pii = detect_pii
        self.pii_patterns = pii_patterns if pii_patterns is not None else DEFAULT_PII_PATTERNS
        self.sensitive_fields = sensitive_fields if sensitive_fields is not None else DEFAULT_SENSITIVE_FIELDS
        self.detect_secrets = detect_secrets
        self.secret_patterns = secret_patterns if secret_patterns is not None else DEFAULT_SECRET_PATTERNS
        self.role_filters = role_filters if role_filters is not None else {}
        self.masking_char = masking_char
        self.preserve_length = preserve_length
        self.logger = logger or _noop_logger

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def filter(
        self,
        output: Any,
        role: Optional[str] = None,
        request_id: str = "",
    ) -> OutputFilterResult:
        """Filter output and detect sensitive data."""
        violations: List[str] = []
        pii_detections: List[PIIDetection] = []
        secret_detections: List[SecretDetection] = []
        filtered_fields: List[str] = []
        blocking_reason: Optional[str] = None

        # Convert to string for pattern matching
        if isinstance(output, str):
            output_str = output
        else:
            try:
                output_str = json.dumps(output)
            except (TypeError, ValueError):
                output_str = str(output)

        # Detect PII
        if self.detect_pii:
            for pii_pat in self.pii_patterns:
                regex = re.compile(pii_pat.pattern, pii_pat.flags)
                matches = regex.findall(output_str)
                if matches:
                    pii_detections.append(
                        PIIDetection(
                            type=pii_pat.name,
                            count=len(matches),
                            masked=True,
                            locations=self._find_locations(output_str, regex),
                        )
                    )
                    violations.append(f"PII_DETECTED_{pii_pat.name.upper()}")

        # Detect secrets
        if self.detect_secrets:
            for sec_pat in self.secret_patterns:
                regex = re.compile(sec_pat.pattern, sec_pat.flags)
                matches = regex.findall(output_str)
                if matches:
                    secret_detections.append(
                        SecretDetection(
                            type=sec_pat.name,
                            severity=sec_pat.severity,
                            blocked=(sec_pat.severity == "critical"),
                            location="response",
                        )
                    )
                    violations.append(f"SECRET_DETECTED_{sec_pat.name.upper()}")

                    if sec_pat.severity == "critical":
                        blocking_reason = f"Critical secret detected: {sec_pat.name}"

        # Build filtered output (deep clone objects via JSON round-trip)
        if isinstance(output, str):
            filtered_output = output
        else:
            try:
                filtered_output = json.loads(json.dumps(output))
            except (TypeError, ValueError):
                filtered_output = str(output)

        # Mask PII in output
        if self.detect_pii and isinstance(filtered_output, str):
            for pii_pat in self.pii_patterns:
                regex = re.compile(pii_pat.pattern, pii_pat.flags)
                replacement = pii_pat.mask_as or self._generate_mask(8)
                filtered_output = regex.sub(replacement, filtered_output)
        elif isinstance(filtered_output, dict) or isinstance(filtered_output, list):
            filtered_output = self._filter_object(
                filtered_output, role, filtered_fields, pii_detections
            )

        # Mask secrets in output
        if self.detect_secrets and isinstance(filtered_output, str):
            for sec_pat in self.secret_patterns:
                regex = re.compile(sec_pat.pattern, sec_pat.flags)
                label = f"[{sec_pat.name.upper()}]"
                filtered_output = regex.sub(label, filtered_output)

        # Determine if blocked
        has_blocking_secrets = any(s.blocked for s in secret_detections)
        allowed = not has_blocking_secrets

        if not allowed:
            self.logger(
                f"[OutputFilter:{request_id}] BLOCKED: {blocking_reason}",
                "info",
            )

        return OutputFilterResult(
            allowed=allowed,
            reason=None if allowed else blocking_reason,
            violations=violations,
            pii_detected=pii_detections,
            secrets_detected=secret_detections,
            filtered_fields=filtered_fields,
            original_response=output,
            filtered_response=filtered_output,
            blocking_reason=blocking_reason,
        )

    def contains_sensitive_data(self, output: Any) -> bool:
        """Quick check if output contains any sensitive data."""
        result = self.filter(output)
        return (
            len(result.pii_detected) > 0
            or len(result.secrets_detected) > 0
            or len(result.filtered_fields) > 0
        )

    def mask(self, value: str, type_name: Optional[str] = None) -> str:
        """Mask a specific value."""
        if type_name:
            for pii_pat in self.pii_patterns:
                if pii_pat.name == type_name and pii_pat.mask_as:
                    return pii_pat.mask_as
        return self._generate_mask(len(value))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _filter_object(
        self,
        obj: Any,
        role: Optional[str],
        filtered_fields: List[str],
        pii_detections: List[PIIDetection],
    ) -> Any:
        if isinstance(obj, list):
            return [
                self._filter_object(item, role, filtered_fields, pii_detections)
                for item in obj
            ]

        if not isinstance(obj, dict):
            if isinstance(obj, str):
                return self._mask_pii_in_string(obj, pii_detections)
            return obj

        result: Dict[str, Any] = {}
        role_specific_filter = self.role_filters.get(role) if role else None

        for key, value in obj.items():
            lower_key = key.lower()

            # Check if field should be filtered
            is_sensitive = any(
                f.lower() in lower_key for f in self.sensitive_fields
            )
            is_role_filtered = (
                role_specific_filter is not None and key in role_specific_filter
            )

            if is_sensitive or is_role_filtered:
                filtered_fields.append(key)
                result[key] = "[FILTERED]"
                continue

            # Recursively filter nested objects
            if isinstance(value, (dict, list)):
                result[key] = self._filter_object(
                    value, role, filtered_fields, pii_detections
                )
            elif isinstance(value, str):
                result[key] = self._mask_pii_in_string(value, pii_detections)
            else:
                result[key] = value

        return result

    def _mask_pii_in_string(
        self, s: str, pii_detections: List[PIIDetection]
    ) -> str:
        result = s
        for pii_pat in self.pii_patterns:
            regex = re.compile(pii_pat.pattern, pii_pat.flags)
            replacement = pii_pat.mask_as or self._generate_mask(8)
            result = regex.sub(replacement, result)
        return result

    def _generate_mask(self, length: int) -> str:
        if self.preserve_length:
            return self.masking_char * length
        return self.masking_char * 8

    def _find_locations(self, text: str, regex: re.Pattern) -> List[str]:  # type: ignore[type-arg]
        locations: List[str] = []
        for match in regex.finditer(text):
            locations.append(f"index:{match.start()}")
        return locations
