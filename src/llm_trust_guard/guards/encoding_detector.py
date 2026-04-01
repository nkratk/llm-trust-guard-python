"""
EncodingDetector

Detects and blocks encoding-based bypass attempts:
- Base64 encoded payloads
- URL encoded attacks
- Unicode/punycode obfuscation
- Hex encoding
- HTML entity encoding
- Mixed encoding attacks
- ROT13 encoding
- Octal encoding
- Base32 encoding

Zero dependencies — uses only Python stdlib.
"""

import re
import base64
import unicodedata
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import unquote


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ThreatPattern:
    name: str
    pattern: re.Pattern
    severity: str  # "low" | "medium" | "high" | "critical"


@dataclass
class EncodingDetection:
    type: str
    count: int
    locations: List[str] = field(default_factory=list)
    decoded_sample: Optional[str] = None


@dataclass
class ThreatFound:
    pattern_name: str
    severity: str
    in_layer: str  # "original" | "decoded_base64" | …


@dataclass
class EncodingAnalysis:
    encodings_detected: List[EncodingDetection] = field(default_factory=list)
    decoded_content: Optional[str] = None
    threats_found: List[ThreatFound] = field(default_factory=list)
    obfuscation_score: int = 0


@dataclass
class EncodingDetectorResult:
    allowed: bool
    reason: Optional[str] = None
    violations: List[str] = field(default_factory=list)
    encoding_analysis: EncodingAnalysis = field(default_factory=EncodingAnalysis)


# ---------------------------------------------------------------------------
# Internal helper result types (not part of public API)
# ---------------------------------------------------------------------------

@dataclass
class _Base64Result:
    found: bool
    matches: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    decoded: Optional[str] = None


@dataclass
class _URLResult:
    found: bool
    count: int = 0
    ratio: float = 0.0
    decoded: Optional[str] = None


@dataclass
class _UnicodeResult:
    found: bool
    count: int = 0
    types: List[str] = field(default_factory=list)
    normalized: Optional[str] = None
    normalized_spaced: Optional[str] = None


@dataclass
class _HexResult:
    found: bool
    matches: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    decoded: Optional[str] = None


@dataclass
class _HTMLResult:
    found: bool
    count: int = 0
    decoded: Optional[str] = None


@dataclass
class _ROT13Result:
    found: bool
    matches: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    decoded: Optional[str] = None


@dataclass
class _OctalResult:
    found: bool
    matches: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    decoded: Optional[str] = None


@dataclass
class _Base32Result:
    found: bool
    matches: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    decoded: Optional[str] = None


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass
class EncodingDetectorConfig:
    detect_base64: bool = True
    detect_url_encoding: bool = True
    detect_unicode: bool = True
    detect_hex: bool = True
    detect_html_entities: bool = True
    detect_mixed_encoding: bool = True
    detect_rot13: bool = True
    detect_octal: bool = True
    detect_base32: bool = True
    max_decoding_depth: int = 3
    threat_patterns: Optional[List[ThreatPattern]] = None
    max_encoded_ratio: float = 0.5
    logger: Optional[Callable[[str, str], None]] = None


# ---------------------------------------------------------------------------
# Default threat patterns
# ---------------------------------------------------------------------------

_DEFAULT_THREAT_PATTERNS: List[ThreatPattern] = [
    # SQL Injection
    ThreatPattern(
        name="sql_injection",
        pattern=re.compile(
            r"(?:union\s+(?:all\s+)?select|drop\s+(?:table|database)|insert\s+into"
            r"|delete\s+from|update\s+.*set|exec\s*\(|execute\s*\(|truncate\s+table"
            r"|alter\s+table|create\s+table|;\s*select\s|or\s+1\s*=\s*1|'\s*or\s*'"
            r"|--\s*$|/\*.*\*/)",
            re.IGNORECASE,
        ),
        severity="critical",
    ),
    # Command Injection
    ThreatPattern(
        name="command_injection",
        pattern=re.compile(
            r"(?:;\s*(?:cat|ls|rm|wget|curl|bash|sh|python|perl|ruby|nc|netcat|nmap"
            r"|chmod|chown|kill|pkill)|`[^`]+`|\$\([^)]+\)|\|\s*(?:sh|bash)"
            r"|&&\s*(?:rm|cat|wget)|>\s*/(?:etc|tmp|var))",
            re.IGNORECASE,
        ),
        severity="critical",
    ),
    # Path Traversal
    ThreatPattern(
        name="path_traversal",
        pattern=re.compile(
            r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%2e%2e%5c|\.\.%5c"
            r"|%252e%252e|%c0%ae|%c1%9c|\.\.%c0%af|\.\.%c1%9c)",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    # XSS
    ThreatPattern(
        name="xss",
        pattern=re.compile(
            r"(?:<script|javascript:|on\w+\s*=|<iframe|<object|<embed"
            r"|<svg\s+onload|<img\s+onerror|<body\s+onload|expression\s*\("
            r"|vbscript:|data:text/html|<style>.*expression)",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    # Prompt Injection
    ThreatPattern(
        name="prompt_injection",
        pattern=re.compile(
            r"(?:ignore\s+(?:all\s+)?(?:previous|prior|above|the)?\s*"
            r"(?:instructions|rules|guidelines|directives)?|disregard\s+"
            r"(?:above|all|everything|the)|you\s+are\s+now|new\s+instructions"
            r"|forget\s+(?:everything|all)|system\s*:\s*you|act\s+as\s+(?:a|an|if)"
            r"|pretend\s+(?:you|to\s+be)|roleplay\s+as|jailbreak|DAN\s+mode"
            r"|developer\s+mode|bypass\s+(?:safety|security|restrictions|filters)"
            r"|reveal\s+.*(?:system|prompt|instructions|secret|password)"
            r"|show\s+.*(?:system|prompt|instructions)"
            r"|output\s+.*(?:system|prompt|instructions)"
            r"|system\s+prompt|your\s+(?:system|initial)\s+(?:prompt|instructions))",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    # System Commands
    ThreatPattern(
        name="system_command",
        pattern=re.compile(
            r"(?:/bin/|/etc/passwd|/etc/shadow|cmd\.exe|powershell|\.exe|\.bat"
            r"|\.cmd|\.ps1|\.sh\s|eval\s*\(|system\s*\(|exec\s*\(|popen"
            r"|subprocess|os\.system)",
            re.IGNORECASE,
        ),
        severity="critical",
    ),
    # Data Exfiltration
    ThreatPattern(
        name="data_exfiltration",
        pattern=re.compile(
            r"(?:curl\s+.*-d|wget\s+.*--post|fetch\s*\(|XMLHttpRequest"
            r"|sendBeacon|\.innerHTML\s*=|document\.cookie|localStorage\."
            r"|sessionStorage\.)",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    # LDAP Injection
    ThreatPattern(
        name="ldap_injection",
        pattern=re.compile(
            r"(?:\)\s*\(\||\*\)\s*\(|\)\s*\(&|%28%7c|%29%28)",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    # XML / XXE Injection
    ThreatPattern(
        name="xxe_injection",
        pattern=re.compile(
            r'(?:<!ENTITY|<!DOCTYPE.*SYSTEM|<!DOCTYPE.*PUBLIC'
            r'|SYSTEM\s*"file:|SYSTEM\s*"http)',
            re.IGNORECASE,
        ),
        severity="critical",
    ),
    # Template Injection
    ThreatPattern(
        name="template_injection",
        pattern=re.compile(
            r"(?:\{\{.*\}\}|\$\{.*\}|<%.*%>|<\?.*\?>|\[\[.*\]\])",
            re.IGNORECASE,
        ),
        severity="high",
    ),
    # Role / Permission Escalation
    ThreatPattern(
        name="role_escalation",
        pattern=re.compile(
            r"""(?:admin\s*:\s*true|role\s*:\s*(?:admin|root|superuser)"""
            r"""|isAdmin\s*=\s*true|permissions?\s*:\s*\[?\s*['\"]\*['\"])""",
            re.IGNORECASE,
        ),
        severity="critical",
    ),
]


# ---------------------------------------------------------------------------
# Zero-width & bidi character sets (reused across methods)
# ---------------------------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(
    "[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]"
)

_BIDI_RE = re.compile(
    "[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]"
)

_TAG_CHARS_RE = re.compile("[\U000E0000-\U000E007F]")


# ---------------------------------------------------------------------------
# EncodingDetector
# ---------------------------------------------------------------------------

class EncodingDetector:
    """Detects encoding-based bypass attempts and scans decoded content for threats."""

    def __init__(self, config: Optional[EncodingDetectorConfig] = None) -> None:
        cfg = config or EncodingDetectorConfig()
        self._config = cfg
        if cfg.threat_patterns is None:
            cfg.threat_patterns = list(_DEFAULT_THREAT_PATTERNS)
        self._logger = cfg.logger or (lambda msg, level: None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self, input_text: str, request_id: str = "") -> EncodingDetectorResult:
        """Detect encoding and analyse for threats."""
        violations: List[str] = []
        encodings_detected: List[EncodingDetection] = []
        threats_found: List[ThreatFound] = []
        obfuscation_score = 0

        # Check original input for threats
        self._check_threats(input_text, "original", threats_found)

        # --- Base64 ---
        if self._config.detect_base64:
            r = self._detect_base64(input_text)
            if r.found:
                encodings_detected.append(EncodingDetection(
                    type="base64", count=len(r.matches),
                    locations=r.locations,
                    decoded_sample=r.decoded[:100] if r.decoded else None,
                ))
                obfuscation_score += 3
                violations.append("BASE64_ENCODING_DETECTED")
                if r.decoded:
                    self._check_threats(r.decoded, "decoded_base64", threats_found)

        # --- URL encoding ---
        if self._config.detect_url_encoding:
            r_url = self._detect_url_encoding(input_text)
            if r_url.found:
                encodings_detected.append(EncodingDetection(
                    type="url_encoding", count=r_url.count,
                    locations=[],
                    decoded_sample=r_url.decoded[:100] if r_url.decoded else None,
                ))
                obfuscation_score += 4 if r_url.ratio > 0.3 else 2
                if r_url.ratio > self._config.max_encoded_ratio:
                    violations.append("EXCESSIVE_URL_ENCODING")
                if r_url.decoded:
                    self._check_threats(r_url.decoded, "decoded_url", threats_found)

        # --- Unicode ---
        if self._config.detect_unicode:
            r_uni = self._detect_unicode(input_text)
            if r_uni.found:
                encodings_detected.append(EncodingDetection(
                    type="unicode", count=r_uni.count,
                    locations=r_uni.types,
                    decoded_sample=r_uni.normalized[:100] if r_uni.normalized else None,
                ))
                obfuscation_score += 3
                violations.append("UNICODE_OBFUSCATION_DETECTED")
                # Dual normalization (v4.13.1): stripped + spaced
                if r_uni.normalized:
                    self._check_threats(r_uni.normalized, "decoded_unicode", threats_found)
                if r_uni.normalized_spaced and r_uni.normalized_spaced != r_uni.normalized:
                    self._check_threats(r_uni.normalized_spaced, "decoded_unicode", threats_found)

        # --- Hex ---
        if self._config.detect_hex:
            r_hex = self._detect_hex(input_text)
            if r_hex.found:
                encodings_detected.append(EncodingDetection(
                    type="hex", count=len(r_hex.matches),
                    locations=r_hex.locations,
                    decoded_sample=r_hex.decoded[:100] if r_hex.decoded else None,
                ))
                obfuscation_score += 2
                violations.append("HEX_ENCODING_DETECTED")
                if r_hex.decoded:
                    self._check_threats(r_hex.decoded, "decoded_hex", threats_found)
                    # Also check the full input with hex replaced
                    full_decoded = re.sub(
                        r"(?:0x|\\x)([0-9A-Fa-f]{2})",
                        lambda m: chr(int(m.group(1), 16)),
                        input_text,
                    )
                    self._check_threats(full_decoded, "decoded_hex", threats_found)

        # --- HTML entities ---
        if self._config.detect_html_entities:
            r_html = self._detect_html_entities(input_text)
            if r_html.found:
                encodings_detected.append(EncodingDetection(
                    type="html_entities", count=r_html.count,
                    locations=[],
                    decoded_sample=r_html.decoded[:100] if r_html.decoded else None,
                ))
                obfuscation_score += 2
                entity_chars = r_html.count * 5
                if len(input_text) > 10 and entity_chars / len(input_text) > 0.5:
                    obfuscation_score += 3
                    violations.append("EXCESSIVE_HTML_ENTITY_ENCODING")
                if r_html.decoded:
                    self._check_threats(r_html.decoded, "decoded_html", threats_found)

        # --- ROT13 ---
        if self._config.detect_rot13:
            r_rot = self._detect_rot13(input_text)
            if r_rot.found:
                encodings_detected.append(EncodingDetection(
                    type="rot13", count=len(r_rot.matches),
                    locations=r_rot.locations,
                    decoded_sample=r_rot.decoded[:100] if r_rot.decoded else None,
                ))
                obfuscation_score += 3
                violations.append("ROT13_ENCODING_DETECTED")
                if r_rot.decoded:
                    self._check_threats(r_rot.decoded, "decoded_rot13", threats_found)

        # --- Octal ---
        if self._config.detect_octal:
            r_oct = self._detect_octal(input_text)
            if r_oct.found:
                encodings_detected.append(EncodingDetection(
                    type="octal", count=len(r_oct.matches),
                    locations=r_oct.locations,
                    decoded_sample=r_oct.decoded[:100] if r_oct.decoded else None,
                ))
                obfuscation_score += 2
                violations.append("OCTAL_ENCODING_DETECTED")
                if r_oct.decoded:
                    self._check_threats(r_oct.decoded, "decoded_octal", threats_found)

        # --- Base32 ---
        if self._config.detect_base32:
            r_b32 = self._detect_base32(input_text)
            if r_b32.found:
                encodings_detected.append(EncodingDetection(
                    type="base32", count=len(r_b32.matches),
                    locations=r_b32.locations,
                    decoded_sample=r_b32.decoded[:100] if r_b32.decoded else None,
                ))
                obfuscation_score += 3
                violations.append("BASE32_ENCODING_DETECTED")
                if r_b32.decoded:
                    self._check_threats(r_b32.decoded, "decoded_base32", threats_found)

        # --- Mixed encoding ---
        if self._config.detect_mixed_encoding and len(encodings_detected) > 1:
            obfuscation_score += len(encodings_detected) * 2
            violations.append("MIXED_ENCODING_DETECTED")

        # Add violations for threats found
        for threat in threats_found:
            if threat.severity in ("critical", "high"):
                violations.append(
                    f"ENCODED_THREAT_{threat.pattern_name.upper()}_IN_{threat.in_layer.upper()}"
                )

        # Blocking logic
        has_encoding_detected = len(encodings_detected) > 0
        has_threat_in_decoded = any(
            t.severity in ("critical", "high") and t.in_layer != "original"
            for t in threats_found
        )
        has_critical_in_original_with_encoding = has_encoding_detected and any(
            t.severity == "critical" and t.in_layer == "original"
            for t in threats_found
        )
        allowed = not has_threat_in_decoded and not has_critical_in_original_with_encoding

        if not allowed:
            self._logger(
                f"[EncodingDetector:{request_id}] BLOCKED: {', '.join(violations)}",
                "info",
            )

        # Fully decode content
        decoded_content = input_text
        for _ in range(self._config.max_decoding_depth):
            decoded = self._fully_decode(decoded_content)
            if decoded == decoded_content:
                break
            decoded_content = decoded

        return EncodingDetectorResult(
            allowed=allowed,
            reason=None if allowed else f"Encoding bypass attempt detected: {', '.join(violations)}",
            violations=violations,
            encoding_analysis=EncodingAnalysis(
                encodings_detected=encodings_detected,
                decoded_content=decoded_content if decoded_content != input_text else None,
                threats_found=threats_found,
                obfuscation_score=obfuscation_score,
            ),
        )

    def contains_encoded_threat(self, input_text: str) -> bool:
        """Quick check if input contains encoded threats."""
        result = self.detect(input_text)
        return any(
            t.in_layer != "original"
            for t in result.encoding_analysis.threats_found
        )

    # ------------------------------------------------------------------
    # Detection methods
    # ------------------------------------------------------------------

    def _detect_base64(self, input_text: str) -> _Base64Result:
        # Min 20 chars (5 groups of 4) to reduce false positives
        pattern = re.compile(
            r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?"
        )
        matches: List[str] = []
        locations: List[str] = []
        decoded: Optional[str] = None

        for m in pattern.finditer(input_text):
            try:
                candidate = m.group(0)
                decoded_bytes = base64.b64decode(candidate)
                decoded_str = decoded_bytes.decode("utf-8")
                # Check if it decodes to printable ASCII
                if re.fullmatch(r"[\x20-\x7E\r\n\t]+", decoded_str):
                    matches.append(candidate)
                    locations.append(f"index:{m.start()}")
                    decoded = (decoded + " " + decoded_str) if decoded else decoded_str
            except Exception:
                pass

        return _Base64Result(found=len(matches) > 0, matches=matches, locations=locations, decoded=decoded)

    def _detect_url_encoding(self, input_text: str) -> _URLResult:
        url_encoded = re.findall(r"%[0-9A-Fa-f]{2}", input_text)
        count = len(url_encoded)
        ratio = (count * 3) / len(input_text) if input_text else 0.0

        decoded: Optional[str] = None
        if count > 0:
            try:
                decoded = unquote(input_text)
            except Exception:
                # Partial decoding fallback
                def _replace_hex(m: re.Match) -> str:
                    try:
                        return chr(int(m.group(1), 16))
                    except Exception:
                        return m.group(0)
                decoded = re.sub(r"%([0-9A-Fa-f]{2})", _replace_hex, input_text)

        return _URLResult(found=count > 0, count=count, ratio=ratio, decoded=decoded)

    def _detect_unicode(self, input_text: str) -> _UnicodeResult:
        types: List[str] = []
        count = 0

        # \uXXXX escape sequences
        escape_matches = re.findall(r"\\u[0-9A-Fa-f]{4}", input_text)
        if escape_matches:
            count += len(escape_matches)
            types.append("unicode_escape_u")

        # \u{XXXXX} ES6 style
        es6_matches = re.findall(r"\\u\{[0-9A-Fa-f]{1,6}\}", input_text)
        if es6_matches:
            count += len(es6_matches)
            types.append("unicode_escape_es6")

        # \UXXXXXXXX Python style
        python_matches = re.findall(r"\\U[0-9A-Fa-f]{8}", input_text)
        if python_matches:
            count += len(python_matches)
            types.append("unicode_escape_U")

        # Homoglyphs: Cyrillic, Greek, fullwidth, math alphanumerics
        homoglyph_matches = re.findall(
            "[\u0430-\u044F\u0410-\u042F\u0391-\u03C9\u2010-\u2015"
            "\uFF01-\uFF5E\U0001D400-\U0001D7FF]",
            input_text,
        )
        if homoglyph_matches:
            count += len(homoglyph_matches)
            types.append("homoglyphs")

        # Zero-width characters
        zw_matches = _ZERO_WIDTH_RE.findall(input_text)
        if zw_matches:
            count += len(zw_matches)
            types.append("zero_width")

        # Bidi control characters
        bidi_matches = _BIDI_RE.findall(input_text)
        if bidi_matches:
            count += len(bidi_matches)
            types.append("bidi_controls")

        # Confusable characters
        confusable_matches = re.findall(
            "[\u0131\u0130\u017F\u212A\u0261\u0251\u025B\u0254\u028C]",
            input_text,
        )
        if confusable_matches:
            count += len(confusable_matches)
            types.append("confusables")

        # Tag characters
        tag_matches = _TAG_CHARS_RE.findall(input_text)
        if tag_matches:
            count += len(tag_matches)
            types.append("tag_characters")

        normalized: Optional[str] = None
        normalized_spaced: Optional[str] = None

        if count > 0:
            base = unicodedata.normalize("NFKC", input_text)
            # Decode \uXXXX
            base = re.sub(
                r"\\u([0-9A-Fa-f]{4})",
                lambda m: chr(int(m.group(1), 16)),
                base,
            )
            # Decode \u{XXXXX}
            base = re.sub(
                r"\\u\{([0-9A-Fa-f]{1,6})\}",
                lambda m: chr(int(m.group(1), 16)),
                base,
            )
            # Decode \UXXXXXXXX
            base = re.sub(
                r"\\U([0-9A-Fa-f]{8})",
                lambda m: chr(int(m.group(1), 16)),
                base,
            )
            # Replace common homoglyphs with Latin equivalents
            _HOMOGLYPH_MAP = {
                "\u0430": "a", "\u0410": "A",  # Cyrillic а/А
                "\u0435": "e", "\u0415": "E",  # Cyrillic е/Е
                "\u043E": "o", "\u041E": "O",  # Cyrillic о/О
                "\u0440": "p", "\u0420": "P",  # Cyrillic р/Р
                "\u0441": "c", "\u0421": "C",  # Cyrillic с/С
                "\u0443": "y", "\u0423": "Y",  # Cyrillic у/У
                "\u0456": "i", "\u0406": "I",  # Cyrillic і/І
                "\u0445": "x", "\u0425": "X",  # Cyrillic х/Х
                "\u0422": "T", "\u041D": "H",  # Cyrillic Т/Н
                "\u041C": "M", "\u041A": "K",  # Cyrillic М/К
                "\u0392": "B", "\u0395": "E",  # Greek Β/Ε
                "\u0397": "H", "\u039A": "K",  # Greek Η/Κ
                "\u039C": "M", "\u039D": "N",  # Greek Μ/Ν
                "\u039F": "O", "\u03A1": "P",  # Greek Ο/Ρ
                "\u03A4": "T", "\u0396": "Z",  # Greek Τ/Ζ
            }
            for src, dst in _HOMOGLYPH_MAP.items():
                base = base.replace(src, dst)

            # Remove bidi controls
            base = _BIDI_RE.sub("", base)
            # Remove tag characters
            base = _TAG_CHARS_RE.sub("", base)

            # Primary: strip ZWS (intra-word: "igno\u200Bre" -> "ignore")
            normalized = _ZERO_WIDTH_RE.sub("", base)
            normalized = re.sub(r"\s{2,}", " ", normalized).strip()

            # Secondary: replace ZWS with space (inter-word: "Ignore\u200Bprevious" -> "Ignore previous")
            normalized_spaced = _ZERO_WIDTH_RE.sub(" ", base)
            normalized_spaced = re.sub(r"\s{2,}", " ", normalized_spaced).strip()

        return _UnicodeResult(
            found=count > 0, count=count, types=types,
            normalized=normalized, normalized_spaced=normalized_spaced,
        )

    def _detect_hex(self, input_text: str) -> _HexResult:
        matches: List[str] = []
        locations: List[str] = []
        decoded = ""

        # Pattern 1: 0x41 or \x41
        for m in re.finditer(r"(?:0x|\\x)([0-9A-Fa-f]{2})", input_text):
            matches.append(m.group(0))
            locations.append(f"index:{m.start()}")
            decoded += chr(int(m.group(1), 16))

        # Pattern 2: Consecutive hex bytes (min 8 chars = 4 bytes)
        for m in re.finditer(r"(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{8,})(?:[^0-9A-Fa-f]|$)", input_text):
            hex_string = m.group(1)
            if len(hex_string) % 2 == 0:
                decoded_bytes = ""
                is_printable = True
                for i in range(0, len(hex_string), 2):
                    byte_val = int(hex_string[i:i + 2], 16)
                    if 32 <= byte_val <= 126:
                        decoded_bytes += chr(byte_val)
                    else:
                        is_printable = False
                        break
                if is_printable and len(decoded_bytes) >= 4:
                    matches.append(hex_string)
                    locations.append(f"index:{m.start()}")
                    decoded += decoded_bytes

        # Pattern 3: Space-separated hex bytes "41 42 43 44"
        for m in re.finditer(r"(?:[0-9A-Fa-f]{2}\s+){3,}[0-9A-Fa-f]{2}", input_text):
            byte_strs = m.group(0).split()
            decoded_bytes = ""
            is_printable = True
            for bs in byte_strs:
                byte_val = int(bs, 16)
                if 32 <= byte_val <= 126:
                    decoded_bytes += chr(byte_val)
                else:
                    is_printable = False
                    break
            if is_printable and len(decoded_bytes) >= 4:
                matches.append(m.group(0))
                locations.append(f"index:{m.start()}")
                decoded += decoded_bytes

        return _HexResult(
            found=len(matches) > 0, matches=matches, locations=locations,
            decoded=decoded or None,
        )

    def _detect_html_entities(self, input_text: str) -> _HTMLResult:
        entity_pattern = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|\w+);")
        entity_matches = entity_pattern.findall(input_text)
        count = len(entity_matches)

        decoded: Optional[str] = None
        if count > 0:
            decoded = re.sub(
                r"&#(\d+);",
                lambda m: chr(int(m.group(1))),
                input_text,
            )
            decoded = re.sub(
                r"&#x([0-9A-Fa-f]+);",
                lambda m: chr(int(m.group(1), 16)),
                decoded,
            )
            decoded = decoded.replace("&lt;", "<")
            decoded = decoded.replace("&gt;", ">")
            decoded = decoded.replace("&amp;", "&")
            decoded = decoded.replace("&quot;", '"')
            decoded = decoded.replace("&apos;", "'")

        return _HTMLResult(found=count > 0, count=count, decoded=decoded)

    def _detect_rot13(self, input_text: str) -> _ROT13Result:
        def _rot13_decode(s: str) -> str:
            result = []
            for ch in s:
                if "a" <= ch <= "z":
                    result.append(chr((ord(ch) - 97 + 13) % 26 + 97))
                elif "A" <= ch <= "Z":
                    result.append(chr((ord(ch) - 65 + 13) % 26 + 65))
                else:
                    result.append(ch)
            return "".join(result)

        threat_keywords = [
            "ignore", "instructions", "system", "admin", "password", "secret",
            "delete", "drop", "select", "union", "script", "eval", "exec",
            "shell", "command", "root", "sudo", "bypass", "hack", "inject",
            "reveal", "prompt", "override", "jailbreak", "unrestricted",
        ]

        matches: List[str] = []
        locations: List[str] = []
        decoded: Optional[str] = None

        for m in re.finditer(r"\b[a-zA-Z]{5,}\b", input_text):
            candidate = m.group(0)
            decoded_word = _rot13_decode(candidate).lower()
            if decoded_word in threat_keywords:
                matches.append(candidate)
                locations.append(f"index:{m.start()}")
                decoded = (decoded + " " + decoded_word) if decoded else decoded_word

        # Also decode the entire input when it looks like ROT13 (all alpha+spaces)
        is_all_alpha = re.fullmatch(r"[a-zA-Z\s]+", input_text.strip())
        if matches or is_all_alpha:
            full_decoded = _rot13_decode(input_text)
            decoded = full_decoded  # Always use full decode for threat scanning
            if is_all_alpha and not matches:
                # Input is all alpha — likely ROT13 even without keyword matches
                matches.append(input_text[:20])
                locations.append("index:0")

        return _ROT13Result(found=len(matches) > 0, matches=matches, locations=locations, decoded=decoded)

    def _detect_octal(self, input_text: str) -> _OctalResult:
        pattern = re.compile(r"(?:\\([0-7]{3})|(?:^|\s)(0[0-7]{2,}))")
        matches: List[str] = []
        locations: List[str] = []
        decoded = ""

        for m in pattern.finditer(input_text):
            matches.append(m.group(0))
            locations.append(f"index:{m.start()}")
            if m.group(1):
                # \101 format
                decoded += chr(int(m.group(1), 8))
            elif m.group(2):
                # 0101 format
                char_code = int(m.group(2), 8)
                if 32 <= char_code <= 126:
                    decoded += chr(char_code)

        return _OctalResult(
            found=len(matches) > 0, matches=matches, locations=locations,
            decoded=decoded or None,
        )

    def _detect_base32(self, input_text: str) -> _Base32Result:
        pattern = re.compile(r"(?:[A-Z2-7]{8}){2,}(?:={0,6})?")
        matches: List[str] = []
        locations: List[str] = []
        decoded: Optional[str] = None

        _ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

        def _base32_decode(s: str) -> Optional[str]:
            clean = s.replace("=", "").upper()
            bits = ""
            for ch in clean:
                idx = _ALPHABET.find(ch)
                if idx == -1:
                    return None
                bits += format(idx, "05b")
            result = ""
            for i in range(0, len(bits) - 7, 8):
                byte_val = int(bits[i:i + 8], 2)
                if 32 <= byte_val <= 126:
                    result += chr(byte_val)
                else:
                    return None
            return result if result else None

        for m in pattern.finditer(input_text):
            try:
                candidate = m.group(0)
                decoded_str = _base32_decode(candidate)
                if decoded_str and len(decoded_str) >= 4:
                    matches.append(candidate)
                    locations.append(f"index:{m.start()}")
                    decoded = (decoded + " " + decoded_str) if decoded else decoded_str
            except Exception:
                pass

        return _Base32Result(found=len(matches) > 0, matches=matches, locations=locations, decoded=decoded)

    # ------------------------------------------------------------------
    # Threat checking
    # ------------------------------------------------------------------

    def _check_threats(
        self, content: str, layer: str, threats_found: List[ThreatFound]
    ) -> None:
        assert self._config.threat_patterns is not None
        for tp in self._config.threat_patterns:
            if tp.pattern.search(content):
                threats_found.append(ThreatFound(
                    pattern_name=tp.name,
                    severity=tp.severity,
                    in_layer=layer,
                ))

    # ------------------------------------------------------------------
    # Full decode pass
    # ------------------------------------------------------------------

    def _fully_decode(self, input_text: str) -> str:
        result = input_text

        # URL decode
        try:
            result = unquote(result)
        except Exception:
            def _replace_hex(m: re.Match) -> str:
                try:
                    return chr(int(m.group(1), 16))
                except Exception:
                    return m.group(0)
            result = re.sub(r"%([0-9A-Fa-f]{2})", _replace_hex, result)

        # Unicode decode \uXXXX
        result = re.sub(
            r"\\u([0-9A-Fa-f]{4})",
            lambda m: chr(int(m.group(1), 16)),
            result,
        )

        # Unicode decode ES6 \u{XXXXX}
        result = re.sub(
            r"\\u\{([0-9A-Fa-f]{1,6})\}",
            lambda m: chr(int(m.group(1), 16)),
            result,
        )

        # Unicode decode Python \UXXXXXXXX
        result = re.sub(
            r"\\U([0-9A-Fa-f]{8})",
            lambda m: chr(int(m.group(1), 16)),
            result,
        )

        # Hex decode
        result = re.sub(
            r"(?:0x|\\x)([0-9A-Fa-f]{2})",
            lambda m: chr(int(m.group(1), 16)),
            result,
        )

        # Octal decode \NNN
        result = re.sub(
            r"\\([0-7]{3})",
            lambda m: chr(int(m.group(1), 8)),
            result,
        )

        # HTML entity decode
        result = re.sub(r"&#(\d+);", lambda m: chr(int(m.group(1))), result)
        result = re.sub(r"&#x([0-9A-Fa-f]+);", lambda m: chr(int(m.group(1), 16)), result)
        result = result.replace("&lt;", "<")
        result = result.replace("&gt;", ">")
        result = result.replace("&amp;", "&")
        result = result.replace("&quot;", '"')
        result = result.replace("&apos;", "'")
        result = result.replace("&nbsp;", " ")

        # Remove zero-width characters
        result = _ZERO_WIDTH_RE.sub("", result)

        # Remove bidi control characters
        result = _BIDI_RE.sub("", result)

        return result
