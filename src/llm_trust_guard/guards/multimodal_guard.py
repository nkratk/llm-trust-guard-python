"""
MultiModalGuard (L8)

Detects hidden instructions and malicious content in multi-modal inputs
(images, audio, documents, base64 payloads).

Threat Model:
- ASI01: Agent Goal Hijack via manipulated media
- Multi-Modal Injection: Hidden text in images, audio with embedded instructions

Detection Capabilities:
- Image metadata (EXIF) injection
- Steganographic patterns
- Hidden text detection (white-on-white, etc.)
- Base64 embedded payloads
- Document macro/script detection
- Audio transcript injection markers
"""

import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class MultiModalGuardConfig:
    """Configuration for MultiModalGuard."""
    scan_metadata: bool = True
    detect_base64_payloads: bool = True
    detect_steganography: bool = True
    max_metadata_size: int = 10000  # 10KB
    custom_patterns: Optional[List["re.Pattern[str]"]] = None
    allowed_mime_types: Optional[List[str]] = None
    strict_mode: bool = False


@dataclass
class MultiModalContent:
    """Multi-modal content item."""
    type: Literal["image", "audio", "document", "base64", "url"]
    content: Optional[str] = None
    mime_type: Optional[str] = None
    url: Optional[str] = None
    filename: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    extracted_text: Optional[str] = None


@dataclass
class ContentAnalysis:
    """Content analysis details."""
    type: str
    threats_detected: List[str]
    metadata_suspicious: bool
    hidden_content_detected: bool
    injection_patterns_found: List[str]
    risk_score: int


@dataclass
class MultiModalGuardResult:
    """Result of a multi-modal content check."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    content_analysis: ContentAnalysis
    recommendations: List[str]


_InjectionPattern = Tuple[str, "re.Pattern[str]"]


class MultiModalGuard:
    """Detects hidden instructions and malicious content in multi-modal inputs."""

    INJECTION_PATTERNS: List[_InjectionPattern] = [
        ("ignore_instructions", re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|guidelines)", re.IGNORECASE)),
        ("system_override", re.compile(r"\[SYSTEM\]|\[ADMIN\]|\[OVERRIDE\]|<\s*system\s*>|<\s*admin\s*>", re.IGNORECASE)),
        ("role_switch", re.compile(r"you\s+are\s+(now|actually)\s+(a|an|the)|switch\s+to\s+(\w+)\s+mode", re.IGNORECASE)),
        ("hidden_prompt", re.compile(r"HIDDEN_PROMPT|SECRET_INSTRUCTION|INVISIBLE_COMMAND", re.IGNORECASE)),
        ("jailbreak_markers", re.compile(r"DAN\s*mode|developer\s*mode|unrestricted\s*mode|bypass\s*safety", re.IGNORECASE)),
        ("base64_instruction", re.compile(r"execute\s*:\s*[A-Za-z0-9+/=]{20,}", re.IGNORECASE)),
        ("command_injection", re.compile(r";\s*(rm|del|wget|curl|eval|exec)\s", re.IGNORECASE)),
        ("exfiltration_markers", re.compile(r"send\s+(to|this|data)\s+(to\s+)?https?://", re.IGNORECASE)),
        ("invisible_unicode", re.compile(r"[\u200B-\u200D\uFEFF\u2060-\u206F]")),
        ("json_policy_in_metadata", re.compile(r'"(?:role|instructions?|system|policy)"\s*:\s*"', re.IGNORECASE)),
        ("ini_policy_in_metadata", re.compile(r"^\s*\[(?:system|admin|override|config)\]\s*$", re.IGNORECASE | re.MULTILINE)),
        ("emoji_instruction_sequence", re.compile(r"(?:\U0001F513|\U0001F511|\U0001F6E1\uFE0F|\u2699\uFE0F|\U0001F527|\U0001F6AB|\u274C|\u2705)\s*(?:unlock|admin|override|bypass|disable|enable|grant|allow)", re.IGNORECASE)),
        ("rebus_instruction_pattern", re.compile(r"(?:[A-Z]{2,}\s*[-=:>\u2192]\s*){3,}")),
        ("metadata_split_marker", re.compile(r"(?:part|step|fragment)\s*[1-9]\s*(?:of|:)", re.IGNORECASE)),
    ]

    SUSPICIOUS_METADATA_FIELDS = [
        "ImageDescription", "UserComment", "XPComment", "XPKeywords",
        "XPSubject", "XPTitle", "Artist", "Copyright", "Software",
        "HostComputer", "DocumentName", "PageName",
    ]

    DANGEROUS_MIME_TYPES = [
        "application/x-msdownload", "application/x-msdos-program",
        "application/x-sh", "application/x-shellscript",
        "application/javascript", "text/javascript",
        "application/x-python", "application/vnd.ms-office",
    ]

    DEFAULT_ALLOWED_MIME_TYPES = [
        "image/jpeg", "image/png", "image/gif", "image/webp",
        "audio/mpeg", "audio/wav", "audio/ogg",
        "application/pdf", "text/plain",
    ]

    STEGO_MARKERS = [
        re.compile(rb"^[\x00-\x08\x0B\x0C\x0E-\x1F]{4,}"),
        re.compile(rb"PK\x03\x04"),
        re.compile(rb"%PDF-"),
        re.compile(rb"\x89PNG.*IEND.*[A-Za-z]{10,}", re.DOTALL),
    ]

    def __init__(self, config: Optional[MultiModalGuardConfig] = None) -> None:
        cfg = config or MultiModalGuardConfig()
        self._scan_metadata = cfg.scan_metadata
        self._detect_base64_payloads = cfg.detect_base64_payloads
        self._detect_steganography = cfg.detect_steganography
        self._max_metadata_size = cfg.max_metadata_size
        self._custom_patterns: List["re.Pattern[str]"] = cfg.custom_patterns or []
        self._allowed_mime_types = cfg.allowed_mime_types or list(self.DEFAULT_ALLOWED_MIME_TYPES)
        self._strict_mode = cfg.strict_mode

    def check(
        self,
        content: MultiModalContent,
        request_id: Optional[str] = None,
    ) -> MultiModalGuardResult:
        """Analyze multi-modal content for hidden instructions or malicious payloads."""
        req_id = request_id or f"mm-{_now_ms()}"
        violations: List[str] = []
        threats_detected: List[str] = []
        injection_patterns_found: List[str] = []
        risk_score = 0
        metadata_suspicious = False
        hidden_content_detected = False

        # Strict mode blocks all multi-modal content
        if self._strict_mode:
            return MultiModalGuardResult(
                allowed=False,
                reason="Multi-modal content blocked in strict mode",
                violations=["strict_mode_block"],
                request_id=req_id,
                content_analysis=ContentAnalysis(
                    type=content.type,
                    threats_detected=["strict_mode"],
                    metadata_suspicious=False,
                    hidden_content_detected=False,
                    injection_patterns_found=[],
                    risk_score=100,
                ),
                recommendations=["Disable strict mode to allow multi-modal content"],
            )

        # Check MIME type
        if content.mime_type:
            if content.mime_type in self.DANGEROUS_MIME_TYPES:
                violations.append("dangerous_mime_type")
                threats_detected.append(f"Dangerous MIME type: {content.mime_type}")
                risk_score += 50

            if content.mime_type not in self._allowed_mime_types:
                violations.append("disallowed_mime_type")
                threats_detected.append(f"Disallowed MIME type: {content.mime_type}")
                risk_score += 30

        # Check for suspicious filename
        if content.filename:
            dangerous_extensions = [".exe", ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".js"]
            dot_idx = content.filename.rfind(".")
            if dot_idx >= 0:
                ext = content.filename[dot_idx:].lower()
                if ext in dangerous_extensions:
                    violations.append("dangerous_file_extension")
                    threats_detected.append(f"Dangerous file extension: {ext}")
                    risk_score += 40

            # Double extension attack
            if re.search(r"\.(jpg|png|gif|pdf)\.(exe|sh|bat|js)$", content.filename, re.IGNORECASE):
                violations.append("double_extension_attack")
                threats_detected.append("Double extension attack detected")
                risk_score += 60

        # Scan metadata for injections
        if self._scan_metadata and content.metadata:
            meta_result = self._scan_metadata_dict(content.metadata)
            if meta_result["suspicious"]:
                metadata_suspicious = True
                violations.extend(meta_result["violations"])
                injection_patterns_found.extend(meta_result["patterns"])
                risk_score += meta_result["risk_contribution"]

            # Check metadata size
            metadata_size = len(json.dumps(content.metadata))
            if metadata_size > self._max_metadata_size:
                violations.append("oversized_metadata")
                threats_detected.append(
                    f"Metadata size {metadata_size} exceeds limit {self._max_metadata_size}"
                )
                risk_score += 20

        # Scan extracted text for injections
        if content.extracted_text:
            text_result = self._scan_text(content.extracted_text)
            if text_result["injection_found"]:
                hidden_content_detected = True
                violations.extend(text_result["violations"])
                injection_patterns_found.extend(text_result["patterns"])
                risk_score += text_result["risk_contribution"]

        # Detect base64 payloads in content
        if self._detect_base64_payloads and content.content:
            base64_result = self._detect_base64_payloads_in(content.content)
            if base64_result["found"]:
                violations.append("embedded_base64_payload")
                threats_detected.append("Embedded base64 payload detected")
                risk_score += 30

                for payload in base64_result["payloads"]:
                    try:
                        decoded = base64.b64decode(payload).decode("utf-8")
                        decoded_scan = self._scan_text(decoded)
                        if decoded_scan["injection_found"]:
                            hidden_content_detected = True
                            violations.append("base64_injection_payload")
                            injection_patterns_found.extend(decoded_scan["patterns"])
                            risk_score += 40
                    except Exception:
                        pass

        # Steganography detection heuristics
        if self._detect_steganography and content.content:
            stego_result = self._detect_steganography_in(content.content)
            if stego_result["detected"]:
                violations.append("potential_steganography")
                threats_detected.append("Potential steganography detected")
                hidden_content_detected = True
                risk_score += 25

        # URL safety check
        if content.type == "url" and content.url:
            url_result = self._check_url(content.url)
            if not url_result["safe"]:
                violations.extend(url_result["violations"])
                threats_detected.extend(url_result["threats"])
                risk_score += url_result["risk_contribution"]

        # Apply custom patterns
        all_text = " ".join([
            content.extracted_text or "",
            json.dumps(content.metadata or {}),
        ])
        for pattern in self._custom_patterns:
            if pattern.search(all_text):
                violations.append("custom_pattern_match")
                injection_patterns_found.append(f"Custom: {pattern.pattern[:30]}")
                risk_score += 20

        blocked = risk_score >= 50 or len(violations) > 0

        return MultiModalGuardResult(
            allowed=not blocked,
            reason=(
                f"Multi-modal content blocked: {', '.join(violations[:3])}"
                if blocked
                else "Multi-modal content passed security checks"
            ),
            violations=violations,
            request_id=req_id,
            content_analysis=ContentAnalysis(
                type=content.type,
                threats_detected=threats_detected,
                metadata_suspicious=metadata_suspicious,
                hidden_content_detected=hidden_content_detected,
                injection_patterns_found=injection_patterns_found,
                risk_score=min(100, risk_score),
            ),
            recommendations=self._generate_recommendations(violations),
        )

    def check_batch(
        self,
        contents: List[MultiModalContent],
        request_id: Optional[str] = None,
    ) -> MultiModalGuardResult:
        """Batch check multiple content items."""
        req_id = request_id or f"mm-batch-{_now_ms()}"
        all_violations: List[str] = []
        all_threats: List[str] = []
        all_patterns: List[str] = []
        total_risk_score = 0
        any_metadata_suspicious = False
        any_hidden_content = False

        for c in contents:
            result = self.check(c, req_id)
            all_violations.extend(result.violations)
            all_threats.extend(result.content_analysis.threats_detected)
            all_patterns.extend(result.content_analysis.injection_patterns_found)
            total_risk_score = max(total_risk_score, result.content_analysis.risk_score)
            any_metadata_suspicious = any_metadata_suspicious or result.content_analysis.metadata_suspicious
            any_hidden_content = any_hidden_content or result.content_analysis.hidden_content_detected

        unique_violations = list(dict.fromkeys(all_violations))
        unique_threats = list(dict.fromkeys(all_threats))
        unique_patterns = list(dict.fromkeys(all_patterns))

        blocked = total_risk_score >= 50 or len(unique_violations) > 0

        return MultiModalGuardResult(
            allowed=not blocked,
            reason=(
                f"Batch blocked: {', '.join(unique_violations[:3])}"
                if blocked
                else "All multi-modal content passed security checks"
            ),
            violations=unique_violations,
            request_id=req_id,
            content_analysis=ContentAnalysis(
                type=f"batch({len(contents)})",
                threats_detected=unique_threats,
                metadata_suspicious=any_metadata_suspicious,
                hidden_content_detected=any_hidden_content,
                injection_patterns_found=unique_patterns,
                risk_score=total_risk_score,
            ),
            recommendations=self._generate_recommendations(unique_violations),
        )

    def parse_image_metadata(self, base64_image: str) -> Dict[str, Any]:
        """Extract and analyze image metadata (EXIF simulation)."""
        metadata: Dict[str, Any] = {}
        try:
            decoded = base64.b64decode(base64_image)
            content = decoded.decode("latin-1")

            text_matches = re.findall(r"[\x20-\x7E]{10,}", content)
            for match in text_matches[:20]:
                if "=" in match or ":" in match:
                    parts = re.split(r"[=:]", match, maxsplit=1)
                    if len(parts) == 2:
                        metadata[parts[0].strip()] = parts[1].strip()

            xmp_match = re.search(r"<x:xmpmeta[\s\S]*?</x:xmpmeta>", content, re.IGNORECASE)
            if xmp_match:
                metadata["_xmp"] = xmp_match.group(0)[:500]
        except Exception:
            pass
        return metadata

    # -- Private methods --

    def _scan_metadata_dict(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        violations: List[str] = []
        patterns: List[str] = []
        risk_contribution = 0

        def check_value(key: str, value: Any, path: str = "") -> None:
            nonlocal risk_contribution
            current_path = f"{path}.{key}" if path else key

            if isinstance(value, str):
                if key in self.SUSPICIOUS_METADATA_FIELDS:
                    for name, pattern in self.INJECTION_PATTERNS:
                        if pattern.search(value):
                            violations.append(f"metadata_injection_{name}")
                            patterns.append(f"{name} in {current_path}")
                            risk_contribution += 30

                for name, pattern in self.INJECTION_PATTERNS:
                    if pattern.search(value) and len(value) > 20:
                        violations.append(f"metadata_{name}")
                        patterns.append(f"{name} in {current_path}")
                        risk_contribution += 20
            elif isinstance(value, dict):
                for k, v in value.items():
                    check_value(k, v, current_path)

        for key, value in metadata.items():
            check_value(key, value)

        unique_violations = list(dict.fromkeys(violations))
        unique_patterns = list(dict.fromkeys(patterns))

        return {
            "suspicious": len(unique_violations) > 0,
            "violations": unique_violations,
            "patterns": unique_patterns,
            "risk_contribution": min(60, risk_contribution),
        }

    def _scan_text(self, text: str) -> Dict[str, Any]:
        violations: List[str] = []
        patterns: List[str] = []
        risk_contribution = 0

        for name, pattern in self.INJECTION_PATTERNS:
            if pattern.search(text):
                violations.append(f"text_injection_{name}")
                patterns.append(name)
                risk_contribution += 25

        invisible_count = len(re.findall(r"[\u200B-\u200D\uFEFF\u2060-\u206F]", text))
        if invisible_count > 5:
            violations.append("excessive_invisible_characters")
            patterns.append(f"invisible_unicode({invisible_count})")
            risk_contribution += 20

        homoglyph_re = re.compile(r"[\u0430-\u044F\u0410-\u042F]")
        if homoglyph_re.search(text) and re.search(r"[a-zA-Z]", text):
            violations.append("potential_homoglyph_attack")
            patterns.append("mixed_scripts")
            risk_contribution += 15

        return {
            "injection_found": len(violations) > 0,
            "violations": violations,
            "patterns": patterns,
            "risk_contribution": min(60, risk_contribution),
        }

    def _detect_base64_payloads_in(self, content: str) -> Dict[str, Any]:
        base64_pattern = re.compile(r"(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?:[^A-Za-z0-9+/]|$)")
        payloads: List[str] = []

        for match in base64_pattern.finditer(content):
            try:
                decoded = base64.b64decode(match.group(1))
                text = decoded.decode("utf-8")
                if re.search(r"[a-zA-Z\s]{10,}", text):
                    payloads.append(match.group(1))
            except Exception:
                pass

        return {"found": len(payloads) > 0, "payloads": payloads}

    def _detect_steganography_in(self, content: str) -> Dict[str, Any]:
        markers: List[str] = []
        content_bytes = content.encode("latin-1", errors="replace")

        for marker in self.STEGO_MARKERS:
            if marker.search(content_bytes):
                markers.append(marker.pattern[:20] if isinstance(marker.pattern, str) else str(marker.pattern)[:20])

        # Entropy analysis (simplified)
        sample = content[-1000:] if len(content) > 1000 else content
        if sample:
            unique_chars = len(set(sample))
            entropy = unique_chars / len(sample)
            if entropy > 0.9:
                markers.append("high_entropy_tail")

        return {"detected": len(markers) > 0, "markers": markers}

    def _check_url(self, url: str) -> Dict[str, Any]:
        violations: List[str] = []
        threats: List[str] = []
        risk_contribution = 0

        try:
            parsed = urlparse(url)

            if parsed.scheme not in ("http", "https"):
                violations.append("suspicious_protocol")
                threats.append(f"Suspicious protocol: {parsed.scheme}")
                risk_contribution += 40

            if parsed.hostname and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed.hostname):
                violations.append("ip_address_url")
                threats.append("Direct IP address URL")
                risk_contribution += 20

            if ".." in url or "%00" in url:
                violations.append("path_traversal_url")
                threats.append("Path traversal in URL")
                risk_contribution += 30

            if url.startswith("data:"):
                violations.append("data_url")
                threats.append("Data URL detected")
                risk_contribution += 25
        except Exception:
            violations.append("invalid_url")
            threats.append("Invalid URL format")
            risk_contribution += 30

        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "threats": threats,
            "risk_contribution": risk_contribution,
        }

    def _generate_recommendations(self, violations: List[str]) -> List[str]:
        recommendations: List[str] = []
        if any("metadata" in v for v in violations):
            recommendations.append("Strip metadata from uploaded files before processing")
        if any("base64" in v for v in violations):
            recommendations.append("Validate and sanitize base64 payloads before decoding")
        if any("mime" in v for v in violations):
            recommendations.append("Implement strict MIME type validation")
        if any("steganography" in v for v in violations):
            recommendations.append("Consider re-encoding images to remove hidden data")
        if any("injection" in v for v in violations):
            recommendations.append("Sanitize extracted text before including in prompts")
        if not recommendations:
            recommendations.append("Continue monitoring multi-modal inputs")
        return recommendations


def _now_ms() -> int:
    return int(time.time() * 1000)
