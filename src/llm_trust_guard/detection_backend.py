"""
DetectionBackend - Pluggable detection classifier

Allows users to plug in ML-based detection alongside the built-in regex guards.
Default: regex-only (zero dependencies, <5ms).
Optional: any async classifier (embedding similarity, external API, custom ML).

Why this exists: Research shows regex-only detection is bypassed at >90% ASR
by adaptive attacks (JBFuzz 99%, AutoDAN 88%, PAIR adaptive). This interface
lets users add ML-based detection without forcing dependencies on all users.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Literal, Optional

from .guards.encoding_detector import EncodingDetector
from .guards.input_sanitizer import InputSanitizer


@dataclass
class DetectionContext:
    """Context about what is being classified."""

    type: Literal[
        "user_input", "tool_result", "llm_output", "system_context", "rag_document"
    ]
    session_id: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class DetectionThreat:
    """A single detected threat."""

    category: str  # "injection", "jailbreak", "pii", "toxicity", "exfiltration", etc.
    severity: Literal["low", "medium", "high", "critical"]
    description: str


@dataclass
class DetectionResult:
    """Result from a detection classifier."""

    safe: bool
    confidence: float  # 0-1 (1 = definitely safe, 0 = definitely unsafe)
    threats: List[DetectionThreat] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Classifier type aliases
# ---------------------------------------------------------------------------

DetectionClassifier = Callable[[str, DetectionContext], DetectionResult]
"""
Sync detection classifier callback type.

Can be used for regex/local ML classifiers that return immediately.

Example::

    def my_classifier(input_text: str, ctx: DetectionContext) -> DetectionResult:
        return DetectionResult(
            safe=not "hack" in input_text,
            confidence=0.9,
            threats=[],
        )
"""

AsyncDetectionClassifier = Callable[[str, DetectionContext], Awaitable[DetectionResult]]
"""
Async detection classifier callback type.

Can be used for ML API calls or other async classifiers.

Example::

    async def ml_classifier(input_text: str, ctx: DetectionContext) -> DetectionResult:
        # Call external ML API
        result = await some_async_api_call(input_text, ctx.type)
        return DetectionResult(
            safe=result.score < 0.5,
            confidence=result.score,
            threats=result.threats,
        )
"""


# ---------------------------------------------------------------------------
# Built-in regex classifier
# ---------------------------------------------------------------------------


def create_regex_classifier(
    *,
    threshold: float = 0.3,
) -> DetectionClassifier:
    """
    Create a built-in regex classifier that wraps InputSanitizer + EncodingDetector.

    Useful as a baseline or fallback classifier.

    Args:
        threshold: Score threshold for the InputSanitizer (default 0.3).

    Returns:
        A DetectionClassifier function.
    """
    sanitizer = InputSanitizer(threshold=threshold)
    encoder = EncodingDetector()

    def _classify(input_text: str, context: DetectionContext) -> DetectionResult:
        threats: List[DetectionThreat] = []

        # Run sanitizer
        sanitize_result = sanitizer.sanitize(input_text)
        if not sanitize_result.allowed:
            # Check if any matched pattern is a PAP pattern
            has_pap = any(m.startswith("pap_") for m in sanitize_result.matches)
            category = "persuasion" if has_pap else "injection"
            description_matches = ", ".join(sanitize_result.matches[:3])
            threats.append(
                DetectionThreat(
                    category=category,
                    severity="high",
                    description=f"Injection detected: {description_matches}",
                )
            )

        # Run encoding detector
        encoding_result = encoder.detect(input_text)
        if not encoding_result.allowed:
            description_violations = ", ".join(encoding_result.violations[:3])
            threats.append(
                DetectionThreat(
                    category="encoding_bypass",
                    severity="high",
                    description=f"Encoded threat: {description_violations}",
                )
            )

        return DetectionResult(
            safe=len(threats) == 0,
            confidence=sanitize_result.score,
            threats=threats,
        )

    return _classify


# ---------------------------------------------------------------------------
# Result merging
# ---------------------------------------------------------------------------


def merge_detection_results(
    a: DetectionResult, b: DetectionResult
) -> DetectionResult:
    """
    Merge two detection results (used when combining regex + ML backends).

    Policy: if EITHER result is unsafe, the merged result is unsafe.
    Confidence: take the lower confidence (most conservative).
    Threats: concatenate both threat lists.
    """
    return DetectionResult(
        safe=a.safe and b.safe,
        confidence=min(a.confidence, b.confidence),
        threats=a.threats + b.threats,
    )
