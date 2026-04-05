"""
PromptLeakageGuard (L15)

Prevents system prompt extraction and leakage attacks.
Detects various evasion techniques used to extract system prompts.

Threat Model:
- OWASP LLM07:2025 System Prompt Leakage
- PLeak algorithmic extraction attacks
- Remember-the-Start attacks
- Evasion techniques (Leetspeak, ROT13, Base64, Morse)

Protection Capabilities:
- Direct extraction attempt detection
- Encoded extraction detection (Leetspeak, ROT13, Morse, etc.)
- Indirect extraction pattern detection
- Output monitoring for prompt leakage
- Prefix completion attack detection
"""

from __future__ import annotations

import base64
import re
import time
import unicodedata
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PromptLeakageAnalysis:
    direct_extraction_attempt: bool
    encoded_extraction_attempt: bool
    indirect_extraction_attempt: bool
    evasion_techniques_detected: List[str]
    risk_score: int
    decoded_content: Optional[str] = None


@dataclass
class PromptLeakageResult:
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    analysis: PromptLeakageAnalysis
    recommendations: List[str]


@dataclass
class OutputLeakageAnalysis:
    keywords_found: List[str]
    similarity_score: float
    potential_leakage_fragments: List[str]


@dataclass
class OutputLeakageResult:
    leaked: bool
    reason: str
    violations: List[str]
    request_id: str
    analysis: OutputLeakageAnalysis
    sanitized_output: Optional[str] = None


@dataclass
class PromptLeakageGuardConfig:
    detect_leetspeak: bool = True
    detect_rot13: bool = True
    detect_base64: bool = True
    detect_morse: bool = True
    detect_unicode: bool = True
    detect_indirect_extraction: bool = True
    monitor_output: bool = True
    system_prompt_hash: str = ""
    system_prompt_keywords: List[str] = field(default_factory=list)
    similarity_threshold: float = 0.7
    risk_threshold: int = 25
    custom_patterns: List[re.Pattern[str]] = field(default_factory=list)


@dataclass
class _WeightedPattern:
    name: str
    pattern: re.Pattern[str]
    weight: int


# fmt: off
_DIRECT_EXTRACTION_PATTERNS: List[_WeightedPattern] = [
    # Direct system prompt requests
    _WeightedPattern("system_prompt_request", re.compile(r"what\s+(is|are)\s+your\s+(system|initial)\s+(prompt|instructions?)", re.I), 40),
    _WeightedPattern("reveal_prompt", re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt", re.I), 45),
    _WeightedPattern("show_instructions", re.compile(r"show\s+(me\s+)?(your\s+)?instructions", re.I), 40),
    _WeightedPattern("display_rules", re.compile(r"display\s+(your\s+)?(system\s+)?rules", re.I), 40),
    _WeightedPattern("print_prompt", re.compile(r"print\s+(your\s+)?(system\s+)?(prompt|instructions|config)", re.I), 45),
    _WeightedPattern("print_configuration", re.compile(r"print\s+(your\s+)?(initial\s+)?configuration", re.I), 45),

    # PLeak-style attacks
    _WeightedPattern("repeat_after_me", re.compile(r"repeat\s+after\s+me|repeat[:\s]+\"?'?(?:my|your|the)\s+(?:instructions|rules|prompt)", re.I), 50),
    _WeightedPattern("repeat_above", re.compile(r"repeat\s+(the\s+)?(text|content|message)\s+(above|before)", re.I), 50),
    _WeightedPattern("output_previous", re.compile(r"output\s+(all\s+)?(previous|prior)\s+(text|content|instructions)", re.I), 50),
    _WeightedPattern("echo_everything", re.compile(r"echo\s+(everything|all)(\s+(above|before|prior|that|said))?", re.I), 50),
    _WeightedPattern("echo_said", re.compile(r"echo\s+.*(said|was|before|that)", re.I), 45),

    # Remember-the-Start attacks
    _WeightedPattern("complete_sentence", re.compile(r"complete\s+(this\s+|the\s+)?sentence", re.I), 50),
    _WeightedPattern("complete_you_are", re.compile(r"complete[:\s]+\"?'?you\s+are", re.I), 55),
    _WeightedPattern("continue_from", re.compile(r"continue\s+(from|with)[:\s]", re.I), 50),
    _WeightedPattern("continue_role", re.compile(r"continue[:\s]+\"?'?(you|your)\s+(are|role|purpose)", re.I), 55),
    _WeightedPattern("finish_phrase", re.compile(r"finish\s+(this\s+)?phrase", re.I), 50),
    _WeightedPattern("finish_you", re.compile(r"finish[:\s]+\"?'?you\s+(are|should|must|will)", re.I), 55),

    # Instruction extraction
    _WeightedPattern("list_constraints", re.compile(r"list\s+(all\s+)?(your\s+)?constraints", re.I), 35),
    _WeightedPattern("what_told", re.compile(r"what\s+(were\s+you|are\s+you)\s+told\s+to\s+do", re.I), 40),
    _WeightedPattern("original_purpose", re.compile(r"what\s+(is|was)\s+your\s+original\s+purpose", re.I), 35),
    _WeightedPattern("instructions_followed", re.compile(r"(?:summarize|describe|list|tell\s+me)\s+(?:the\s+)?instructions\s+you\s+(?:just\s+)?(?:followed|received|were\s+given)", re.I), 40),
    _WeightedPattern("how_you_work", re.compile(r"(?:manual|document|guide|explanation)\s+(?:on|about|of)\s+how\s+you\s+work", re.I), 35),
    _WeightedPattern("constraints_given", re.compile(r"what\s+(?:constraints|rules|guidelines|restrictions)\s+(?:were\s+you|are\s+you)\s+given", re.I), 40),
    _WeightedPattern("extract_system_prompt", re.compile(r"(?:extract|obtain|get|retrieve|access)\s+(?:a\s+|the\s+)?(?:system\s+)?prompt", re.I), 45),
    _WeightedPattern("trained_to_do", re.compile(r"what\s+(?:were|are)\s+you\s+trained\s+to\s+(?:do|say|follow|obey)", re.I), 40),
    _WeightedPattern("trained_instructions", re.compile(r"(?:when\s+(?:you\s+were\s+)?trained|during\s+training).*(?:instructions|rules|constraints|told|do)", re.I), 35),
    _WeightedPattern("reveal_instructions", re.compile(r"reveal\s+(?:your\s+)?(?:\w+\s+)?instructions", re.I), 45),
    _WeightedPattern("demonstrate_instructions", re.compile(r"demonstrate\s+(?:your\s+)?(?:\w+\s+)?(?:instructions|prompt|rules|guidelines)", re.I), 40),
    _WeightedPattern("how_work_internally", re.compile(r"how\s+(?:do\s+)?you\s+work\s+(?:internally|under\s+the\s+hood|behind\s+the\s+scenes)", re.I), 35),

    # Debug/Developer mode extraction
    _WeightedPattern("debug_mode", re.compile(r"enter\s+(debug|developer|admin)\s+mode", re.I), 45),
    _WeightedPattern("activate_developer", re.compile(r"activate\s+(developer|debug|admin)\s+mode", re.I), 45),
    _WeightedPattern("developer_mode", re.compile(r"developer\s+mode", re.I), 40),
    _WeightedPattern("show_config", re.compile(r"show\s+(your\s+)?(config|configuration|settings)", re.I), 40),
    _WeightedPattern("dump_state", re.compile(r"dump\s+(your\s+)?(internal\s+)?state", re.I), 45),

    # Context window manipulation
    _WeightedPattern("first_message", re.compile(r"what\s+was\s+(the\s+)?first\s+message", re.I), 45),
    _WeightedPattern("beginning_context", re.compile(r"what('s|\s+is)\s+at\s+the\s+beginning\s+of\s+(your\s+)?context", re.I), 50),
    _WeightedPattern("beginning_conversation", re.compile(r"(?:what|tell\s+me)\s+.*(?:beginning|start)\s+of\s+(?:this\s+)?conversation", re.I), 45),
    _WeightedPattern("what_told_beginning", re.compile(r"what\s+did\s+I\s+tell\s+you\s+at\s+the\s+beginning", re.I), 50),
    _WeightedPattern("context_start", re.compile(r"show\s+(me\s+)?the\s+start\s+of\s+(your\s+)?context", re.I), 50),
]

_INDIRECT_EXTRACTION_PATTERNS: List[_WeightedPattern] = [
    # Summarization tricks
    _WeightedPattern("summarize_guidelines", re.compile(r"summarize\s+(your\s+)?(guidelines|rules|constraints)", re.I), 35),
    _WeightedPattern("describe_limitations", re.compile(r"describe\s+(your\s+)?limitations", re.I), 30),

    # Role clarification exploits
    _WeightedPattern("explain_role", re.compile(r"explain\s+(in\s+detail\s+)?(your\s+)?role", re.I), 35),
    _WeightedPattern("explain_role_purpose", re.compile(r"explain\s+.*(role|purpose)", re.I), 35),
    _WeightedPattern("what_cant_do", re.compile(r"what\s+(can't|cannot)\s+you\s+do", re.I), 25),
    _WeightedPattern("describe_yourself", re.compile(r"describe\s+(yourself|your\s+purpose)", re.I), 30),
    _WeightedPattern("summarize_yourself", re.compile(r"summarize\s+(everything|all)\s+(you\s+know|about\s+yourself)", re.I), 35),
    _WeightedPattern("know_about_yourself", re.compile(r"(?:what|everything)\s+(?:do\s+)?you\s+know\s+about\s+yourself", re.I), 35),

    # Hypothetical extraction
    _WeightedPattern("if_asked", re.compile(r"if\s+i\s+asked\s+for\s+your\s+prompt", re.I), 40),
    _WeightedPattern("hypothetically", re.compile(r"hypothetically[,\s]+(what|how)\s+would\s+your\s+instructions", re.I), 40),

    # Academic/research framing
    _WeightedPattern("academic_extraction", re.compile(r"(?:for\s+)?(?:academic|research|educational|study)\s+(?:purposes?|reasons?).*(?:system\s+prompt|instructions|jailbreak|extract|demonstrate)", re.I), 40),
    _WeightedPattern("demonstrate_extraction", re.compile(r"demonstrate\s+(?:how\s+)?(?:to\s+)?(?:an?\s+)?(?:AI|system|model)\s+(?:could\s+be\s+)?(?:manipulated|jailbroken|exploited|tricked)", re.I), 40),

    # Output-as-input tricks
    _WeightedPattern("write_prompt", re.compile(r"write\s+a\s+(system\s+)?prompt\s+similar\s+to\s+yours", re.I), 45),
    _WeightedPattern("recreate_instructions", re.compile(r"recreate\s+(your\s+)?instructions", re.I), 45),
]
# fmt: on

# Leetspeak character mappings
_LEETSPEAK_MAP: Dict[str, str] = {
    "4": "a", "@": "a", "8": "b", "(": "c", "3": "e",
    "6": "g", "#": "h", "1": "i", "!": "i", "|": "l",
    "7": "t", "0": "o", "5": "s", "$": "s",
    "+": "t", "2": "z", "9": "g",
}

# Common Morse code words related to prompts
_MORSE_KEYWORDS = [
    "... -.-- ... - . --",        # SYSTEM
    ".--. .-. --- -- .--. -",     # PROMPT
    ".. -. ... - .-. ..- -.-. - .. --- -. ...",  # INSTRUCTIONS
]


def _build_rot13_map() -> Dict[str, str]:
    m: Dict[str, str] = {}
    for i in range(26):
        lower = chr(97 + i)
        upper = chr(65 + i)
        m[lower] = chr(97 + ((i + 13) % 26))
        m[upper] = chr(65 + ((i + 13) % 26))
    return m


_ROT13_MAP = _build_rot13_map()


class PromptLeakageGuard:
    """Prevents system prompt extraction and leakage attacks."""

    def __init__(self, config: Optional[PromptLeakageGuardConfig] = None) -> None:
        self._config = config or PromptLeakageGuardConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, input_text: str, request_id: Optional[str] = None) -> PromptLeakageResult:
        """Check input for prompt extraction attempts."""
        req_id = request_id or f"pl-{int(time.time() * 1000)}"
        violations: List[str] = []
        evasion_techniques: List[str] = []
        risk_score = 0
        direct_attempt = False
        encoded_attempt = False
        indirect_attempt = False
        decoded_content: Optional[str] = None

        # Direct extraction patterns
        for wp in _DIRECT_EXTRACTION_PATTERNS:
            if wp.pattern.search(input_text):
                violations.append(f"direct_extraction: {wp.name}")
                risk_score += wp.weight
                direct_attempt = True

        # Indirect extraction patterns
        if self._config.detect_indirect_extraction:
            for wp in _INDIRECT_EXTRACTION_PATTERNS:
                if wp.pattern.search(input_text):
                    violations.append(f"indirect_extraction: {wp.name}")
                    risk_score += wp.weight
                    indirect_attempt = True

        # Leetspeak evasion
        if self._config.detect_leetspeak:
            decoded = self._decode_leetspeak(input_text)
            if decoded != input_text.lower():
                leet_check = self._check_decoded_content(decoded, "leetspeak")
                if leet_check["detected"]:
                    violations.extend(leet_check["violations"])
                    risk_score += leet_check["risk_contribution"]
                    evasion_techniques.append("leetspeak")
                    encoded_attempt = True
                    decoded_content = decoded
                else:
                    kw_check = self._check_keywords_in_decoded(decoded)
                    if kw_check["detected"]:
                        violations.append(f"leetspeak_keyword: {', '.join(kw_check['keywords'])}")
                        risk_score += 35
                        evasion_techniques.append("leetspeak")
                        encoded_attempt = True
                        decoded_content = decoded

        # ROT13 evasion
        if self._config.detect_rot13:
            decoded = self._decode_rot13(input_text)
            rot13_check = self._check_decoded_content(decoded, "rot13")
            if rot13_check["detected"]:
                violations.extend(rot13_check["violations"])
                risk_score += rot13_check["risk_contribution"]
                evasion_techniques.append("rot13")
                encoded_attempt = True
                decoded_content = decoded
            else:
                kw_check = self._check_keywords_in_decoded(decoded)
                if kw_check["detected"]:
                    violations.append(f"rot13_keyword: {', '.join(kw_check['keywords'])}")
                    risk_score += 40
                    evasion_techniques.append("rot13")
                    encoded_attempt = True
                    decoded_content = decoded

        # Base64 evasion
        if self._config.detect_base64:
            b64_matches = re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", input_text)
            for match in b64_matches:
                try:
                    decoded_bytes = base64.b64decode(match)
                    decoded = decoded_bytes.decode("utf-8", errors="strict")
                    if decoded and re.search(r"[\x20-\x7E]{4,}", decoded):
                        b64_check = self._check_decoded_content(decoded, "base64")
                        if b64_check["detected"]:
                            violations.extend(b64_check["violations"])
                            risk_score += b64_check["risk_contribution"]
                            evasion_techniques.append("base64")
                            encoded_attempt = True
                            decoded_content = decoded
                        else:
                            kw_check = self._check_keywords_in_decoded(decoded)
                            if kw_check["detected"]:
                                violations.append(f"base64_keyword: {', '.join(kw_check['keywords'])}")
                                risk_score += 45
                                evasion_techniques.append("base64")
                                encoded_attempt = True
                                decoded_content = decoded
                except Exception:
                    pass

        # Unicode evasion
        if self._config.detect_unicode:
            unicode_check = self._check_unicode_evasion(input_text)
            if unicode_check["detected"]:
                violations.extend(unicode_check["violations"])
                risk_score += unicode_check["risk_contribution"]
                evasion_techniques.append("unicode")
                encoded_attempt = True

        # Morse code
        if self._config.detect_morse:
            morse_check = self._check_morse_code(input_text)
            if morse_check["detected"]:
                violations.extend(morse_check["violations"])
                risk_score += morse_check["risk_contribution"]
                evasion_techniques.append("morse")
                encoded_attempt = True

        # Custom patterns
        for i, pattern in enumerate(self._config.custom_patterns):
            if pattern.search(input_text):
                violations.append(f"custom_pattern_{i}")
                risk_score += 30

        risk_score = min(100, risk_score)
        blocked = risk_score >= self._config.risk_threshold

        return PromptLeakageResult(
            allowed=not blocked,
            reason=f"Prompt extraction attempt detected (risk: {risk_score})" if blocked else "Input validated",
            violations=violations,
            request_id=req_id,
            analysis=PromptLeakageAnalysis(
                direct_extraction_attempt=direct_attempt,
                encoded_extraction_attempt=encoded_attempt,
                indirect_extraction_attempt=indirect_attempt,
                evasion_techniques_detected=evasion_techniques,
                risk_score=risk_score,
                decoded_content=decoded_content,
            ),
            recommendations=self._generate_recommendations(violations, evasion_techniques),
        )

    def check_output(self, output: str, request_id: Optional[str] = None) -> OutputLeakageResult:
        """Monitor output for potential prompt leakage."""
        req_id = request_id or f"pl-out-{int(time.time() * 1000)}"

        if not self._config.monitor_output:
            return OutputLeakageResult(
                leaked=False,
                reason="Output monitoring disabled",
                violations=[],
                request_id=req_id,
                analysis=OutputLeakageAnalysis(
                    keywords_found=[], similarity_score=0.0, potential_leakage_fragments=[],
                ),
            )

        violations: List[str] = []
        keywords_found: List[str] = []
        potential_fragments: List[str] = []

        # Check system prompt keywords in output
        for keyword in self._config.system_prompt_keywords:
            if keyword.lower() in output.lower():
                keywords_found.append(keyword)
                violations.append(f"keyword_leaked: {keyword}")

        # Check for common prompt fragment patterns
        prompt_fragment_patterns = [
            re.compile(r"you\s+are\s+an?\s+(helpful\s+)?assistant", re.I),
            re.compile(r"your\s+(role|purpose|goal)\s+is\s+to", re.I),
            re.compile(r"you\s+(must|should|will)\s+(always|never)", re.I),
            re.compile(r"do\s+not\s+(reveal|disclose|share)\s+(your|the)\s+(system|initial)", re.I),
            re.compile(r"\[system\]|\[instruction\]|<<sys>>|<\|system\|>", re.I),
            re.compile(r"as\s+an?\s+AI\s+(assistant|model|language\s+model)", re.I),
        ]

        for pattern in prompt_fragment_patterns:
            m = pattern.search(output)
            if m:
                potential_fragments.append(m.group(0))
                violations.append("prompt_fragment_detected")

        # Rough similarity heuristic
        similarity_score = min(1.0, len(potential_fragments) / 10.0)
        leaked = len(keywords_found) > 0 or len(potential_fragments) >= 2

        return OutputLeakageResult(
            leaked=leaked,
            reason=(
                f"Potential prompt leakage detected: {', '.join(violations[:3])}"
                if leaked else "Output appears safe"
            ),
            violations=violations,
            request_id=req_id,
            analysis=OutputLeakageAnalysis(
                keywords_found=keywords_found,
                similarity_score=similarity_score,
                potential_leakage_fragments=potential_fragments,
            ),
            sanitized_output=self._sanitize_output(output) if leaked else None,
        )

    def set_system_prompt_keywords(self, keywords: List[str]) -> None:
        """Set system prompt keywords for output monitoring."""
        self._config.system_prompt_keywords = keywords

    def add_pattern(self, pattern: re.Pattern[str]) -> None:
        """Add custom extraction pattern."""
        self._config.custom_patterns.append(pattern)

    def set_risk_threshold(self, threshold: int) -> None:
        """Update risk threshold."""
        self._config.risk_threshold = max(0, min(100, threshold))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _decode_leetspeak(input_text: str) -> str:
        result = input_text.lower()
        for leet, char in _LEETSPEAK_MAP.items():
            result = result.replace(leet, char)
        return result

    @staticmethod
    def _decode_rot13(input_text: str) -> str:
        return "".join(_ROT13_MAP.get(c, c) for c in input_text)

    def _check_decoded_content(
        self, decoded: str, technique: str
    ) -> Dict[str, Any]:
        violations: List[str] = []
        risk_contribution = 0

        for wp in _DIRECT_EXTRACTION_PATTERNS:
            if wp.pattern.search(decoded):
                violations.append(f"{technique}_evasion: {wp.name}")
                risk_contribution += wp.weight + 10

        return {
            "detected": len(violations) > 0,
            "violations": violations,
            "risk_contribution": risk_contribution,
        }

    def _check_unicode_evasion(self, input_text: str) -> Dict[str, Any]:
        violations: List[str] = []
        risk_contribution = 0

        # Invisible characters
        invisible = re.findall(r"[\u200B-\u200D\uFEFF\u2060-\u206F\u00AD]", input_text)
        if len(invisible) > 3:
            violations.append("invisible_unicode_chars")
            risk_contribution += 20

        # Homoglyphs (Cyrillic, Greek)
        homoglyphs = re.findall(r"[\u0400-\u04FF\u0370-\u03FF]", input_text)
        if homoglyphs:
            normalized = unicodedata.normalize("NFKD", input_text)
            normalized = re.sub(r"[\u0300-\u036f]", "", normalized)
            for wp in _DIRECT_EXTRACTION_PATTERNS:
                if wp.pattern.search(normalized):
                    violations.append("homoglyph_evasion")
                    risk_contribution += 30
                    break

        # Fullwidth characters
        fullwidth = re.findall(r"[\uFF01-\uFF5E]", input_text)
        if len(fullwidth) > 5:
            violations.append("fullwidth_chars")
            risk_contribution += 15

        return {
            "detected": len(violations) > 0,
            "violations": violations,
            "risk_contribution": risk_contribution,
        }

    @staticmethod
    def _check_morse_code(input_text: str) -> Dict[str, Any]:
        violations: List[str] = []
        risk_contribution = 0

        if re.search(r"[.\-]{2,}\s+[.\-]{2,}", input_text):
            for keyword in _MORSE_KEYWORDS:
                if keyword in input_text:
                    violations.append("morse_code_evasion")
                    risk_contribution += 35
                    break

        return {
            "detected": len(violations) > 0,
            "violations": violations,
            "risk_contribution": risk_contribution,
        }

    @staticmethod
    def _check_keywords_in_decoded(decoded: str) -> Dict[str, Any]:
        action_keywords = ["reveal", "show", "display", "print", "output", "dump", "list", "give", "tell"]
        target_keywords = [
            "prompt", "instructions", "configuration", "config", "rules",
            "guidelines", "constraints", "system", "initial", "secret", "hidden", "internal",
        ]

        found: List[str] = []
        lower = decoded.lower()
        has_action = False
        has_target = False

        for kw in action_keywords:
            if kw in lower:
                found.append(kw)
                has_action = True

        for kw in target_keywords:
            if kw in lower:
                found.append(kw)
                has_target = True

        return {"detected": has_action and has_target, "keywords": found}

    @staticmethod
    def _sanitize_output(output: str) -> str:
        sanitized = output
        fragment_patterns = [
            re.compile(r"you\s+are\s+an?\s+(helpful\s+)?assistant[^.]*\.", re.I),
            re.compile(r"your\s+(role|purpose|goal)\s+is\s+to[^.]*\.", re.I),
            re.compile(r"you\s+(must|should|will)\s+(always|never)[^.]*\.", re.I),
            re.compile(r"\[system\][^\[\]]*\[/system\]", re.I),
            re.compile(r"<<sys>>[^<]*<</sys>>", re.I),
        ]
        for pattern in fragment_patterns:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized

    @staticmethod
    def _generate_recommendations(
        violations: List[str], evasion_techniques: List[str]
    ) -> List[str]:
        recommendations: List[str] = []
        if any("direct_extraction" in v for v in violations):
            recommendations.append("Direct prompt extraction attempt blocked")
        if any("indirect_extraction" in v for v in violations):
            recommendations.append("Consider strengthening indirect extraction detection")
        if evasion_techniques:
            recommendations.append(f"Evasion techniques detected: {', '.join(evasion_techniques)}")
        if any("unicode" in v for v in violations):
            recommendations.append("Normalize input before processing")
        if not recommendations:
            recommendations.append("Input validated successfully")
        return recommendations
