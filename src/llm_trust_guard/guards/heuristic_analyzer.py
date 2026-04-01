"""
HeuristicAnalyzer

Advanced heuristic detection using three techniques from research (DMPI-PMHFE, 2026):

1. SYNONYM EXPANSION - Expand injection keywords to catch paraphrased attacks
   Instead of matching "ignore" only, match {ignore, disregard, overlook, neglect, skip, bypass, omit...}

2. STRUCTURAL PATTERN ANALYSIS - Detect instruction-like sentence structures
   Imperative commands, Q&A injection (many-shot), repeated token attacks

3. STATISTICAL FEATURES - Score inputs based on statistical properties
   Instruction word density, special character ratio, command-to-question ratio

These techniques are zero-dependency, pure string analysis - no ML required.
Research shows they add +10-15pp detection over keyword-only regex.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class HeuristicAnalyzerConfig:
    """Configuration for HeuristicAnalyzer."""
    synonym_expansion: bool = True
    structural_analysis: bool = True
    statistical_scoring: bool = True
    risk_threshold: float = 0.8
    many_shot_threshold: int = 3
    repeated_token_threshold: int = 3


@dataclass
class HeuristicFeatures:
    """Feature flags and scores from heuristic analysis."""
    # Synonym matching (8 categories)
    is_ignore: bool = False
    is_urgent: bool = False
    is_incentive: bool = False
    is_covert: bool = False
    is_format_manipulation: bool = False
    is_hypothetical: bool = False
    is_systemic: bool = False
    is_immoral: bool = False
    synonym_categories_matched: int = 0
    # Structural patterns
    is_shot_attack: bool = False
    is_repeated_token: bool = False
    is_imperative: bool = False
    is_role_assignment: bool = False
    structural_score: float = 0.0
    # Statistical features
    instruction_word_density: float = 0.0
    special_char_ratio: float = 0.0
    uppercase_ratio: float = 0.0
    average_word_length: float = 0.0
    statistical_score: float = 0.0


@dataclass
class HeuristicResult:
    """Result from heuristic analysis."""
    allowed: bool
    risk_score: float
    features: HeuristicFeatures
    violations: List[str] = field(default_factory=list)
    reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Synonym sets for 8 attack categories
# Based on DMPI-PMHFE paper (2026) + expanded with additional synonyms
# All lowercase for matching
# ---------------------------------------------------------------------------

@dataclass
class _SynonymCategory:
    keywords: Set[str]
    weight: float


SYNONYM_SETS: Dict[str, _SynonymCategory] = {
    "ignore": _SynonymCategory(
        keywords={
            "ignore", "disregard", "overlook", "neglect", "skip", "bypass", "omit",
            "dismiss", "override", "overrule", "forget", "abandon", "drop", "ditch",
            "scrap", "discard", "set aside", "pay no attention", "turn a blind eye",
            "look past", "brush off", "shrug off", "wave away", "cast aside",
            "put aside", "leave behind", "throw out", "toss out",
        },
        weight=0.3,
    ),
    "urgent": _SynonymCategory(
        keywords={
            "urgent", "immediate", "immediately", "asap", "emergency", "critical",
            "time-sensitive", "pressing", "crucial", "dire", "life-threatening",
            "now", "hurry", "rush", "quick", "fast", "right away", "without delay",
            "time is running out", "deadline",
        },
        weight=0.15,
    ),
    "incentive": _SynonymCategory(
        keywords={
            "excellent", "fantastic", "nice", "awesome", "brilliant", "great",
            "amazing", "wonderful", "superb", "outstanding", "reward", "tip",
            "bonus", "payment", "compensate", "grateful", "appreciate",
        },
        weight=0.1,
    ),
    "covert": _SynonymCategory(
        keywords={
            "secret", "hidden", "covert", "quiet", "silent", "discreetly", "stealth",
            "confidential", "private", "classified", "concealed", "disguised",
            "undercover", "off the record", "between us", "nobody will know",
            "our little secret", "hush", "whisper",
        },
        weight=0.2,
    ),
    "format_manipulation": _SynonymCategory(
        keywords={
            "encode", "decode", "disguise", "morse", "binary", "hexadecimal",
            "base64", "rot13", "cipher", "encrypt", "obfuscate", "scramble",
            "reverse", "translate to code", "convert to",
        },
        weight=0.15,
    ),
    "hypothetical": _SynonymCategory(
        keywords={
            "assume", "imagine", "hypothetically", "fictional", "scenario",
            "pretend", "suppose", "what if", "let's say", "in theory",
            "theoretically", "fantasy", "roleplay", "simulation", "make believe",
            "alternate reality", "parallel universe", "thought experiment",
        },
        weight=0.15,
    ),
    "systemic": _SynonymCategory(
        keywords={
            "developer", "administrator", "admin", "boss", "manager", "creator",
            "owner", "supervisor", "root", "superuser", "operator", "maintainer",
            "engineer", "architect", "designer", "authority", "controller",
            "master", "god mode", "sudo",
        },
        weight=0.2,
    ),
    "immoral": _SynonymCategory(
        keywords={
            "amoral", "immoral", "unethical", "illegal", "harmful", "dangerous",
            "offensive", "violent", "malicious", "evil", "wicked", "sinister",
            "criminal", "unlawful", "forbidden", "prohibited", "taboo",
            "no morals", "no ethics", "no rules", "no limits", "unrestricted",
            "uncensored", "unfiltered",
        },
        weight=0.25,
    ),
}

# Words that indicate instruction-like content (for density scoring)
INSTRUCTION_WORDS: Set[str] = {
    "must", "should", "shall", "will", "need", "require", "always", "never",
    "do", "don't", "cannot", "can't", "ensure", "make sure", "remember",
    "forget", "ignore", "follow", "obey", "comply", "execute", "perform",
    "output", "respond", "reply", "answer", "generate", "create", "write",
    "act", "behave", "pretend", "assume", "become", "transform",
}

# Pre-compiled patterns
_QA_PATTERN = re.compile(
    r"(?:Q:|Question:|Human:|User:)[\s\S]*?(?:A:|Answer:|Assistant:|AI:)",
    re.IGNORECASE,
)
_IMPERATIVE_PATTERN = re.compile(
    r"^(?:ignore|forget|disregard|override|bypass|reveal|show|tell|give|grant|"
    r"make|do|don't|never|always|you\s+(?:must|should|will|are|can))",
    re.IGNORECASE,
)
_ROLE_ASSIGNMENT_PATTERN = re.compile(
    r"you\s+(?:are|will\s+be|shall\s+be|must\s+be)\s+(?:now\s+)?(?:a|an|the|my)\s+",
    re.IGNORECASE,
)
_ROLE_BYPASS_PATTERN = re.compile(
    r"(?:no\s+(?:restrictions|rules|limits)|unrestricted|unfiltered|evil|amoral|can\s+do\s+anything)",
    re.IGNORECASE,
)
_TOKEN_CLEAN_RE = re.compile(r"[^a-z'\-]")
_WORD_CLEAN_RE = re.compile(r"[^a-z']")
_SPECIAL_CHAR_RE = re.compile(r"[a-zA-Z0-9\s]")
_UPPERCASE_RE = re.compile(r"[^A-Z]")
_LETTER_RE = re.compile(r"[^a-zA-Z]")


class HeuristicAnalyzer:
    """Advanced heuristic analyzer using synonym expansion, structural analysis,
    and statistical scoring to detect prompt injection attacks."""

    def __init__(self, config: Optional[HeuristicAnalyzerConfig] = None) -> None:
        self.config = config or HeuristicAnalyzerConfig()

    def analyze(self, input_text: str, request_id: Optional[str] = None) -> HeuristicResult:
        """Analyze input using all three heuristic techniques."""
        violations: List[str] = []
        features = HeuristicFeatures()
        total_risk = 0.0

        # Technique 1: Synonym Expansion
        if self.config.synonym_expansion:
            synonym_result = self._check_synonyms(input_text)
            # Update features from synonym result
            for key, value in synonym_result["features"].items():
                setattr(features, key, value)
            total_risk += synonym_result["risk"]
            if synonym_result["risk"] > 0:
                violations.extend(
                    f"SYNONYM_{m.upper()}" for m in synonym_result["matched"]
                )

        # Technique 2: Structural Pattern Analysis
        if self.config.structural_analysis:
            struct_result = self._check_structure(input_text)
            features.is_shot_attack = struct_result["is_shot_attack"]
            features.is_repeated_token = struct_result["is_repeated_token"]
            features.is_imperative = struct_result["is_imperative"]
            features.is_role_assignment = struct_result["is_role_assignment"]
            features.structural_score = struct_result["score"]
            total_risk += struct_result["score"]
            violations.extend(struct_result["violations"])

        # Technique 3: Statistical Feature Scoring
        if self.config.statistical_scoring:
            stat_result = self._score_statistics(input_text)
            features.instruction_word_density = stat_result["instruction_word_density"]
            features.special_char_ratio = stat_result["special_char_ratio"]
            features.uppercase_ratio = stat_result["uppercase_ratio"]
            features.average_word_length = stat_result["average_word_length"]
            features.statistical_score = stat_result["score"]
            total_risk += stat_result["score"]

        # Compound risk: multiple categories matching is more suspicious
        if features.synonym_categories_matched >= 3:
            total_risk += 0.15
            violations.append("MULTI_CATEGORY_COMPOUND")

        risk_score = min(1.0, total_risk)
        allowed = risk_score < self.config.risk_threshold

        return HeuristicResult(
            allowed=allowed,
            reason=(
                None if allowed
                else f"Heuristic analysis risk {risk_score:.2f} exceeds threshold {self.config.risk_threshold}"
            ),
            risk_score=risk_score,
            features=features,
            violations=violations,
        )

    # ------------------------------------------------------------------
    # Technique 1: Synonym Expansion
    # ------------------------------------------------------------------

    def _check_synonyms(self, input_text: str) -> dict:
        """Check if input tokens match expanded synonym sets for 8 attack categories."""
        # Tokenize and normalize
        tokens = [
            _TOKEN_CLEAN_RE.sub("", t)
            for t in input_text.lower().split()
        ]
        tokens = [t for t in tokens if len(t) > 2]
        input_lower = input_text.lower()

        features: dict = {}
        risk = 0.0
        matched: List[str] = []
        categories_matched = 0

        for category, syn_cat in SYNONYM_SETS.items():
            found = False

            # Check individual tokens
            for token in tokens:
                if token in syn_cat.keywords:
                    found = True
                    break

            # Check multi-word phrases
            if not found:
                for keyword in syn_cat.keywords:
                    if " " in keyword and keyword in input_lower:
                        found = True
                        break

            if found:
                features[f"is_{category}"] = True
                risk += syn_cat.weight
                matched.append(category)
                categories_matched += 1
            else:
                features[f"is_{category}"] = False

        features["synonym_categories_matched"] = categories_matched
        return {"features": features, "risk": risk, "matched": matched}

    # ------------------------------------------------------------------
    # Technique 2: Structural Pattern Analysis
    # ------------------------------------------------------------------

    def _check_structure(self, input_text: str) -> dict:
        """Detect instruction-like sentence structures."""
        violations: List[str] = []
        score = 0.0

        # Many-shot detection: count Q&A-like pairs
        qa_matches = _QA_PATTERN.findall(input_text)
        is_shot_attack = len(qa_matches) >= self.config.many_shot_threshold
        if is_shot_attack:
            score += 0.3
            violations.append("MANY_SHOT_PATTERN")

        # Repeated token detection
        words = [w for w in input_text.lower().split() if len(w) > 3]
        word_counts: Dict[str, int] = {}
        for w in words:
            word_counts[w] = word_counts.get(w, 0) + 1
        max_repeat = max(word_counts.values()) if word_counts else 0
        is_repeated_token = (
            max_repeat >= self.config.repeated_token_threshold
            and len(words) > 10
            and (max_repeat / len(words)) > 0.15
        )
        if is_repeated_token:
            score += 0.1
            violations.append("REPEATED_TOKEN_ATTACK")

        # Imperative sentence detection (commands)
        sentences = [s.strip() for s in re.split(r"[.!?\n]+", input_text) if len(s.strip()) > 5]
        imperative_count = 0
        for sentence in sentences:
            if _IMPERATIVE_PATTERN.search(sentence):
                imperative_count += 1
        is_imperative = len(sentences) > 0 and (imperative_count / len(sentences)) > 0.4
        if is_imperative:
            score += 0.15
            violations.append("HIGH_IMPERATIVE_RATIO")

        # Role assignment structure: "You are [now] a/an [ROLE]" + bypass keywords
        is_role_assignment = (
            bool(_ROLE_ASSIGNMENT_PATTERN.search(input_text))
            and bool(_ROLE_BYPASS_PATTERN.search(input_text))
        )
        if is_role_assignment:
            score += 0.25
            violations.append("ROLE_ASSIGNMENT_WITH_BYPASS")

        return {
            "is_shot_attack": is_shot_attack,
            "is_repeated_token": is_repeated_token,
            "is_imperative": is_imperative,
            "is_role_assignment": is_role_assignment,
            "score": score,
            "violations": violations,
        }

    # ------------------------------------------------------------------
    # Technique 3: Statistical Feature Scoring
    # ------------------------------------------------------------------

    def _score_statistics(self, input_text: str) -> dict:
        """Score based on statistical properties of the input."""
        words = [w for w in input_text.split() if len(w) > 0]
        if not words:
            return {
                "instruction_word_density": 0.0,
                "special_char_ratio": 0.0,
                "uppercase_ratio": 0.0,
                "average_word_length": 0.0,
                "score": 0.0,
            }

        # Instruction word density
        instruction_count = 0
        for word in words:
            cleaned = _WORD_CLEAN_RE.sub("", word.lower())
            if cleaned in INSTRUCTION_WORDS:
                instruction_count += 1
        instruction_word_density = instruction_count / len(words)

        # Special character ratio (high ratio = potential encoding/obfuscation)
        special_chars = len(_SPECIAL_CHAR_RE.sub("", input_text))
        special_char_ratio = special_chars / len(input_text) if input_text else 0.0

        # Uppercase ratio (high ratio = shouting/emphasis, common in jailbreaks)
        uppercase_chars = len(_UPPERCASE_RE.sub("", input_text))
        letter_chars = len(_LETTER_RE.sub("", input_text))
        uppercase_ratio = uppercase_chars / letter_chars if letter_chars > 0 else 0.0

        # Average word length
        total_word_length = sum(len(w) for w in words)
        average_word_length = total_word_length / len(words)

        # Score based on statistical anomalies
        score = 0.0

        # High instruction density is suspicious
        if instruction_word_density > 0.15:
            score += 0.1
        if instruction_word_density > 0.25:
            score += 0.1

        # Very high uppercase ratio (>40% caps) is suspicious
        if uppercase_ratio > 0.4 and letter_chars > 20:
            score += 0.05

        return {
            "instruction_word_density": instruction_word_density,
            "special_char_ratio": special_char_ratio,
            "uppercase_ratio": uppercase_ratio,
            "average_word_length": average_word_length,
            "score": score,
        }
