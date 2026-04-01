"""
ConversationGuard

Detects and prevents multi-turn manipulation attacks by:
- Tracking conversation history patterns
- Detecting gradual privilege escalation attempts
- Identifying context manipulation across turns
- Blocking suspicious conversation trajectories

Port of the TypeScript ConversationGuard.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable

LoggerFn = Optional[Callable[[str, str], None]]


@dataclass
class ManipulationPattern:
    name: str
    pattern: re.Pattern
    weight: int
    category: str  # "escalation" | "confusion" | "override" | "extraction"


@dataclass
class RiskFactor:
    factor: str
    weight: int
    details: str


@dataclass
class ConversationAnalysis:
    turn_count: int
    escalation_attempts: int
    manipulation_indicators: int
    suspicious_patterns: List[str]


@dataclass
class ConversationGuardResult:
    allowed: bool
    violations: List[str]
    risk_score: int
    risk_factors: List[RiskFactor]
    conversation_analysis: ConversationAnalysis
    reason: Optional[str] = None


@dataclass
class ConversationGuardConfig:
    max_conversation_length: int = 50
    conversation_ttl_minutes: int = 30
    escalation_threshold: int = 10
    manipulation_patterns: Optional[List[ManipulationPattern]] = None
    detect_tone_shifts: bool = True
    detect_role_confusion: bool = True
    detect_instruction_override: bool = True
    logger: LoggerFn = None


@dataclass
class _ConversationTurn:
    timestamp: float
    role: str  # "user" | "assistant"
    content: str
    tool_calls: Optional[List[str]] = None
    risk_indicators: Optional[List[str]] = field(default_factory=list)


@dataclass
class _ConversationSession:
    id: str
    turns: List[_ConversationTurn] = field(default_factory=list)
    escalation_attempts: int = 0
    manipulation_indicators: int = 0
    last_activity: float = 0.0
    initial_role: Optional[str] = None
    claimed_roles: List[str] = field(default_factory=list)


# fmt: off
DEFAULT_MANIPULATION_PATTERNS: List[ManipulationPattern] = [
    # Escalation patterns
    ManipulationPattern("role_claim", re.compile(r"(?:i am|i'm|as|acting as)\s+(?:an?\s+)?(?:admin|administrator|root|superuser|manager|supervisor)", re.I), 3, "escalation"),
    ManipulationPattern("permission_request", re.compile(r"(?:give me|grant me|i need|enable|unlock)\s+(?:access|permission|privileges|admin|root)", re.I), 4, "escalation"),
    ManipulationPattern("bypass_attempt", re.compile(r"(?:bypass|skip|ignore|override|disable)\s+(?:security|check|validation|permission|auth)", re.I), 5, "escalation"),
    # Confusion patterns
    ManipulationPattern("context_switch", re.compile(r"(?:forget|ignore|disregard)\s+(?:previous|earlier|what i said|instructions)", re.I), 4, "confusion"),
    ManipulationPattern("role_confusion", re.compile(r"(?:you are now|pretend to be|act as if|imagine you're)\s+", re.I), 4, "confusion"),
    ManipulationPattern("scenario_framing", re.compile(r"(?:in this scenario|hypothetically|let's say|imagine that|pretend that)", re.I), 2, "confusion"),
    # Override patterns
    ManipulationPattern("instruction_override", re.compile(r"(?:new instructions?|override|update your|change your)\s+(?:are|is|:)", re.I), 5, "override"),
    ManipulationPattern("system_impersonation", re.compile(r"(?:\[system\]|\[admin\]|system:|\bSYSTEM\b|ADMIN:)", re.I), 5, "override"),
    ManipulationPattern("priority_claim", re.compile(r"(?:priority|urgent|important|critical)[:.]?\s*(?:override|ignore|bypass)", re.I), 4, "override"),
    # Extraction patterns
    ManipulationPattern("data_extraction", re.compile(r"(?:list all|show me all|dump|export|extract)\s+(?:users|data|records|passwords|credentials)", re.I), 4, "extraction"),
    ManipulationPattern("internal_query", re.compile(r"(?:what are your|tell me your|reveal your)\s+(?:instructions|rules|prompts|system)", re.I), 3, "extraction"),
]
# fmt: on


class ConversationGuard:
    """Detects and prevents multi-turn manipulation attacks."""

    def __init__(self, config: Optional[ConversationGuardConfig] = None) -> None:
        cfg = config or ConversationGuardConfig()
        self._max_conversation_length = cfg.max_conversation_length
        self._conversation_ttl_minutes = cfg.conversation_ttl_minutes
        self._escalation_threshold = cfg.escalation_threshold
        self._manipulation_patterns = cfg.manipulation_patterns or DEFAULT_MANIPULATION_PATTERNS
        self._detect_tone_shifts = cfg.detect_tone_shifts
        self._detect_role_confusion = cfg.detect_role_confusion
        self._detect_instruction_override = cfg.detect_instruction_override
        self._logger: Callable[[str, str], None] = cfg.logger or (lambda msg, level: None)
        self._sessions: Dict[str, _ConversationSession] = {}
        self._last_cleanup: float = 0.0

    def check(
        self,
        session_id: str,
        user_message: str,
        tool_calls: Optional[List[str]] = None,
        claimed_role: Optional[str] = None,
        request_id: str = "",
    ) -> ConversationGuardResult:
        """Analyze a new user message in context of the conversation."""
        violations: List[str] = []
        risk_factors: List[RiskFactor] = []
        suspicious_patterns: List[str] = []
        risk_score = 0

        session = self._get_or_create_session(session_id)

        turn = _ConversationTurn(
            timestamp=time.time(),
            role="user",
            content=user_message,
            tool_calls=tool_calls,
            risk_indicators=[],
        )

        # Check for manipulation patterns
        for pat in self._manipulation_patterns:
            if pat.pattern.search(user_message):
                risk_score += pat.weight
                risk_factors.append(RiskFactor(
                    factor=pat.name,
                    weight=pat.weight,
                    details=f"Detected {pat.category} pattern: {pat.name}",
                ))
                if turn.risk_indicators is not None:
                    turn.risk_indicators.append(pat.name)
                suspicious_patterns.append(pat.name)
                violations.append(f"MANIPULATION_{pat.category.upper()}_{pat.name.upper()}")

                if pat.category == "escalation":
                    session.escalation_attempts += 1
                session.manipulation_indicators += 1

        # Check for role confusion across turns
        if claimed_role and self._detect_role_confusion:
            if session.initial_role and claimed_role != session.initial_role:
                risk_score += 3
                risk_factors.append(RiskFactor(
                    factor="role_change",
                    weight=3,
                    details=f"Role changed from {session.initial_role} to {claimed_role}",
                ))
                violations.append("ROLE_CHANGE_DETECTED")
            if claimed_role not in session.claimed_roles:
                session.claimed_roles.append(claimed_role)
            if not session.initial_role:
                session.initial_role = claimed_role

        # Check for progressive escalation
        if session.escalation_attempts >= 3:
            risk_score += 5
            risk_factors.append(RiskFactor(
                factor="progressive_escalation",
                weight=5,
                details=f"{session.escalation_attempts} escalation attempts detected",
            ))
            violations.append("PROGRESSIVE_ESCALATION")

        # Check conversation trajectory
        if len(session.turns) > 5:
            recent_manipulation = sum(
                1 for t in session.turns[-5:]
                if t.risk_indicators and len(t.risk_indicators) > 0
            )
            if recent_manipulation >= 3:
                risk_score += 4
                risk_factors.append(RiskFactor(
                    factor="sustained_manipulation",
                    weight=4,
                    details=f"{recent_manipulation} of last 5 turns show manipulation attempts",
                ))
                violations.append("SUSTAINED_MANIPULATION")

        # Check for sensitive tool sequences
        if tool_calls and len(tool_calls) > 0:
            sensitive_tools = ["delete", "modify", "admin", "system", "config"]
            has_sensitive_tool = any(
                any(s in t.lower() for s in sensitive_tools)
                for t in tool_calls
            )
            if has_sensitive_tool and session.manipulation_indicators > 0:
                risk_score += 3
                risk_factors.append(RiskFactor(
                    factor="sensitive_tool_after_manipulation",
                    weight=3,
                    details="Sensitive tool call following manipulation attempts",
                ))
                violations.append("SENSITIVE_TOOL_AFTER_MANIPULATION")

        # Add turn to session
        session.turns.append(turn)
        session.last_activity = time.time()

        # Trim session if too long
        if len(session.turns) > self._max_conversation_length:
            session.turns = session.turns[-self._max_conversation_length:]

        # Determine if blocked
        allowed = risk_score < self._escalation_threshold

        if not allowed:
            self._logger(
                f"[ConversationGuard:{request_id}] BLOCKED: Risk score {risk_score} exceeds threshold",
                "info",
            )

        return ConversationGuardResult(
            allowed=allowed,
            reason=None if allowed else f"Conversation risk score {risk_score} exceeds threshold {self._escalation_threshold}",
            violations=violations,
            risk_score=risk_score,
            risk_factors=risk_factors,
            conversation_analysis=ConversationAnalysis(
                turn_count=len(session.turns),
                escalation_attempts=session.escalation_attempts,
                manipulation_indicators=session.manipulation_indicators,
                suspicious_patterns=suspicious_patterns,
            ),
        )

    def record_response(
        self,
        session_id: str,
        response: str,
        tool_calls: Optional[List[str]] = None,
    ) -> None:
        """Record assistant response for complete conversation tracking."""
        session = self._sessions.get(session_id)
        if session is not None:
            session.turns.append(_ConversationTurn(
                timestamp=time.time(),
                role="assistant",
                content=response,
                tool_calls=tool_calls,
            ))
            session.last_activity = time.time()

    def get_session_analysis(self, session_id: str) -> Optional[Dict]:
        """Get session analysis."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        first_ts = session.turns[0].timestamp if session.turns else time.time()
        return {
            "turn_count": len(session.turns),
            "escalation_attempts": session.escalation_attempts,
            "manipulation_indicators": session.manipulation_indicators,
            "claimed_roles": list(session.claimed_roles),
            "session_age_minutes": (time.time() - first_ts) / 60.0,
        }

    def reset_session(self, session_id: str) -> None:
        """Reset a session."""
        self._sessions.pop(session_id, None)

    def destroy(self) -> None:
        """Destroy guard and release resources."""
        self._sessions.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> _ConversationSession:
        self._lazy_cleanup()
        if session_id not in self._sessions:
            self._sessions[session_id] = _ConversationSession(
                id=session_id,
                last_activity=time.time(),
            )
        return self._sessions[session_id]

    def _lazy_cleanup(self) -> None:
        now = time.time()
        if now - self._last_cleanup < 60:
            return
        self._last_cleanup = now
        ttl_s = self._conversation_ttl_minutes * 60
        expired = [
            sid for sid, s in self._sessions.items()
            if now - s.last_activity > ttl_s
        ]
        for sid in expired:
            del self._sessions[sid]
