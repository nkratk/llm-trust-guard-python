"""
ContextBudgetGuard

Tracks aggregate token usage across all context sources per session.
Prevents context window stuffing and many-shot jailbreaking attacks.

Why this exists: Anthropic's research shows 256 faux dialogues in a single
prompt override safety training. Individual guards have per-source limits,
but nothing tracks the AGGREGATE context size. An attacker can fill the
context window to push out system prompts.

Port of the TypeScript ContextBudgetGuard.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable

LoggerFn = Optional[Callable[[str, str], None]]


def _default_token_estimator(text: str) -> int:
    return math.ceil(len(text) / 3.5)


@dataclass
class BudgetInfo:
    used_tokens: int
    remaining_tokens: int
    system_reserve: int
    sources: Dict[str, int]
    turn_count: int


@dataclass
class ContextBudgetResult:
    allowed: bool
    violations: List[str]
    budget: BudgetInfo
    many_shot_detected: bool
    reason: Optional[str] = None


@dataclass
class ContextBudgetGuardConfig:
    max_total_tokens: int = 8000
    system_prompt_reserve: int = 2000
    max_turns_per_session: int = 50
    max_similar_messages: int = 5
    token_estimator: Optional[Callable[[str], int]] = None


@dataclass
class _SessionBudget:
    sources: Dict[str, int] = field(default_factory=dict)
    total_tokens: int = 0
    turn_count: int = 0
    message_hashes: List[str] = field(default_factory=list)
    last_activity: float = 0.0


class ContextBudgetGuard:
    """Tracks aggregate token usage and prevents context stuffing attacks."""

    def __init__(self, config: Optional[ContextBudgetGuardConfig] = None) -> None:
        cfg = config or ContextBudgetGuardConfig()
        self._max_total_tokens = cfg.max_total_tokens
        self._system_prompt_reserve = cfg.system_prompt_reserve
        self._max_turns_per_session = cfg.max_turns_per_session
        self._max_similar_messages = cfg.max_similar_messages
        self._token_estimator = cfg.token_estimator or _default_token_estimator
        self._sessions: Dict[str, _SessionBudget] = {}

    def track_context(
        self,
        session_id: str,
        source: str,
        content: str,
        request_id: Optional[str] = None,
    ) -> ContextBudgetResult:
        """Track context from any source and check budget."""
        session = self._get_or_create_session(session_id)
        violations: List[str] = []
        tokens = self._token_estimator(content)

        # Track per-source
        current_source_tokens = session.sources.get(source, 0)
        session.sources[source] = current_source_tokens + tokens
        session.total_tokens += tokens
        session.turn_count += 1
        session.last_activity = time.time()

        # Budget check (effective budget = max - system reserve)
        effective_budget = self._max_total_tokens - self._system_prompt_reserve
        if session.total_tokens > effective_budget:
            violations.append("CONTEXT_BUDGET_EXCEEDED")

        # Turn limit check
        if session.turn_count > self._max_turns_per_session:
            violations.append("MAX_TURNS_EXCEEDED")

        # Many-shot detection
        many_shot_detected = self._detect_many_shot_pattern(session, content)
        if many_shot_detected:
            violations.append("MANY_SHOT_PATTERN_DETECTED")

        # Context dilution check (user content > 80% of total)
        user_tokens = session.sources.get("user_input", 0)
        if (
            session.total_tokens > 0
            and user_tokens / session.total_tokens > 0.8
            and session.turn_count > 10
        ):
            violations.append("CONTEXT_DILUTION_DETECTED")

        allowed = len(violations) == 0

        return ContextBudgetResult(
            allowed=allowed,
            reason=None if allowed else f"Context budget violation: {', '.join(violations)}",
            violations=violations,
            budget=BudgetInfo(
                used_tokens=session.total_tokens,
                remaining_tokens=max(0, effective_budget - session.total_tokens),
                system_reserve=self._system_prompt_reserve,
                sources=dict(session.sources),
                turn_count=session.turn_count,
            ),
            many_shot_detected=many_shot_detected,
        )

    def get_session_budget(self, session_id: str) -> Optional[BudgetInfo]:
        """Get current budget status for a session."""
        session = self._sessions.get(session_id)
        if session is None:
            return None
        effective_budget = self._max_total_tokens - self._system_prompt_reserve
        return BudgetInfo(
            used_tokens=session.total_tokens,
            remaining_tokens=max(0, effective_budget - session.total_tokens),
            system_reserve=self._system_prompt_reserve,
            sources=dict(session.sources),
            turn_count=session.turn_count,
        )

    def reset_session(self, session_id: str) -> None:
        """Reset session budget."""
        self._sessions.pop(session_id, None)

    def destroy(self) -> None:
        """Destroy and release all resources."""
        self._sessions.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _detect_many_shot_pattern(self, session: _SessionBudget, content: str) -> bool:
        """Detect repetitive message structures indicative of many-shot attacks."""
        import re
        normalized = re.sub(r"\d+", "N", content)
        normalized = re.sub(r"\s+", " ", normalized).strip()[:100]

        session.message_hashes.append(normalized)

        # Keep only recent hashes
        if len(session.message_hashes) > 100:
            session.message_hashes = session.message_hashes[-100:]

        # Count similar messages in recent window
        recent = session.message_hashes[-20:]
        counts: Dict[str, int] = {}
        for h in recent:
            counts[h] = counts.get(h, 0) + 1

        for count in counts.values():
            if count >= self._max_similar_messages:
                return True

        return False

    def _get_or_create_session(self, session_id: str) -> _SessionBudget:
        # Evict stale sessions
        if len(self._sessions) > 10_000:
            now = time.time()
            expired = [
                sid for sid, s in self._sessions.items()
                if now - s.last_activity > 3600
            ]
            for sid in expired:
                del self._sessions[sid]
                if len(self._sessions) <= 10_000:
                    break

        if session_id not in self._sessions:
            self._sessions[session_id] = _SessionBudget(
                last_activity=time.time(),
            )
        return self._sessions[session_id]
