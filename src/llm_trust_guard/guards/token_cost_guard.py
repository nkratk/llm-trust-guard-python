"""
TokenCostGuard

Tracks LLM API token usage and cost per session/user.
Enforces financial circuit breaking with hard cost ceilings.

Addresses OWASP LLM10: Unbounded Consumption -- insufficient controls
on resource usage leading to excessive API costs, denial-of-service,
or financial exploitation.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class TokenCostGuardConfig:
    max_tokens_per_session: int = 100_000
    max_tokens_per_user: int = 500_000
    max_cost_per_session: float = 10.0
    max_cost_per_user: float = 50.0
    input_token_cost_per_1k: float = 0.003
    output_token_cost_per_1k: float = 0.015
    max_tokens_per_request: int = 32_000
    alert_threshold: float = 0.8
    budget_window_ms: int = 3_600_000


@dataclass
class TokenUsage:
    input_tokens: int
    output_tokens: int
    total_tokens: int
    estimated_cost: float


@dataclass
class BudgetInfo:
    session_remaining_tokens: int
    session_remaining_cost: float
    user_remaining_tokens: int
    user_remaining_cost: float
    alert: bool
    alert_message: Optional[str] = None


@dataclass
class UsageInfo:
    session: TokenUsage
    user: TokenUsage
    request: TokenUsage


@dataclass
class TokenCostResult:
    allowed: bool
    violations: List[str]
    usage: UsageInfo
    budget: BudgetInfo
    reason: Optional[str] = None


@dataclass
class _UsageEntry:
    input_tokens: int
    output_tokens: int
    cost: float
    timestamp: float


@dataclass
class _SessionUsage:
    entries: List[_UsageEntry] = field(default_factory=list)
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    last_activity: float = 0.0


def _now_ms() -> float:
    return time.time() * 1000


class TokenCostGuard:
    def __init__(self, config: Optional[TokenCostGuardConfig] = None) -> None:
        self._config = config or TokenCostGuardConfig()
        self._session_usage: Dict[str, _SessionUsage] = {}
        self._user_usage: Dict[str, _SessionUsage] = {}

    def track_usage(
        self,
        session_id: str,
        user_id: str,
        input_tokens: int,
        output_tokens: int,
        request_id: Optional[str] = None,
    ) -> TokenCostResult:
        violations: List[str] = []
        total_tokens = input_tokens + output_tokens
        request_cost = self._calculate_cost(input_tokens, output_tokens)

        # Per-request check
        if total_tokens > self._config.max_tokens_per_request:
            violations.append("REQUEST_TOKEN_LIMIT_EXCEEDED")

        # Get or create session/user usage
        session = self._get_or_create_usage(self._session_usage, session_id)
        user = self._get_or_create_usage(self._user_usage, user_id)

        # Clean old entries outside budget window
        self._clean_entries(session)
        self._clean_entries(user)

        # Check session limits BEFORE recording
        if session.total_input_tokens + session.total_output_tokens + total_tokens > self._config.max_tokens_per_session:
            violations.append("SESSION_TOKEN_LIMIT_EXCEEDED")
        if session.total_cost + request_cost > self._config.max_cost_per_session:
            violations.append("SESSION_COST_LIMIT_EXCEEDED")

        # Check user limits
        if user.total_input_tokens + user.total_output_tokens + total_tokens > self._config.max_tokens_per_user:
            violations.append("USER_TOKEN_LIMIT_EXCEEDED")
        if user.total_cost + request_cost > self._config.max_cost_per_user:
            violations.append("USER_COST_LIMIT_EXCEEDED")

        allowed = len(violations) == 0

        # Record usage only if allowed
        if allowed:
            now = _now_ms()
            entry = _UsageEntry(
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=request_cost,
                timestamp=now,
            )
            session.entries.append(entry)
            session.total_input_tokens += input_tokens
            session.total_output_tokens += output_tokens
            session.total_cost += request_cost
            session.last_activity = now

            user.entries.append(entry)
            user.total_input_tokens += input_tokens
            user.total_output_tokens += output_tokens
            user.total_cost += request_cost
            user.last_activity = now

        # Alert check
        session_token_ratio = (session.total_input_tokens + session.total_output_tokens) / self._config.max_tokens_per_session
        session_cost_ratio = session.total_cost / self._config.max_cost_per_session
        user_token_ratio = (user.total_input_tokens + user.total_output_tokens) / self._config.max_tokens_per_user
        user_cost_ratio = user.total_cost / self._config.max_cost_per_user

        highest_ratio = max(session_token_ratio, session_cost_ratio, user_token_ratio, user_cost_ratio)
        alert = highest_ratio >= self._config.alert_threshold
        alert_message: Optional[str] = None
        if alert and allowed:
            alert_message = f"Token/cost budget at {highest_ratio * 100:.0f}% -- approaching limit"

        return TokenCostResult(
            allowed=allowed,
            reason=None if allowed else f"Token/cost limit exceeded: {', '.join(violations)}",
            violations=violations,
            usage=UsageInfo(
                session=TokenUsage(
                    input_tokens=session.total_input_tokens,
                    output_tokens=session.total_output_tokens,
                    total_tokens=session.total_input_tokens + session.total_output_tokens,
                    estimated_cost=session.total_cost,
                ),
                user=TokenUsage(
                    input_tokens=user.total_input_tokens,
                    output_tokens=user.total_output_tokens,
                    total_tokens=user.total_input_tokens + user.total_output_tokens,
                    estimated_cost=user.total_cost,
                ),
                request=TokenUsage(
                    input_tokens=input_tokens,
                    output_tokens=output_tokens,
                    total_tokens=total_tokens,
                    estimated_cost=request_cost,
                ),
            ),
            budget=BudgetInfo(
                session_remaining_tokens=max(0, self._config.max_tokens_per_session - session.total_input_tokens - session.total_output_tokens),
                session_remaining_cost=max(0, self._config.max_cost_per_session - session.total_cost),
                user_remaining_tokens=max(0, self._config.max_tokens_per_user - user.total_input_tokens - user.total_output_tokens),
                user_remaining_cost=max(0, self._config.max_cost_per_user - user.total_cost),
                alert=alert,
                alert_message=alert_message,
            ),
        )

    def get_budget(self, session_id: str, user_id: str) -> BudgetInfo:
        session = self._session_usage.get(session_id)
        user = self._user_usage.get(user_id)

        return BudgetInfo(
            session_remaining_tokens=self._config.max_tokens_per_session - (
                (session.total_input_tokens + session.total_output_tokens) if session else 0
            ),
            session_remaining_cost=self._config.max_cost_per_session - (session.total_cost if session else 0),
            user_remaining_tokens=self._config.max_tokens_per_user - (
                (user.total_input_tokens + user.total_output_tokens) if user else 0
            ),
            user_remaining_cost=self._config.max_cost_per_user - (user.total_cost if user else 0),
            alert=False,
        )

    def reset_session(self, session_id: str) -> None:
        self._session_usage.pop(session_id, None)

    def reset_user(self, user_id: str) -> None:
        self._user_usage.pop(user_id, None)

    def destroy(self) -> None:
        self._session_usage.clear()
        self._user_usage.clear()

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            (input_tokens / 1000) * self._config.input_token_cost_per_1k
            + (output_tokens / 1000) * self._config.output_token_cost_per_1k
        )

    def _get_or_create_usage(self, usage_map: Dict[str, _SessionUsage], key: str) -> _SessionUsage:
        if key not in usage_map:
            if len(usage_map) > 10_000:
                oldest = next(iter(usage_map))
                del usage_map[oldest]
            usage_map[key] = _SessionUsage(last_activity=_now_ms())
        return usage_map[key]

    def _clean_entries(self, usage: _SessionUsage) -> None:
        cutoff = _now_ms() - self._config.budget_window_ms
        valid_entries = [e for e in usage.entries if e.timestamp > cutoff]

        if len(valid_entries) < len(usage.entries):
            usage.entries = valid_entries
            usage.total_input_tokens = sum(e.input_tokens for e in valid_entries)
            usage.total_output_tokens = sum(e.output_tokens for e in valid_entries)
            usage.total_cost = sum(e.cost for e in valid_entries)
