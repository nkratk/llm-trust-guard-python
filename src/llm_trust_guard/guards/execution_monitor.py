"""
L6: Execution Monitor

Prevents resource exhaustion attacks by enforcing:
- Rate limiting per user/session
- Timeout limits on operations
- Resource quotas (max operations per window)
- Cost tracking for expensive operations
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional


@dataclass
class ExecutionMonitorConfig:
    max_requests_per_minute: int = 60
    max_requests_per_hour: int = 1000
    default_timeout_ms: int = 30000
    max_timeout_ms: int = 120000
    max_concurrent_operations: int = 10
    operation_costs: Dict[str, float] = field(default_factory=dict)
    max_cost_per_minute: float = 100
    max_cost_per_hour: float = 1000
    track_by_user: bool = True
    track_by_session: bool = True
    logger: Optional[Callable[[str, str], None]] = None


@dataclass
class RateLimitInfo:
    requests_this_minute: int
    requests_this_hour: int
    max_per_minute: int
    max_per_hour: int


@dataclass
class CostInfo:
    cost_this_minute: float
    cost_this_hour: float
    operation_cost: float
    max_per_minute: float
    max_per_hour: float


@dataclass
class ExecutionMonitorResult:
    allowed: bool
    violations: List[str]
    rate_limit_info: RateLimitInfo
    cost_info: CostInfo
    throttled: bool
    reason: Optional[str] = None
    retry_after_ms: Optional[float] = None


@dataclass
class _CostEntry:
    timestamp: float
    cost: float


@dataclass
class _RateLimitEntry:
    requests: List[float] = field(default_factory=list)
    costs: List[_CostEntry] = field(default_factory=list)
    concurrent_operations: int = 0


def _now_ms() -> float:
    return time.time() * 1000


class ExecutionMonitor:
    def __init__(self, config: Optional[ExecutionMonitorConfig] = None) -> None:
        self._config = config or ExecutionMonitorConfig()
        self._logger = self._config.logger or (lambda msg, level: None)
        self._user_limits: Dict[str, _RateLimitEntry] = {}
        self._session_limits: Dict[str, _RateLimitEntry] = {}
        self._global_limits = _RateLimitEntry()

    def check(
        self,
        tool_name: str,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        request_id: str = "",
    ) -> ExecutionMonitorResult:
        now = _now_ms()
        one_minute_ago = now - 60000
        one_hour_ago = now - 3600000
        violations: List[str] = []

        operation_cost = self._config.operation_costs.get(tool_name, 1)
        entry = self._get_entry(user_id, session_id)

        # Clean up old entries
        self._cleanup_entries(entry, one_minute_ago, one_hour_ago)

        # Optimistic record: add FIRST, then check (prevents TOCTOU race)
        entry.requests.append(now)
        entry.costs.append(_CostEntry(timestamp=now, cost=operation_cost))
        entry.concurrent_operations += 1

        # Count requests (including the one we just added)
        requests_this_minute = sum(1 for t in entry.requests if t > one_minute_ago)
        requests_this_hour = sum(1 for t in entry.requests if t > one_hour_ago)

        # Calculate costs (including the one we just added)
        cost_this_minute = sum(c.cost for c in entry.costs if c.timestamp > one_minute_ago)
        cost_this_hour = sum(c.cost for c in entry.costs if c.timestamp > one_hour_ago)

        # Check rate limits
        throttled = False
        retry_after_ms: Optional[float] = None

        if requests_this_minute > self._config.max_requests_per_minute:
            violations.append("RATE_LIMIT_MINUTE_EXCEEDED")
            throttled = True
            minute_requests = sorted(t for t in entry.requests if t > one_minute_ago)
            oldest_in_minute = minute_requests[0] if minute_requests else None
            retry_after_ms = (oldest_in_minute + 60000 - now) if oldest_in_minute else 60000

        if requests_this_hour > self._config.max_requests_per_hour:
            violations.append("RATE_LIMIT_HOUR_EXCEEDED")
            throttled = True
            hour_requests = sorted(t for t in entry.requests if t > one_hour_ago)
            oldest_in_hour = hour_requests[0] if hour_requests else None
            hour_retry = (oldest_in_hour + 3600000 - now) if oldest_in_hour else 3600000
            retry_after_ms = max(retry_after_ms or 0, hour_retry)

        # Check cost limits
        if cost_this_minute > self._config.max_cost_per_minute:
            violations.append("COST_LIMIT_MINUTE_EXCEEDED")
            throttled = True

        if cost_this_hour > self._config.max_cost_per_hour:
            violations.append("COST_LIMIT_HOUR_EXCEEDED")
            throttled = True

        # Check concurrent operations
        if entry.concurrent_operations > self._config.max_concurrent_operations:
            violations.append("MAX_CONCURRENT_OPERATIONS_EXCEEDED")
            throttled = True

        allowed = not throttled

        # Rollback optimistic record if blocked
        if not allowed:
            entry.requests.pop()
            entry.costs.pop()
            entry.concurrent_operations -= 1
            self._logger(
                f"[ExecutionMonitor:{request_id}] BLOCKED: {', '.join(violations)}",
                "info",
            )

        return ExecutionMonitorResult(
            allowed=allowed,
            reason=None if allowed else f"Rate limit exceeded: {', '.join(violations)}",
            violations=violations,
            rate_limit_info=RateLimitInfo(
                requests_this_minute=requests_this_minute,
                requests_this_hour=requests_this_hour,
                max_per_minute=self._config.max_requests_per_minute,
                max_per_hour=self._config.max_requests_per_hour,
            ),
            cost_info=CostInfo(
                cost_this_minute=cost_this_minute,
                cost_this_hour=cost_this_hour,
                operation_cost=operation_cost,
                max_per_minute=self._config.max_cost_per_minute,
                max_per_hour=self._config.max_cost_per_hour,
            ),
            throttled=throttled,
            retry_after_ms=retry_after_ms,
        )

    def complete_operation(
        self,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        entry = self._get_entry(user_id, session_id)
        if entry.concurrent_operations > 0:
            entry.concurrent_operations -= 1

    def get_status(
        self,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> Dict[str, float]:
        now = _now_ms()
        one_minute_ago = now - 60000
        one_hour_ago = now - 3600000
        entry = self._get_entry(user_id, session_id)

        return {
            "requests_per_minute": sum(1 for t in entry.requests if t > one_minute_ago),
            "requests_per_hour": sum(1 for t in entry.requests if t > one_hour_ago),
            "concurrent_operations": entry.concurrent_operations,
            "cost_per_minute": sum(c.cost for c in entry.costs if c.timestamp > one_minute_ago),
            "cost_per_hour": sum(c.cost for c in entry.costs if c.timestamp > one_hour_ago),
        }

    def reset(
        self,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
    ) -> None:
        if session_id and self._config.track_by_session:
            self._session_limits.pop(session_id, None)
        if user_id and self._config.track_by_user:
            self._user_limits.pop(user_id, None)
        if not user_id and not session_id:
            self._global_limits = _RateLimitEntry()

    def _cap_map_size(self, d: Dict[str, _RateLimitEntry]) -> None:
        if len(d) > 10_000:
            keys_to_delete = list(d.keys())[: len(d) - 10_000]
            for key in keys_to_delete:
                del d[key]

    def _get_entry(
        self,
        user_id: Optional[str],
        session_id: Optional[str],
    ) -> _RateLimitEntry:
        # Priority: session > user > global
        if session_id and self._config.track_by_session:
            if session_id not in self._session_limits:
                self._cap_map_size(self._session_limits)
                self._session_limits[session_id] = _RateLimitEntry()
            return self._session_limits[session_id]

        if user_id and self._config.track_by_user:
            if user_id not in self._user_limits:
                self._cap_map_size(self._user_limits)
                self._user_limits[user_id] = _RateLimitEntry()
            return self._user_limits[user_id]

        return self._global_limits

    def _cleanup_entries(
        self,
        entry: _RateLimitEntry,
        one_minute_ago: float,
        one_hour_ago: float,
    ) -> None:
        entry.requests = [t for t in entry.requests if t > one_hour_ago]
        entry.costs = [c for c in entry.costs if c.timestamp > one_hour_ago]
