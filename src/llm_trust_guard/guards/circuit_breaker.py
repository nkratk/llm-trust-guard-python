"""
CircuitBreaker (L13)

Prevents cascade failures in agentic workflows.
Implements the circuit breaker pattern for LLM operations.

Threat Model:
- ASI08: Cascading Failures
- Runaway agent behavior
- Resource exhaustion via retries

Protection Capabilities:
- Failure rate monitoring
- Automatic circuit opening
- Graceful degradation
- Recovery detection
- Rollback triggers
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Generic, List, Literal, Optional, TypeVar

CircuitState = Literal["closed", "open", "half-open"]

T = TypeVar("T")


@dataclass
class CircuitStats:
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    consecutive_failures: int = 0
    consecutive_successes: int = 0
    failure_rate: float = 0.0
    last_failure: Optional[float] = None
    last_success: Optional[float] = None
    state_changed_at: float = 0.0

    def copy(self) -> CircuitStats:
        return CircuitStats(
            total_requests=self.total_requests,
            successful_requests=self.successful_requests,
            failed_requests=self.failed_requests,
            consecutive_failures=self.consecutive_failures,
            consecutive_successes=self.consecutive_successes,
            failure_rate=self.failure_rate,
            last_failure=self.last_failure,
            last_success=self.last_success,
            state_changed_at=self.state_changed_at,
        )


@dataclass
class CircuitBreakerConfig:
    failure_threshold: float = 50
    minimum_requests: int = 5
    window_size: int = 60_000  # 1 minute
    recovery_timeout: int = 30_000  # 30 seconds
    success_threshold: int = 3
    auto_recover: bool = True
    max_consecutive_failures: int = 5
    on_open: Optional[Callable[[str, CircuitStats], None]] = None
    on_close: Optional[Callable[[str, CircuitStats], None]] = None
    on_half_open: Optional[Callable[[str], None]] = None


@dataclass
class CircuitBreakerResult:
    allowed: bool
    state: CircuitState
    reason: str
    request_id: str
    stats: CircuitStats
    fallback_recommended: bool
    retry_after: Optional[float] = None


@dataclass
class OperationResult:
    success: bool
    duration: float
    error: Optional[str] = None


@dataclass
class _CircuitData:
    state: CircuitState = "closed"
    stats: CircuitStats = field(default_factory=CircuitStats)
    request_timestamps: List[float] = field(default_factory=list)
    failure_timestamps: List[float] = field(default_factory=list)
    opened_at: Optional[float] = None


def _now_ms() -> float:
    return time.time() * 1000


class CircuitBreaker:
    def __init__(self, config: Optional[CircuitBreakerConfig] = None) -> None:
        self._config = config or CircuitBreakerConfig()
        self._circuits: Dict[str, _CircuitData] = {}

    def check(self, circuit_id: str, request_id: Optional[str] = None) -> CircuitBreakerResult:
        req_id = request_id or f"cb-{int(_now_ms())}"
        circuit = self._get_or_create_circuit(circuit_id)

        # Clean old data outside window
        self._cleanup_window(circuit)

        if circuit.state == "closed":
            return CircuitBreakerResult(
                allowed=True,
                state="closed",
                reason="Circuit is closed, operation allowed",
                request_id=req_id,
                stats=circuit.stats.copy(),
                fallback_recommended=False,
            )

        if circuit.state == "open":
            # Check if recovery timeout has passed
            if circuit.opened_at is not None and _now_ms() - circuit.opened_at >= self._config.recovery_timeout:
                if self._config.auto_recover:
                    self._transition_to_half_open(circuit_id, circuit)
                    return CircuitBreakerResult(
                        allowed=True,
                        state="half-open",
                        reason="Circuit is half-open, testing recovery",
                        request_id=req_id,
                        stats=circuit.stats.copy(),
                        fallback_recommended=True,
                    )

            retry_after = (
                max(0, self._config.recovery_timeout - (_now_ms() - circuit.opened_at))
                if circuit.opened_at is not None
                else self._config.recovery_timeout
            )

            return CircuitBreakerResult(
                allowed=False,
                state="open",
                reason="Circuit is open, operation blocked",
                request_id=req_id,
                stats=circuit.stats.copy(),
                fallback_recommended=True,
                retry_after=retry_after,
            )

        if circuit.state == "half-open":
            return CircuitBreakerResult(
                allowed=True,
                state="half-open",
                reason="Circuit is half-open, testing recovery",
                request_id=req_id,
                stats=circuit.stats.copy(),
                fallback_recommended=True,
            )

        # Unknown state fallback
        return CircuitBreakerResult(
            allowed=False,
            state="open",
            reason="Unknown circuit state",
            request_id=req_id,
            stats=circuit.stats.copy(),
            fallback_recommended=True,
        )

    def record_result(self, circuit_id: str, result: OperationResult) -> None:
        circuit = self._get_or_create_circuit(circuit_id)
        now = _now_ms()

        circuit.request_timestamps.append(now)
        circuit.stats.total_requests += 1

        if result.success:
            circuit.stats.successful_requests += 1
            circuit.stats.consecutive_successes += 1
            circuit.stats.consecutive_failures = 0
            circuit.stats.last_success = now

            # Check for recovery in half-open state
            if circuit.state == "half-open":
                if circuit.stats.consecutive_successes >= self._config.success_threshold:
                    self._close_circuit(circuit_id, circuit)
        else:
            circuit.stats.failed_requests += 1
            circuit.stats.consecutive_failures += 1
            circuit.stats.consecutive_successes = 0
            circuit.stats.last_failure = now
            circuit.failure_timestamps.append(now)

            # Check for circuit opening conditions
            if circuit.state in ("closed", "half-open"):
                # Check consecutive failures
                if circuit.stats.consecutive_failures >= self._config.max_consecutive_failures:
                    self._open_circuit(circuit_id, circuit)
                    return

                # Check failure rate
                windowed_failures = self._count_in_window(circuit.failure_timestamps)
                windowed_requests = self._count_in_window(circuit.request_timestamps)

                if windowed_requests >= self._config.minimum_requests:
                    failure_rate = (windowed_failures / windowed_requests) * 100
                    circuit.stats.failure_rate = failure_rate

                    if failure_rate >= self._config.failure_threshold:
                        self._open_circuit(circuit_id, circuit)

        # Update failure rate
        windowed_failures = self._count_in_window(circuit.failure_timestamps)
        windowed_requests = self._count_in_window(circuit.request_timestamps)
        circuit.stats.failure_rate = (
            (windowed_failures / windowed_requests) * 100 if windowed_requests > 0 else 0
        )

    def record_success(self, circuit_id: str, duration: Optional[float] = None) -> None:
        self.record_result(circuit_id, OperationResult(success=True, duration=duration or 0))

    def record_failure(self, circuit_id: str, error: Optional[str] = None, duration: Optional[float] = None) -> None:
        self.record_result(
            circuit_id,
            OperationResult(success=False, duration=duration or 0, error=error),
        )

    def get_state(self, circuit_id: str) -> CircuitState:
        circuit = self._circuits.get(circuit_id)
        return circuit.state if circuit else "closed"

    def get_stats(self, circuit_id: str) -> Optional[CircuitStats]:
        circuit = self._circuits.get(circuit_id)
        return circuit.stats.copy() if circuit else None

    def get_circuit_ids(self) -> List[str]:
        return list(self._circuits.keys())

    def force_open(self, circuit_id: str) -> None:
        circuit = self._get_or_create_circuit(circuit_id)
        self._open_circuit(circuit_id, circuit)

    def force_close(self, circuit_id: str) -> None:
        circuit = self._get_or_create_circuit(circuit_id)
        self._close_circuit(circuit_id, circuit)

    def reset(self, circuit_id: str) -> None:
        self._circuits.pop(circuit_id, None)

    def reset_all(self) -> None:
        self._circuits.clear()

    def health_check(self) -> Dict:
        circuit_statuses = []
        open_circuits = 0

        for cid, circuit in self._circuits.items():
            circuit_statuses.append({
                "id": cid,
                "state": circuit.state,
                "failure_rate": circuit.stats.failure_rate,
            })
            if circuit.state == "open":
                open_circuits += 1

        return {
            "healthy": open_circuits == 0,
            "circuits": circuit_statuses,
            "open_circuits": open_circuits,
        }

    def _get_or_create_circuit(self, circuit_id: str) -> _CircuitData:
        circuit = self._circuits.get(circuit_id)
        if circuit is None:
            # Evict stale circuits if map is too large
            if len(self._circuits) > 10_000:
                now = _now_ms()
                to_delete = [
                    cid for cid, c in self._circuits.items()
                    if now - c.stats.state_changed_at > 3_600_000
                ]
                for cid in to_delete:
                    del self._circuits[cid]
                    if len(self._circuits) <= 10_000:
                        break

            circuit = _CircuitData(
                stats=CircuitStats(state_changed_at=_now_ms()),
            )
            self._circuits[circuit_id] = circuit
        return circuit

    def _open_circuit(self, circuit_id: str, circuit: _CircuitData) -> None:
        circuit.state = "open"
        now = _now_ms()
        circuit.opened_at = now
        circuit.stats.state_changed_at = now

        if self._config.on_open:
            self._config.on_open(circuit_id, circuit.stats.copy())

    def _close_circuit(self, circuit_id: str, circuit: _CircuitData) -> None:
        circuit.state = "closed"
        circuit.opened_at = None
        circuit.stats.state_changed_at = _now_ms()
        circuit.stats.consecutive_failures = 0

        if self._config.on_close:
            self._config.on_close(circuit_id, circuit.stats.copy())

    def _transition_to_half_open(self, circuit_id: str, circuit: _CircuitData) -> None:
        circuit.state = "half-open"
        circuit.stats.state_changed_at = _now_ms()
        circuit.stats.consecutive_successes = 0

        if self._config.on_half_open:
            self._config.on_half_open(circuit_id)

    def _cleanup_window(self, circuit: _CircuitData) -> None:
        cutoff = _now_ms() - self._config.window_size
        circuit.request_timestamps = [t for t in circuit.request_timestamps if t > cutoff]
        circuit.failure_timestamps = [t for t in circuit.failure_timestamps if t > cutoff]

    def _count_in_window(self, timestamps: List[float]) -> int:
        cutoff = _now_ms() - self._config.window_size
        return sum(1 for t in timestamps if t > cutoff)
