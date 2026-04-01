"""
StatePersistenceGuard (L22)

Detects and prevents unauthorized state persistence and corruption.
Implements ASI08 from OWASP Agentic Applications 2026.

Threat Model:
- ASI08: State Corruption
- Unauthorized state persistence
- Cross-session state leakage
- Malicious state injection
- State tampering and replay attacks

Protection Capabilities:
- State integrity verification
- Persistence authorization
- Cross-session isolation
- State encryption validation
- Tampering detection
"""

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Set, Tuple


@dataclass
class StatePersistenceGuardConfig:
    """Configuration for StatePersistenceGuard."""
    enable_integrity_check: bool = True
    require_encryption: bool = False
    max_state_size: int = 1024 * 1024  # 1MB
    max_state_age: int = 24 * 60 * 60 * 1000  # 24 hours in ms
    enforce_session_isolation: bool = True
    allowed_targets: Optional[List[str]] = None
    sensitive_keys: Optional[List[str]] = None
    detect_tampering: bool = True
    signing_secret: str = ""


@dataclass
class StateItem:
    """A single state item."""
    state_id: str
    session_id: str
    key: str
    value: Any
    created_at: int
    modified_at: int
    version: int
    integrity_hash: Optional[str] = None
    encrypted: Optional[bool] = None
    target: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class StateOperation:
    """A state operation request."""
    operation: Literal["read", "write", "delete", "restore", "migrate"]
    key: str
    session_id: str
    value: Any = None
    target_session_id: Optional[str] = None
    target: Optional[str] = None
    integrity_hash: Optional[str] = None
    expected_version: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class StateAnalysis:
    """State operation analysis details."""
    operation: str
    state_key: str
    integrity_valid: bool
    encryption_valid: bool
    session_authorized: bool
    size_valid: bool
    age_valid: bool
    tampering_detected: bool


@dataclass
class StatePersistenceResult:
    """Result of a state persistence operation check."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    analysis: StateAnalysis
    state_item: Optional[StateItem] = None
    recommendations: List[str] = field(default_factory=list)


_PatternWithSeverity = Tuple[str, "re.Pattern[str]", int]


class StatePersistenceGuard:
    """Detects and prevents unauthorized state persistence and corruption."""

    INJECTION_PATTERNS: List[_PatternWithSeverity] = [
        # Code injection
        ("code_injection", re.compile(r"(?:eval|exec|Function|setTimeout|setInterval)\s*\(", re.IGNORECASE), 90),
        ("script_injection", re.compile(r"<script[\s>]|javascript:", re.IGNORECASE), 85),
        ("prototype_pollution", re.compile(r"__proto__|constructor\s*\[|prototype\s*\[", re.IGNORECASE), 90),
        # Serialization attacks
        ("json_injection", re.compile(r'\{\s*["\']?(__proto__|constructor|prototype)["\']?\s*:', re.IGNORECASE), 85),
        ("yaml_injection", re.compile(r"!!python/|!!ruby/|!!php/", re.IGNORECASE), 80),
        ("pickle_attack", re.compile(r"cos\n|cposix\n|csubprocess", re.IGNORECASE), 95),
        # Path traversal
        ("path_traversal", re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE), 75),
        ("null_byte", re.compile(r"\x00|%00", re.IGNORECASE), 80),
        # State corruption
        ("state_hijack", re.compile(r"session_id\s*[:=]|tenant_id\s*[:=]", re.IGNORECASE), 70),
        ("privilege_inject", re.compile(r"(?:role|permission|admin|is_admin)\s*[:=]\s*(?:true|admin|1)", re.IGNORECASE), 85),
        ("trust_inject", re.compile(r"trust_level\s*[:=]|autonomy_level\s*[:=]", re.IGNORECASE), 80),
        # Replay attacks
        ("timestamp_manipulation", re.compile(r"created_at\s*[:=]\s*\d+|modified_at\s*[:=]\s*\d+", re.IGNORECASE), 60),
        ("version_manipulation", re.compile(r"version\s*[:=]\s*\d+", re.IGNORECASE), 55),
    ]

    DEFAULT_SENSITIVE_KEYS = [
        "credentials", "password", "token", "secret", "api_key",
        "session_token", "auth_token", "private_key", "encryption_key", "signing_key",
    ]

    def __init__(self, config: Optional[StatePersistenceGuardConfig] = None) -> None:
        cfg = config or StatePersistenceGuardConfig()
        self._enable_integrity_check = cfg.enable_integrity_check
        self._require_encryption = cfg.require_encryption
        self._max_state_size = cfg.max_state_size
        self._max_state_age = cfg.max_state_age
        self._enforce_session_isolation = cfg.enforce_session_isolation
        self._allowed_targets: List[str] = list(cfg.allowed_targets or ["memory", "session", "cache"])
        self._sensitive_keys: List[str] = list(cfg.sensitive_keys or self.DEFAULT_SENSITIVE_KEYS)
        self._detect_tampering = cfg.detect_tampering
        self._signing_secret = cfg.signing_secret or os.urandom(32).hex()

        self._state_store: Dict[str, StateItem] = {}
        self._session_states: Dict[str, Set[str]] = {}

    def validate_operation(
        self,
        operation: StateOperation,
        request_id: Optional[str] = None,
    ) -> StatePersistenceResult:
        """Validate a state operation."""
        req_id = request_id or f"state-{_now_ms()}"
        violations: List[str] = []

        integrity_valid = True
        encryption_valid = True
        session_authorized = True
        size_valid = True
        age_valid = True
        tampering_detected = False

        # 1. Check session authorization for cross-session operations
        if self._enforce_session_isolation and operation.target_session_id:
            if operation.target_session_id != operation.session_id:
                violations.append("cross_session_access_attempt")
                session_authorized = False

        # 2. Check persistence target authorization
        if operation.target and operation.target not in self._allowed_targets:
            violations.append(f"unauthorized_target: {operation.target}")

        # 3. For write operations, validate the value
        if operation.operation == "write" and operation.value is not None:
            value_size = len(json.dumps(operation.value))
            if value_size > self._max_state_size:
                violations.append(f"state_size_exceeded: {value_size} > {self._max_state_size}")
                size_valid = False

            value_str = operation.value if isinstance(operation.value, str) else json.dumps(operation.value)

            for name, pattern, severity in self.INJECTION_PATTERNS:
                if pattern.search(value_str):
                    violations.append(f"injection_pattern: {name}")
                    if severity >= 80:
                        tampering_detected = True

            if self._is_sensitive_key(operation.key) and not (operation.metadata or {}).get("encrypted"):
                if self._require_encryption:
                    violations.append("sensitive_key_not_encrypted")
                    encryption_valid = False

        # 4. For read/restore operations, validate existing state
        if operation.operation in ("read", "restore"):
            state_key = self._get_state_key(operation.session_id, operation.key)
            existing_state = self._state_store.get(state_key)

            if existing_state:
                if self._enforce_session_isolation and existing_state.session_id != operation.session_id:
                    violations.append("state_ownership_violation")
                    session_authorized = False

                age = _now_ms() - existing_state.created_at
                if age > self._max_state_age:
                    violations.append(f"state_expired: age {round(age / 1000)}s")
                    age_valid = False

                if self._enable_integrity_check and existing_state.integrity_hash:
                    expected_hash = self._compute_integrity_hash(existing_state)
                    if existing_state.integrity_hash != expected_hash:
                        violations.append("integrity_check_failed")
                        integrity_valid = False
                        tampering_detected = True

                if operation.integrity_hash and existing_state.integrity_hash != operation.integrity_hash:
                    violations.append("integrity_hash_mismatch")
                    integrity_valid = False

        # 5. For restore operations, additional checks
        if operation.operation == "restore":
            if operation.expected_version is not None:
                state_key = self._get_state_key(operation.session_id, operation.key)
                existing_state = self._state_store.get(state_key)
                if existing_state and existing_state.version != operation.expected_version:
                    violations.append(
                        f"version_conflict: expected {operation.expected_version}, got {existing_state.version}"
                    )

        # 6. For migrate operations, strict validation
        if operation.operation == "migrate":
            violations.append("migration_requires_admin_approval")

        blocked = (
            not session_authorized
            or tampering_detected
            or not integrity_valid
            or not size_valid
            or len(violations) >= 3
        )

        return StatePersistenceResult(
            allowed=not blocked,
            reason=(
                f"State operation blocked: {', '.join(violations[:3])}"
                if blocked
                else "State operation validated"
            ),
            violations=violations,
            request_id=req_id,
            analysis=StateAnalysis(
                operation=operation.operation,
                state_key=operation.key,
                integrity_valid=integrity_valid,
                encryption_valid=encryption_valid,
                session_authorized=session_authorized,
                size_valid=size_valid,
                age_valid=age_valid,
                tampering_detected=tampering_detected,
            ),
            recommendations=self._generate_recommendations(violations, operation.operation),
        )

    def store_state(
        self,
        session_id: str,
        key: str,
        value: Any,
        options: Optional[Dict[str, Any]] = None,
    ) -> StatePersistenceResult:
        """Store state with integrity protection."""
        opts = options or {}
        req_id = f"store-{_now_ms()}"

        validation = self.validate_operation(
            StateOperation(
                operation="write",
                key=key,
                value=value,
                session_id=session_id,
                target=opts.get("target"),
                metadata=opts,
            ),
            req_id,
        )

        if not validation.allowed:
            return validation

        state_key = self._get_state_key(session_id, key)
        existing_state = self._state_store.get(state_key)
        now = _now_ms()

        state_item = StateItem(
            state_id=existing_state.state_id if existing_state else f"state-{now}-{os.urandom(5).hex()}",
            session_id=session_id,
            key=key,
            value=value,
            created_at=existing_state.created_at if existing_state else now,
            modified_at=now,
            version=(existing_state.version if existing_state else 0) + 1,
            encrypted=opts.get("encrypted"),
            target=opts.get("target"),
            metadata=opts.get("metadata"),
        )

        state_item.integrity_hash = self._compute_integrity_hash(state_item)

        self._state_store[state_key] = state_item

        session_states = self._session_states.setdefault(session_id, set())
        session_states.add(key)

        return StatePersistenceResult(
            allowed=validation.allowed,
            reason=validation.reason,
            violations=validation.violations,
            request_id=validation.request_id,
            analysis=validation.analysis,
            state_item=state_item,
            recommendations=validation.recommendations,
        )

    def retrieve_state(
        self,
        session_id: str,
        key: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> StatePersistenceResult:
        """Retrieve state with integrity verification."""
        opts = options or {}
        req_id = f"retrieve-{_now_ms()}"

        validation = self.validate_operation(
            StateOperation(
                operation="read",
                key=key,
                session_id=session_id,
                integrity_hash=opts.get("integrity_hash"),
            ),
            req_id,
        )

        if not validation.allowed:
            return validation

        state_key = self._get_state_key(session_id, key)
        state_item = self._state_store.get(state_key)

        return StatePersistenceResult(
            allowed=validation.allowed,
            reason=validation.reason,
            violations=validation.violations,
            request_id=validation.request_id,
            analysis=validation.analysis,
            state_item=state_item,
            recommendations=validation.recommendations,
        )

    def delete_state(self, session_id: str, key: str) -> StatePersistenceResult:
        """Delete state."""
        req_id = f"delete-{_now_ms()}"
        state_key = self._get_state_key(session_id, key)
        existing_state = self._state_store.get(state_key)

        if not existing_state:
            return StatePersistenceResult(
                allowed=True,
                reason="State not found",
                violations=[],
                request_id=req_id,
                analysis=StateAnalysis(
                    operation="delete",
                    state_key=key,
                    integrity_valid=True,
                    encryption_valid=True,
                    session_authorized=True,
                    size_valid=True,
                    age_valid=True,
                    tampering_detected=False,
                ),
                recommendations=[],
            )

        if self._enforce_session_isolation and existing_state.session_id != session_id:
            return StatePersistenceResult(
                allowed=False,
                reason="Cannot delete state owned by another session",
                violations=["session_ownership_violation"],
                request_id=req_id,
                analysis=StateAnalysis(
                    operation="delete",
                    state_key=key,
                    integrity_valid=True,
                    encryption_valid=True,
                    session_authorized=False,
                    size_valid=True,
                    age_valid=True,
                    tampering_detected=False,
                ),
                recommendations=["Use the correct session ID to delete state"],
            )

        del self._state_store[state_key]

        session_states = self._session_states.get(session_id)
        if session_states:
            session_states.discard(key)

        return StatePersistenceResult(
            allowed=True,
            reason="State deleted",
            violations=[],
            request_id=req_id,
            analysis=StateAnalysis(
                operation="delete",
                state_key=key,
                integrity_valid=True,
                encryption_valid=True,
                session_authorized=True,
                size_valid=True,
                age_valid=True,
                tampering_detected=False,
            ),
            state_item=existing_state,
            recommendations=[],
        )

    def verify_integrity(self, session_id: str, key: str) -> bool:
        """Verify state integrity."""
        state_key = self._get_state_key(session_id, key)
        state_item = self._state_store.get(state_key)

        if not state_item or not state_item.integrity_hash:
            return False

        expected_hash = self._compute_integrity_hash(state_item)
        return state_item.integrity_hash == expected_hash

    def get_session_states(self, session_id: str) -> List[StateItem]:
        """Get all states for a session."""
        state_keys = self._session_states.get(session_id)
        if not state_keys:
            return []

        states: List[StateItem] = []
        for key in state_keys:
            state_key = self._get_state_key(session_id, key)
            state = self._state_store.get(state_key)
            if state:
                states.append(state)
        return states

    def cleanup_expired_states(self) -> int:
        """Clean up expired states."""
        now = _now_ms()
        cleaned = 0
        keys_to_delete = []

        for state_key, state in self._state_store.items():
            if now - state.created_at > self._max_state_age:
                keys_to_delete.append((state_key, state.session_id, state.key))

        for state_key, session_id, key in keys_to_delete:
            del self._state_store[state_key]
            session_states = self._session_states.get(session_id)
            if session_states:
                session_states.discard(key)
            cleaned += 1

        return cleaned

    def reset_session(self, session_id: str) -> None:
        """Reset all states for a session."""
        state_keys = self._session_states.get(session_id)
        if state_keys:
            for key in list(state_keys):
                self._state_store.pop(self._get_state_key(session_id, key), None)
        self._session_states.pop(session_id, None)

    # -- Private methods --

    def _get_state_key(self, session_id: str, key: str) -> str:
        return f"{session_id}:{key}"

    def _compute_integrity_hash(self, state: StateItem) -> str:
        data = json.dumps({
            "session_id": state.session_id,
            "key": state.key,
            "value": state.value,
            "version": state.version,
        }, sort_keys=False)
        return hmac.new(
            self._signing_secret.encode("utf-8"),
            data.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def _is_sensitive_key(self, key: str) -> bool:
        key_lower = key.lower()
        return any(sk.lower() in key_lower for sk in self._sensitive_keys)

    def _generate_recommendations(self, violations: List[str], operation: str) -> List[str]:
        recommendations: List[str] = []
        if any("cross_session" in v for v in violations):
            recommendations.append("Access only states owned by the current session")
        if any("injection" in v for v in violations):
            recommendations.append("Sanitize state values before persistence")
        if any("integrity" in v for v in violations):
            recommendations.append("Ensure state has not been tampered with")
        if any("encryption" in v for v in violations):
            recommendations.append("Encrypt sensitive state before storage")
        if any("size" in v for v in violations):
            recommendations.append("Reduce state size or split into smaller chunks")
        if any("expired" in v for v in violations):
            recommendations.append("Refresh or recreate expired state")
        if any("version" in v for v in violations):
            recommendations.append("Fetch latest state version before updating")
        if not recommendations:
            recommendations.append(f"Continue with {operation} operation")
        return recommendations


def _now_ms() -> int:
    return int(time.time() * 1000)
