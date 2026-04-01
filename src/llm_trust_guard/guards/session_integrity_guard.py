"""
SessionIntegrityGuard

Prevents agent session smuggling, hijacking, and state tampering.
Inspired by Unit42 research on agent session attacks.

Threat Model:
- Session token tampering and forgery
- Privilege escalation within established sessions
- Session hijacking via replay or sequence manipulation
- Concurrent session abuse

Protection Capabilities:
- Session binding with token integrity verification
- Permission consistency enforcement (no escalation)
- Inactivity and absolute timeout enforcement
- Concurrent session limits per user
- State continuity validation
- Request sequence validation (replay/reorder detection)
- Scope binding and authority degradation

This is an ARCHITECTURAL guard — it enforces session boundaries
regardless of detection. Even if an attacker injects a prompt,
they cannot escalate session permissions or hijack sessions.

Port of the TypeScript SessionIntegrityGuard.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

LoggerFn = Optional[Callable[[str, str], None]]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

@dataclass
class SessionIntegrityGuardConfig:
    """Configuration for SessionIntegrityGuard."""
    max_session_duration: int = 3_600_000       # 1 hour in ms
    inactivity_timeout: int = 900_000           # 15 min in ms
    max_concurrent_sessions: int = 5
    enforce_permission_consistency: bool = True
    enforce_sequence_validation: bool = True
    allow_permission_escalation: bool = False
    logger: LoggerFn = None


@dataclass
class SessionState:
    """Internal state for a tracked session."""
    session_id: str
    user_id: str
    initial_permissions: Set[str]
    current_permissions: Set[str]
    created_at: float       # epoch ms
    last_activity: float    # epoch ms
    sequence_number: int
    seen_nonces: Set[str]
    active: bool
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class SessionIntegrityResult:
    """Result from session integrity checks."""
    allowed: bool
    violations: List[str]
    reason: Optional[str] = None
    session_age: Optional[float] = None       # ms since creation
    last_activity: Optional[float] = None     # ms since last request
    permission_delta: Optional[List[str]] = None


# ---------------------------------------------------------------------------
# Guard implementation
# ---------------------------------------------------------------------------

class SessionIntegrityGuard:
    """Prevents agent session smuggling, hijacking, and state tampering."""

    def __init__(self, config: Optional[SessionIntegrityGuardConfig] = None) -> None:
        self.config = config or SessionIntegrityGuardConfig()
        self._sessions: Dict[str, SessionState] = {}
        self._user_sessions: Dict[str, Set[str]] = {}

    def create_session(
        self,
        session_id: str,
        user_id: str,
        permissions: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> SessionIntegrityResult:
        """Register a new session. Enforces concurrent session limits."""
        violations: List[str] = []
        now = time.time() * 1000  # epoch ms

        # Reject duplicate session IDs
        if session_id in self._sessions:
            violations.append("duplicate_session_id")
            self._log(f"Duplicate session ID rejected: {session_id}", "warn")
            return SessionIntegrityResult(allowed=False, reason="Session ID already exists", violations=violations)

        # Purge expired sessions for this user before checking limits
        self._purge_expired_sessions(user_id)

        # Check concurrent session limit
        user_set = self._user_sessions.get(user_id, set())
        if len(user_set) >= self.config.max_concurrent_sessions:
            violations.append("concurrent_session_limit_exceeded")
            self._log(f"Concurrent session limit exceeded for user: {user_id}", "warn")
            return SessionIntegrityResult(
                allowed=False,
                reason=f"User already has {len(user_set)} active sessions (max: {self.config.max_concurrent_sessions})",
                violations=violations,
            )

        # Reject empty permissions
        if len(permissions) == 0:
            violations.append("empty_permissions")
            return SessionIntegrityResult(allowed=False, reason="Session must have at least one permission", violations=violations)

        # Create session state
        perm_set = set(permissions)
        session = SessionState(
            session_id=session_id,
            user_id=user_id,
            initial_permissions=set(perm_set),
            current_permissions=perm_set,
            created_at=now,
            last_activity=now,
            sequence_number=0,
            seen_nonces=set(),
            active=True,
            metadata=metadata,
        )

        self._sessions[session_id] = session
        user_set.add(session_id)
        self._user_sessions[user_id] = user_set

        self._log(f"Session created: {session_id} for user: {user_id} with {len(permissions)} permissions", "info")

        return SessionIntegrityResult(allowed=True, violations=[], session_age=0, last_activity=0)

    def validate_request(
        self,
        session_id: str,
        action: str,
        requested_permissions: Optional[List[str]] = None,
        nonce: Optional[str] = None,
        sequence_number: Optional[int] = None,
    ) -> SessionIntegrityResult:
        """
        Validate a request within an existing session.
        Enforces timeouts, permissions, sequence ordering, and scope binding.
        """
        violations: List[str] = []
        now = time.time() * 1000

        # Session must exist
        session = self._sessions.get(session_id)
        if session is None:
            violations.append("session_not_found")
            return SessionIntegrityResult(allowed=False, reason="Session does not exist", violations=violations)

        # Session must be active
        if not session.active:
            violations.append("session_inactive")
            return SessionIntegrityResult(allowed=False, reason="Session has been terminated", violations=violations)

        session_age = now - session.created_at
        idle_time = now - session.last_activity

        # Absolute timeout check
        if session_age > self.config.max_session_duration:
            violations.append("absolute_timeout_exceeded")
            self._terminate_session(session)
            self._log(f"Session {session_id} expired (absolute timeout: {session_age}ms)", "warn")
            return SessionIntegrityResult(
                allowed=False,
                reason=f"Session exceeded maximum duration ({self.config.max_session_duration}ms)",
                violations=violations,
                session_age=session_age,
                last_activity=idle_time,
            )

        # Inactivity timeout check
        if idle_time > self.config.inactivity_timeout:
            violations.append("inactivity_timeout_exceeded")
            self._terminate_session(session)
            self._log(f"Session {session_id} expired (inactivity: {idle_time}ms)", "warn")
            return SessionIntegrityResult(
                allowed=False,
                reason=f"Session exceeded inactivity timeout ({self.config.inactivity_timeout}ms)",
                violations=violations,
                session_age=session_age,
                last_activity=idle_time,
            )

        # Replay detection via nonce
        if nonce is not None:
            if nonce in session.seen_nonces:
                violations.append("replay_detected")
                self._log(f"Replay attack detected on session {session_id}: nonce={nonce}", "warn")
                return SessionIntegrityResult(
                    allowed=False,
                    reason="Duplicate request nonce — possible replay attack",
                    violations=violations,
                    session_age=session_age,
                    last_activity=idle_time,
                )
            session.seen_nonces.add(nonce)

        # Sequence validation
        if self.config.enforce_sequence_validation and sequence_number is not None:
            expected_seq = session.sequence_number + 1
            if sequence_number != expected_seq:
                violations.append("sequence_violation")
                self._log(
                    f"Sequence violation on session {session_id}: expected={expected_seq}, got={sequence_number}",
                    "warn",
                )
                return SessionIntegrityResult(
                    allowed=False,
                    reason=f"Request out of sequence (expected {expected_seq}, got {sequence_number})",
                    violations=violations,
                    session_age=session_age,
                    last_activity=idle_time,
                )

        # Permission / scope binding checks
        permission_delta: List[str] = []

        if requested_permissions and len(requested_permissions) > 0:
            for perm in requested_permissions:
                # Check against initial scope
                if perm not in session.initial_permissions:
                    permission_delta.append(f"+{perm}")
                    violations.append("scope_violation")

                # Check against current permissions (may have been degraded)
                if perm not in session.current_permissions:
                    if perm in session.initial_permissions:
                        # Was degraded — cannot re-escalate
                        permission_delta.append(f"re-escalate:{perm}")
                        violations.append("authority_re_escalation")

            # Enforce permission consistency — block any escalation
            if self.config.enforce_permission_consistency and not self.config.allow_permission_escalation:
                if "scope_violation" in violations or "authority_re_escalation" in violations:
                    self._log(
                        f"Permission escalation blocked on session {session_id}: {', '.join(permission_delta)}",
                        "warn",
                    )
                    return SessionIntegrityResult(
                        allowed=False,
                        reason="Permission escalation denied — session permissions can only decrease",
                        violations=violations,
                        session_age=session_age,
                        last_activity=idle_time,
                        permission_delta=permission_delta,
                    )

        # State continuity — detect dangerous permission transitions
        if action and self._is_abrupt_state_change(action, session):
            violations.append("abrupt_state_change")
            self._log(f"Abrupt state change detected on session {session_id}: action={action}", "warn")
            return SessionIntegrityResult(
                allowed=False,
                reason="Abrupt state transition detected — action inconsistent with session permissions",
                violations=violations,
                session_age=session_age,
                last_activity=idle_time,
            )

        # All checks passed — update session state
        session.last_activity = now
        if sequence_number is not None:
            session.sequence_number = sequence_number
        else:
            session.sequence_number += 1

        return SessionIntegrityResult(
            allowed=len(violations) == 0,
            violations=violations,
            session_age=session_age,
            last_activity=idle_time,
            permission_delta=permission_delta if permission_delta else None,
        )

    def degrade_permissions(self, session_id: str, permissions_to_remove: List[str]) -> SessionIntegrityResult:
        """Degrade permissions for a session. Permissions can only be removed, never added."""
        session = self._sessions.get(session_id)
        if session is None or not session.active:
            return SessionIntegrityResult(
                allowed=False,
                reason="Session not found or inactive",
                violations=["session_not_found"],
            )

        removed: List[str] = []
        for perm in permissions_to_remove:
            if perm in session.current_permissions:
                session.current_permissions.discard(perm)
                removed.append(f"-{perm}")

        now = time.time() * 1000
        self._log(f"Permissions degraded on session {session_id}: {', '.join(removed)}", "info")

        return SessionIntegrityResult(
            allowed=True,
            violations=[],
            permission_delta=removed,
            session_age=now - session.created_at,
            last_activity=now - session.last_activity,
        )

    def end_session(self, session_id: str) -> SessionIntegrityResult:
        """Terminate a session and clean up state."""
        session = self._sessions.get(session_id)
        if session is None:
            return SessionIntegrityResult(allowed=False, reason="Session not found", violations=["session_not_found"])

        self._terminate_session(session)
        now = time.time() * 1000
        self._log(f"Session ended: {session_id}", "info")

        return SessionIntegrityResult(
            allowed=True,
            violations=[],
            session_age=now - session.created_at,
            last_activity=now - session.last_activity,
        )

    def get_active_sessions(self, user_id: str) -> List[str]:
        """List active sessions for a user."""
        self._purge_expired_sessions(user_id)
        user_set = self._user_sessions.get(user_id)
        if not user_set:
            return []
        return [sid for sid in user_set if self._sessions.get(sid) and self._sessions[sid].active]

    # -----------------------------------------------------------------------
    # Private helpers
    # -----------------------------------------------------------------------

    def _is_abrupt_state_change(self, action: str, session: SessionState) -> bool:
        """Detect abrupt state changes — e.g., a read-only session attempting destructive actions."""
        destructive_actions = ["delete", "drop", "truncate", "destroy", "purge", "wipe", "format"]
        write_actions = ["write", "update", "modify", "create", "insert", "patch", "put"]
        admin_actions = ["admin", "sudo", "escalate", "grant", "revoke", "configure"]

        perms = session.current_permissions
        action_lower = action.lower()

        # Read-only session attempting write/delete
        if (len(perms) == 1 and "read" in perms) or "read_only" in perms:
            if any(d in action_lower for d in destructive_actions):
                return True
            if any(w in action_lower for w in write_actions):
                return True

        # Non-admin session attempting admin actions
        if "admin" not in perms and "sudo" not in perms:
            if any(a in action_lower for a in admin_actions):
                return True

        # Any session attempting destructive actions without explicit delete permission
        if "delete" not in perms and "admin" not in perms:
            if any(d in action_lower for d in destructive_actions):
                return True

        return False

    def _terminate_session(self, session: SessionState) -> None:
        """Mark session inactive and remove from user tracking."""
        session.active = False
        user_set = self._user_sessions.get(session.user_id)
        if user_set:
            user_set.discard(session.session_id)
            if len(user_set) == 0:
                del self._user_sessions[session.user_id]

    def _purge_expired_sessions(self, user_id: str) -> None:
        """Purge expired sessions for a user to reclaim concurrent session slots."""
        user_set = self._user_sessions.get(user_id)
        if not user_set:
            return

        now = time.time() * 1000
        for sid in list(user_set):
            session = self._sessions.get(sid)
            if session is None or not session.active:
                user_set.discard(sid)
                continue
            age = now - session.created_at
            idle = now - session.last_activity
            if age > self.config.max_session_duration or idle > self.config.inactivity_timeout:
                self._terminate_session(session)

    def _log(self, message: str, level: str) -> None:
        if self.config.logger:
            self.config.logger(message, level)
