"""
ToolChainValidator v2

Detects and prevents dangerous tool chaining attacks by:
- Validating tool call sequences
- Blocking dangerous tool combinations
- Enforcing cooldown periods between sensitive operations
- Tracking tool usage patterns for anomaly detection

v2 Enhancements:
- ASI07: Agent State Corruption detection
- ASI04: Agent Autonomy Escalation detection
- Loop/repetition attack detection
- Resource accumulation monitoring
- Time-based anomaly detection
- Cumulative impact scoring
- Cross-tool data flow tracking

Port of the TypeScript ToolChainValidator.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Callable, Set

LoggerFn = Optional[Callable[[str, str], None]]


@dataclass
class ForbiddenSequence:
    name: str
    sequence: List[str]
    reason: str
    severity: str  # "warning" | "block"


@dataclass
class ToolPrecondition:
    tool: str
    requires: List[str]
    within_turns: int = 10


@dataclass
class ChainAnalysis:
    current_tool: str
    previous_tools: List[str]
    forbidden_sequences_detected: List[str]
    precondition_violations: List[str]
    cooldown_violations: List[str]
    state_corruption_detected: bool = False
    autonomy_escalation_detected: bool = False
    loop_detected: bool = False
    resource_accumulation: int = 0
    time_anomaly_detected: bool = False
    cumulative_impact: float = 0.0


@dataclass
class ToolChainValidatorResult:
    allowed: bool
    violations: List[str]
    chain_analysis: ChainAnalysis
    warnings: List[str]
    reason: Optional[str] = None


@dataclass
class ToolChainValidatorConfig:
    forbidden_sequences: Optional[List[ForbiddenSequence]] = None
    required_preconditions: Optional[List[ToolPrecondition]] = None
    tool_cooldowns: Optional[Dict[str, float]] = None  # tool -> cooldown in seconds
    max_tools_per_request: int = 10
    max_sensitive_tools_per_session: int = 5
    sensitive_tools: Optional[List[str]] = None
    session_ttl_minutes: int = 30
    # v2: State corruption detection
    enable_state_tracking: bool = True
    state_modifying_tools: Optional[List[str]] = None
    # v2: Autonomy escalation detection
    enable_autonomy_detection: bool = True
    autonomy_expanding_tools: Optional[List[str]] = None
    # v2: Loop detection
    enable_loop_detection: bool = True
    max_repetitions_per_minute: int = 5
    # v2: Resource accumulation
    enable_resource_tracking: bool = True
    resource_acquiring_tools: Optional[List[str]] = None
    max_resources_per_session: int = 10
    # v2: Time anomaly detection
    enable_time_anomaly_detection: bool = True
    min_time_between_tools_ms: float = 50.0
    # v2: Impact scoring
    enable_impact_scoring: bool = True
    max_cumulative_impact: float = 100.0
    tool_impact_scores: Optional[Dict[str, float]] = None
    logger: LoggerFn = None


@dataclass
class _ToolUsage:
    tool: str
    timestamp: float
    params_hash: Optional[str] = None
    modifies_state: bool = False
    expands_autonomy: bool = False
    acquires_resource: bool = False
    impact_score: float = 0.0


@dataclass
class _ToolSession:
    id: str
    tool_history: List[_ToolUsage] = field(default_factory=list)
    sensitive_tool_count: int = 0
    last_activity: float = 0.0
    state_modifications: int = 0
    autonomy_expansions: int = 0
    resources_acquired: int = 0
    cumulative_impact: float = 0.0
    tool_repetitions: Dict[str, List[float]] = field(default_factory=dict)


# fmt: off
DEFAULT_FORBIDDEN_SEQUENCES: List[ForbiddenSequence] = [
    ForbiddenSequence("read_then_delete", ["read_file", "delete_file"], "Reading then deleting files may indicate data exfiltration", "block"),
    ForbiddenSequence("list_then_bulk_delete", ["list_users", "delete_user"], "Listing then deleting users may indicate account takeover", "block"),
    ForbiddenSequence("get_credentials_then_external", ["get_api_key", "http_request"], "Accessing credentials then making external requests is suspicious", "block"),
    ForbiddenSequence("modify_config_then_execute", ["update_config", "execute_command"], "Modifying config then executing commands may indicate system compromise", "block"),
    ForbiddenSequence("disable_security_then_action", ["disable_audit", "delete_records"], "Disabling audit then deleting records indicates malicious activity", "block"),
    ForbiddenSequence("escalate_then_sensitive", ["modify_user_role", "access_admin_panel"], "Role escalation followed by admin access is suspicious", "block"),
]

DEFAULT_SENSITIVE_TOOLS: List[str] = [
    "delete", "remove", "drop", "truncate", "execute", "run",
    "admin", "system", "config", "modify_role", "grant", "revoke",
    "transfer_funds", "bulk_", "export",
]

DEFAULT_STATE_MODIFYING_TOOLS: List[str] = [
    "set_config", "update_settings", "modify_state", "change_mode",
    "set_variable", "store_memory", "update_context", "modify_prompt",
    "change_behavior", "set_preference", "alter_state", "write_memory",
    "persist_data",
]

DEFAULT_AUTONOMY_EXPANDING_TOOLS: List[str] = [
    "grant_permission", "enable_capability", "unlock_feature", "expand_scope",
    "add_tool", "register_handler", "create_webhook", "schedule_task",
    "spawn_agent", "create_subprocess", "enable_auto", "set_autonomous",
    "bypass_approval", "disable_confirmation", "skip_verification",
]

DEFAULT_RESOURCE_ACQUIRING_TOOLS: List[str] = [
    "get_credentials", "fetch_api_key", "acquire_token", "download_file",
    "copy_data", "clone_repo", "export_data", "backup_database",
    "snapshot", "read_secrets", "access_vault", "get_certificate",
]

DEFAULT_TOOL_IMPACT_SCORES: Dict[str, float] = {
    "delete": 20, "remove": 15, "execute": 25, "admin": 30,
    "system": 25, "config": 15, "grant": 20, "transfer": 30,
    "export": 15, "credential": 25, "secret": 25, "password": 30,
    "spawn": 30, "subprocess": 25, "bypass": 35,
}
# fmt: on


def _contains_any(tool_name: str, keywords: List[str]) -> bool:
    tl = tool_name.lower()
    return any(k.lower() in tl for k in keywords)


class ToolChainValidator:
    """Detects and prevents dangerous tool chaining attacks."""

    def __init__(self, config: Optional[ToolChainValidatorConfig] = None) -> None:
        cfg = config or ToolChainValidatorConfig()
        self._forbidden_sequences = cfg.forbidden_sequences if cfg.forbidden_sequences is not None else DEFAULT_FORBIDDEN_SEQUENCES
        self._required_preconditions = cfg.required_preconditions or []
        self._tool_cooldowns = cfg.tool_cooldowns or {}
        self._max_tools_per_request = cfg.max_tools_per_request
        self._max_sensitive_tools_per_session = cfg.max_sensitive_tools_per_session
        self._sensitive_tools = cfg.sensitive_tools if cfg.sensitive_tools is not None else DEFAULT_SENSITIVE_TOOLS
        self._session_ttl_minutes = cfg.session_ttl_minutes
        # v2
        self._enable_state_tracking = cfg.enable_state_tracking
        self._state_modifying_tools = cfg.state_modifying_tools if cfg.state_modifying_tools is not None else DEFAULT_STATE_MODIFYING_TOOLS
        self._enable_autonomy_detection = cfg.enable_autonomy_detection
        self._autonomy_expanding_tools = cfg.autonomy_expanding_tools if cfg.autonomy_expanding_tools is not None else DEFAULT_AUTONOMY_EXPANDING_TOOLS
        self._enable_loop_detection = cfg.enable_loop_detection
        self._max_repetitions_per_minute = cfg.max_repetitions_per_minute
        self._enable_resource_tracking = cfg.enable_resource_tracking
        self._resource_acquiring_tools = cfg.resource_acquiring_tools if cfg.resource_acquiring_tools is not None else DEFAULT_RESOURCE_ACQUIRING_TOOLS
        self._max_resources_per_session = cfg.max_resources_per_session
        self._enable_time_anomaly_detection = cfg.enable_time_anomaly_detection
        self._min_time_between_tools_s = cfg.min_time_between_tools_ms / 1000.0
        self._enable_impact_scoring = cfg.enable_impact_scoring
        self._max_cumulative_impact = cfg.max_cumulative_impact
        self._tool_impact_scores = cfg.tool_impact_scores if cfg.tool_impact_scores is not None else DEFAULT_TOOL_IMPACT_SCORES
        self._logger: Callable[[str, str], None] = cfg.logger or (lambda msg, level: None)
        self._sessions: Dict[str, _ToolSession] = {}

    def validate(
        self,
        session_id: str,
        tool_name: str,
        all_tools_in_request: Optional[List[str]] = None,
        request_id: str = "",
    ) -> ToolChainValidatorResult:
        """Validate a tool call in context of the session."""
        violations: List[str] = []
        warnings: List[str] = []
        forbidden_sequences_detected: List[str] = []
        precondition_violations: List[str] = []
        cooldown_violations: List[str] = []

        # v2 tracking
        state_corruption_detected = False
        autonomy_escalation_detected = False
        loop_detected = False
        time_anomaly_detected = False

        session = self._get_or_create_session(session_id)
        now = time.time()

        # Recent tool history
        ttl_s = self._session_ttl_minutes * 60
        recent_tools = [
            t.tool for t in session.tool_history
            if now - t.timestamp < ttl_s
        ]

        # Check max tools per request
        if all_tools_in_request and len(all_tools_in_request) > self._max_tools_per_request:
            violations.append("MAX_TOOLS_PER_REQUEST_EXCEEDED")

        # Check forbidden sequences
        for forbidden in self._forbidden_sequences:
            if self._matches_sequence(recent_tools, tool_name, forbidden.sequence):
                forbidden_sequences_detected.append(forbidden.name)
                if forbidden.severity == "block":
                    violations.append(f"FORBIDDEN_SEQUENCE_{forbidden.name.upper()}")
                else:
                    warnings.append(f"Suspicious sequence detected: {forbidden.name}")

        # Check preconditions
        for precondition in self._required_preconditions:
            if tool_name == precondition.tool:
                turns_to_check = precondition.within_turns
                recent_history = session.tool_history[-turns_to_check:]
                has_required = all(
                    any(h.tool == req for h in recent_history)
                    for req in precondition.requires
                )
                if not has_required:
                    precondition_violations.append(
                        f"{tool_name} requires: {', '.join(precondition.requires)}"
                    )
                    violations.append(f"PRECONDITION_VIOLATED_{tool_name.upper()}")

        # Check cooldowns
        cooldown = self._tool_cooldowns.get(tool_name)
        if cooldown is not None:
            matching = [t for t in session.tool_history if t.tool == tool_name]
            if matching:
                last_usage = max(matching, key=lambda t: t.timestamp)
                elapsed = now - last_usage.timestamp
                # cooldown is in ms in TS; we store as-is but compare in seconds
                cooldown_s = cooldown / 1000.0
                if elapsed < cooldown_s:
                    remaining_s = cooldown_s - elapsed
                    cooldown_violations.append(
                        f"{tool_name} on cooldown for {int(remaining_s + 0.999)}s"
                    )
                    violations.append(f"COOLDOWN_VIOLATION_{tool_name.upper()}")

        # Check sensitive tool limits
        is_sensitive = _contains_any(tool_name, self._sensitive_tools)
        if is_sensitive:
            if session.sensitive_tool_count >= self._max_sensitive_tools_per_session:
                violations.append("MAX_SENSITIVE_TOOLS_EXCEEDED")

        # ===== v2 CHECKS =====

        # State corruption detection (ASI07)
        if self._enable_state_tracking:
            modifies_state = _contains_any(tool_name, self._state_modifying_tools)
            if modifies_state:
                session.state_modifications += 1
                recent_state_mods = sum(
                    1 for t in session.tool_history
                    if t.modifies_state and now - t.timestamp < 60
                )
                if recent_state_mods >= 3:
                    state_corruption_detected = True
                    violations.append("STATE_CORRUPTION_PATTERN")
                    warnings.append("Multiple rapid state modifications detected - potential state corruption attack")

        # Autonomy escalation detection (ASI04)
        if self._enable_autonomy_detection:
            expands_autonomy = _contains_any(tool_name, self._autonomy_expanding_tools)
            if expands_autonomy:
                session.autonomy_expansions += 1
                if session.autonomy_expansions >= 2:
                    autonomy_escalation_detected = True
                    violations.append("AUTONOMY_ESCALATION_DETECTED")
                    warnings.append("Agent attempting to expand its own autonomy")

        # Loop/repetition detection
        if self._enable_loop_detection:
            if tool_name not in session.tool_repetitions:
                session.tool_repetitions[tool_name] = []
            reps = session.tool_repetitions[tool_name]
            reps.append(now)
            one_minute_ago = now - 60
            recent_reps = [t for t in reps if t > one_minute_ago]
            session.tool_repetitions[tool_name] = recent_reps
            if len(recent_reps) > self._max_repetitions_per_minute:
                loop_detected = True
                violations.append("LOOP_ATTACK_DETECTED")
                warnings.append(f'Tool "{tool_name}" called {len(recent_reps)} times in the last minute')

        # Resource accumulation detection
        if self._enable_resource_tracking:
            acquires_resource = _contains_any(tool_name, self._resource_acquiring_tools)
            if acquires_resource:
                session.resources_acquired += 1
                if session.resources_acquired > self._max_resources_per_session:
                    violations.append("RESOURCE_ACCUMULATION_EXCEEDED")
                    warnings.append("Agent has acquired too many resources in this session")

        # Time anomaly detection
        if self._enable_time_anomaly_detection:
            if session.tool_history:
                last_tool = session.tool_history[-1]
                if now - last_tool.timestamp < self._min_time_between_tools_s:
                    time_anomaly_detected = True
                    violations.append("TIME_ANOMALY_DETECTED")
                    warnings.append("Tool calls too rapid - possible automated attack")

        # Impact scoring
        tool_impact = 0.0
        if self._enable_impact_scoring:
            for keyword, score in self._tool_impact_scores.items():
                if keyword.lower() in tool_name.lower():
                    tool_impact = max(tool_impact, score)
            new_cumulative = session.cumulative_impact + tool_impact
            if new_cumulative > self._max_cumulative_impact:
                violations.append("MAX_CUMULATIVE_IMPACT_EXCEEDED")
                warnings.append(f"Cumulative impact {new_cumulative} exceeds threshold {self._max_cumulative_impact}")

        # ===== END v2 CHECKS =====

        allowed = len(violations) == 0

        # Record tool usage if allowed
        if allowed:
            modifies_state = _contains_any(tool_name, self._state_modifying_tools)
            expands_autonomy = _contains_any(tool_name, self._autonomy_expanding_tools)
            acquires_resource = _contains_any(tool_name, self._resource_acquiring_tools)

            session.tool_history.append(_ToolUsage(
                tool=tool_name,
                timestamp=now,
                modifies_state=modifies_state,
                expands_autonomy=expands_autonomy,
                acquires_resource=acquires_resource,
                impact_score=tool_impact,
            ))
            if is_sensitive:
                session.sensitive_tool_count += 1
            session.cumulative_impact += tool_impact
            session.last_activity = now

        if not allowed:
            self._logger(
                f"[ToolChainValidator:{request_id}] BLOCKED: {', '.join(violations)}",
                "info",
            )

        return ToolChainValidatorResult(
            allowed=allowed,
            reason=None if allowed else f"Tool chain validation failed: {', '.join(violations)}",
            violations=violations,
            chain_analysis=ChainAnalysis(
                current_tool=tool_name,
                previous_tools=recent_tools[-10:],
                forbidden_sequences_detected=forbidden_sequences_detected,
                precondition_violations=precondition_violations,
                cooldown_violations=cooldown_violations,
                state_corruption_detected=state_corruption_detected,
                autonomy_escalation_detected=autonomy_escalation_detected,
                loop_detected=loop_detected,
                resource_accumulation=session.resources_acquired,
                time_anomaly_detected=time_anomaly_detected,
                cumulative_impact=session.cumulative_impact,
            ),
            warnings=warnings,
        )

    def validate_batch(
        self,
        session_id: str,
        tools: List[str],
        request_id: str = "",
    ) -> ToolChainValidatorResult:
        """Validate multiple tools at once (for parallel tool calls)."""
        all_violations: List[str] = []
        all_warnings: List[str] = []
        all_forbidden: List[str] = []
        all_precondition: List[str] = []
        all_cooldown: List[str] = []

        if len(tools) > self._max_tools_per_request:
            all_violations.append("MAX_TOOLS_PER_REQUEST_EXCEEDED")

        for tool in tools:
            result = self.validate(session_id, tool, tools, request_id)
            all_violations.extend(result.violations)
            all_warnings.extend(result.warnings)
            all_forbidden.extend(result.chain_analysis.forbidden_sequences_detected)
            all_precondition.extend(result.chain_analysis.precondition_violations)
            all_cooldown.extend(result.chain_analysis.cooldown_violations)

        # Check for forbidden sequences within the batch
        for forbidden in self._forbidden_sequences:
            if all(
                any(s.lower() in t.lower() for t in tools)
                for s in forbidden.sequence
            ):
                all_forbidden.append(forbidden.name)
                if forbidden.severity == "block":
                    all_violations.append(f"BATCH_FORBIDDEN_SEQUENCE_{forbidden.name.upper()}")

        session = self._sessions.get(session_id)
        recent_tools = [t.tool for t in session.tool_history] if session else []

        unique_violations = list(dict.fromkeys(all_violations))
        unique_warnings = list(dict.fromkeys(all_warnings))
        unique_forbidden = list(dict.fromkeys(all_forbidden))
        unique_precondition = list(dict.fromkeys(all_precondition))
        unique_cooldown = list(dict.fromkeys(all_cooldown))

        return ToolChainValidatorResult(
            allowed=len(unique_violations) == 0,
            reason=None if len(unique_violations) == 0 else f"Batch validation failed: {', '.join(unique_violations)}",
            violations=unique_violations,
            chain_analysis=ChainAnalysis(
                current_tool=", ".join(tools),
                previous_tools=recent_tools[-10:],
                forbidden_sequences_detected=unique_forbidden,
                precondition_violations=unique_precondition,
                cooldown_violations=unique_cooldown,
            ),
            warnings=unique_warnings,
        )

    def get_tool_history(self, session_id: str) -> List[str]:
        """Get session tool history."""
        session = self._sessions.get(session_id)
        if session is None:
            return []
        return [t.tool for t in session.tool_history]

    def reset_session(self, session_id: str) -> None:
        """Reset session."""
        self._sessions.pop(session_id, None)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> _ToolSession:
        if session_id not in self._sessions:
            self._sessions[session_id] = _ToolSession(
                id=session_id,
                last_activity=time.time(),
            )
        return self._sessions[session_id]

    def _matches_sequence(
        self,
        history: List[str],
        current_tool: str,
        sequence: List[str],
    ) -> bool:
        if not sequence:
            return False

        last_in_sequence = sequence[-1]
        if last_in_sequence.lower() not in current_tool.lower():
            return False

        if len(sequence) == 1:
            return True

        preceding = sequence[:-1]
        seq_index = 0
        for hist_tool in history:
            if preceding[seq_index].lower() in hist_tool.lower():
                seq_index += 1
                if seq_index >= len(preceding):
                    return True
        return False

    def _cleanup_sessions(self) -> None:
        ttl_s = self._session_ttl_minutes * 60
        now = time.time()
        expired = [
            sid for sid, s in self._sessions.items()
            if now - s.last_activity > ttl_s
        ]
        for sid in expired:
            del self._sessions[sid]
