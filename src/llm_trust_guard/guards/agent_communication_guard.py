"""
AgentCommunicationGuard (L12)

Secures communication between agents in multi-agent systems.
Prevents impersonation, replay attacks, and message tampering.

Threat Model:
- ASI07: Insecure Inter-Agent Communication
- Agent impersonation attacks
- Message replay attacks
- Man-in-the-middle attacks

Protection Capabilities:
- Message authentication (HMAC signing)
- Agent identity verification
- Replay attack prevention (nonces)
- Message encryption (optional, XOR placeholder — see note below)
- Channel integrity validation
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set, Union


@dataclass
class AgentCommunicationGuardConfig:
    """Configuration for AgentCommunicationGuard."""
    signing_key: Optional[str] = None
    enable_encryption: bool = False
    encryption_key: Optional[str] = None
    nonce_expiration: int = 5 * 60 * 1000  # 5 minutes in ms
    max_message_age: int = 60 * 1000  # 1 minute in ms
    require_signatures: bool = True
    allowed_agents: List[str] = field(default_factory=list)
    strict_mode: bool = False


@dataclass
class AgentIdentity:
    """Registered agent identity."""
    agent_id: str
    agent_type: str
    capabilities: List[str]
    registered_at: int
    trust_score: int = 80
    public_key: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AgentMessage:
    """Inter-agent message."""
    message_id: str
    from_agent: str
    to_agent: Union[str, List[str]]
    type: str  # "request" | "response" | "broadcast" | "event"
    payload: Any
    timestamp: int
    nonce: str
    signature: Optional[str] = None
    encrypted: Optional[bool] = None
    reply_to: Optional[str] = None
    ttl: Optional[int] = None


@dataclass
class MessageValidation:
    """Validation sub-result."""
    sender_verified: bool
    recipient_valid: bool
    signature_valid: bool
    nonce_valid: bool
    timestamp_valid: bool
    payload_safe: bool
    trust_score: int


@dataclass
class MessageValidationResult:
    """Result of message validation."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    validation: MessageValidation
    decrypted_payload: Any = None
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ChannelStatus:
    """Channel status for an agent."""
    agent_id: str
    connected: bool
    last_seen: int
    message_count: int
    trust_score: int
    violations: int


@dataclass
class _PayloadPattern:
    name: str
    pattern: re.Pattern[str]
    severity: int


def _now_ms() -> int:
    return int(time.time() * 1000)


class AgentCommunicationGuard:
    """Secures communication between agents in multi-agent systems."""

    PAYLOAD_INJECTION_PATTERNS: List[_PayloadPattern] = [
        _PayloadPattern("instruction_injection", re.compile(r'"instruction"\s*:\s*"[^"]*(?:ignore|override)', re.IGNORECASE), 40),
        _PayloadPattern("role_escalation", re.compile(r'"(?:role|permission|capability)"\s*:\s*"(?:admin|root|system)"', re.IGNORECASE), 50),
        _PayloadPattern("command_injection", re.compile(r'"(?:command|action|execute)"\s*:\s*"(?:rm|delete|drop|exec)', re.IGNORECASE), 55),
        _PayloadPattern("redirect_attack", re.compile(r'"(?:redirect|forward|proxy)"\s*:\s*"https?://(?!localhost)', re.IGNORECASE), 45),
        _PayloadPattern("credential_request", re.compile(r'"(?:request|get|retrieve)"\s*:\s*"(?:password|secret|key|token)"', re.IGNORECASE), 50),
    ]

    def __init__(self, config: Optional[AgentCommunicationGuardConfig] = None) -> None:
        cfg = config or AgentCommunicationGuardConfig()

        signing_key_hex = cfg.signing_key or os.urandom(32).hex()
        encryption_key_hex = cfg.encryption_key or ""

        if cfg.enable_encryption and not encryption_key_hex:
            encryption_key_hex = os.urandom(32).hex()

        self._signing_key_hex = signing_key_hex
        self._enable_encryption = cfg.enable_encryption
        self._encryption_key_hex = encryption_key_hex
        self._nonce_expiration = cfg.nonce_expiration
        self._max_message_age = cfg.max_message_age
        self._require_signatures = cfg.require_signatures
        self._allowed_agents: List[str] = list(cfg.allowed_agents)
        self._strict_mode = cfg.strict_mode

        self._signing_key = bytes.fromhex(signing_key_hex)
        self._encryption_key: Optional[bytes] = bytes.fromhex(encryption_key_hex) if cfg.enable_encryption and encryption_key_hex else None

        self._registered_agents: Dict[str, AgentIdentity] = {}
        self._used_nonces: Dict[str, int] = {}  # nonce -> timestamp
        self._message_history: Dict[str, int] = {}  # message_id -> timestamp
        self._agent_violations: Dict[str, int] = {}
        self._last_cleanup = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_agent(
        self,
        agent_id: str,
        agent_type: str,
        capabilities: List[str],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AgentIdentity:
        identity = AgentIdentity(
            agent_id=agent_id,
            agent_type=agent_type,
            capabilities=capabilities,
            registered_at=_now_ms(),
            trust_score=80,
            metadata=metadata,
        )
        self._registered_agents[agent_id] = identity
        return identity

    def unregister_agent(self, agent_id: str) -> bool:
        return self._registered_agents.pop(agent_id, None) is not None

    def create_message(
        self,
        from_agent: str,
        to_agent: Union[str, List[str]],
        type: str,
        payload: Any,
        reply_to: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> AgentMessage:
        message_id = f"msg-{_now_ms()}-{os.urandom(8).hex()}"
        nonce = os.urandom(16).hex()
        timestamp = _now_ms()

        final_payload = payload
        if self._enable_encryption and self._encryption_key:
            final_payload = self._encrypt_payload(payload)

        message = AgentMessage(
            message_id=message_id,
            from_agent=from_agent,
            to_agent=to_agent,
            type=type,
            payload=final_payload,
            timestamp=timestamp,
            nonce=nonce,
            reply_to=reply_to,
            ttl=ttl if ttl is not None else self._max_message_age,
            encrypted=self._enable_encryption,
        )

        message.signature = self._sign_message(message)
        return message

    def validate_message(
        self,
        message: AgentMessage,
        receiving_agent_id: str,
        request_id: Optional[str] = None,
    ) -> MessageValidationResult:
        self._lazy_cleanup_nonces()
        req_id = request_id or f"amsg-{_now_ms()}"
        violations: List[str] = []
        sender_verified = False
        recipient_valid = False
        signature_valid = False
        nonce_valid = False
        timestamp_valid = False
        payload_safe = False
        trust_score = 0

        # Check sender is registered
        sender = self._registered_agents.get(message.from_agent)
        if sender:
            sender_verified = True
            trust_score = sender.trust_score
            if self._allowed_agents and message.from_agent not in self._allowed_agents:
                violations.append("sender_not_allowed")
                sender_verified = False
        else:
            violations.append("sender_not_registered")

        # Check recipient
        recipients = message.to_agent if isinstance(message.to_agent, list) else [message.to_agent]
        if receiving_agent_id in recipients or "*" in recipients:
            recipient_valid = True
        else:
            violations.append("recipient_mismatch")

        # Verify signature
        if self._require_signatures:
            if not message.signature:
                violations.append("missing_signature")
            else:
                msg_without_sig = AgentMessage(
                    message_id=message.message_id,
                    from_agent=message.from_agent,
                    to_agent=message.to_agent,
                    type=message.type,
                    payload=message.payload,
                    timestamp=message.timestamp,
                    nonce=message.nonce,
                    encrypted=message.encrypted,
                    reply_to=message.reply_to,
                    ttl=message.ttl,
                    signature=None,
                )
                expected_signature = self._sign_message(msg_without_sig)
                if message.signature == expected_signature:
                    signature_valid = True
                else:
                    violations.append("invalid_signature")
        else:
            signature_valid = True

        # Check nonce (replay prevention)
        if message.nonce in self._used_nonces:
            violations.append("nonce_reused")
        else:
            nonce_valid = True
            self._used_nonces[message.nonce] = _now_ms()

        # Check message ID uniqueness
        if message.message_id in self._message_history:
            violations.append("duplicate_message")
        else:
            self._message_history[message.message_id] = _now_ms()

        # Check timestamp
        message_age = _now_ms() - message.timestamp
        if message_age < 0:
            violations.append("future_timestamp")
        elif message_age > (message.ttl or self._max_message_age):
            violations.append("message_expired")
        else:
            timestamp_valid = True

        # Validate payload
        decrypted_payload = message.payload
        if message.encrypted and self._encryption_key:
            try:
                decrypted_payload = self._decrypt_payload(message.payload)
            except Exception:
                violations.append("decryption_failed")

        payload_check = self._validate_payload(decrypted_payload)
        if payload_check["safe"]:
            payload_safe = True
        else:
            violations.extend(payload_check["violations"])
            trust_score -= payload_check["risk_contribution"]

        # Update agent violations
        if violations and sender:
            current_violations = self._agent_violations.get(message.from_agent, 0)
            self._agent_violations[message.from_agent] = current_violations + len(violations)
            sender.trust_score = max(0, sender.trust_score - len(violations) * 5)
            self._registered_agents[message.from_agent] = sender

        # Decision
        critical_violations = [
            v for v in violations
            if v in ("invalid_signature", "sender_not_registered", "nonce_reused", "duplicate_message")
        ]

        blocked = (
            len(violations) > 0 if self._strict_mode
            else len(critical_violations) > 0
        )

        return MessageValidationResult(
            allowed=not blocked,
            reason=(
                f"Message blocked: {', '.join(violations[:3])}"
                if blocked
                else "Message validated successfully"
            ),
            violations=violations,
            request_id=req_id,
            validation=MessageValidation(
                sender_verified=sender_verified,
                recipient_valid=recipient_valid,
                signature_valid=signature_valid,
                nonce_valid=nonce_valid,
                timestamp_valid=timestamp_valid,
                payload_safe=payload_safe,
                trust_score=max(0, trust_score),
            ),
            decrypted_payload=decrypted_payload if not blocked else None,
            recommendations=self._generate_recommendations(violations),
        )

    def create_response(
        self,
        original_message: AgentMessage,
        from_agent: str,
        payload: Any,
    ) -> AgentMessage:
        return self.create_message(
            from_agent,
            original_message.from_agent,
            "response",
            payload,
            reply_to=original_message.message_id,
        )

    def get_channel_status(self, agent_id: str) -> Optional[ChannelStatus]:
        agent = self._registered_agents.get(agent_id)
        if not agent:
            return None

        message_count = sum(
            1 for mid in self._message_history if agent_id in mid
        )

        return ChannelStatus(
            agent_id=agent_id,
            connected=True,
            last_seen=agent.registered_at,
            message_count=message_count,
            trust_score=agent.trust_score,
            violations=self._agent_violations.get(agent_id, 0),
        )

    def get_registered_agents(self) -> List[AgentIdentity]:
        return list(self._registered_agents.values())

    def has_capability(self, agent_id: str, capability: str) -> bool:
        agent = self._registered_agents.get(agent_id)
        if not agent:
            return False
        return capability in agent.capabilities

    def update_trust_score(self, agent_id: str, delta: int) -> None:
        agent = self._registered_agents.get(agent_id)
        if agent:
            agent.trust_score = max(0, min(100, agent.trust_score + delta))
            self._registered_agents[agent_id] = agent

    def reset_violations(self, agent_id: str) -> None:
        self._agent_violations.pop(agent_id, None)

    def verify_message_chain(
        self, messages: List[AgentMessage]
    ) -> Dict[str, Any]:
        violations: List[str] = []

        for i in range(1, len(messages)):
            current = messages[i]
            previous = messages[i - 1]

            if current.reply_to != previous.message_id:
                violations.append(f"chain_broken_at_{i}")
                return {"valid": False, "broken_at": i, "violations": violations}

            if current.timestamp < previous.timestamp:
                violations.append(f"timestamp_order_violation_at_{i}")
                return {"valid": False, "broken_at": i, "violations": violations}

            expected_sig = self._sign_message(AgentMessage(
                message_id=current.message_id,
                from_agent=current.from_agent,
                to_agent=current.to_agent,
                type=current.type,
                payload=current.payload,
                timestamp=current.timestamp,
                nonce=current.nonce,
                encrypted=current.encrypted,
                reply_to=current.reply_to,
                ttl=current.ttl,
                signature=None,
            ))
            if current.signature != expected_sig:
                violations.append(f"signature_invalid_at_{i}")
                return {"valid": False, "broken_at": i, "violations": violations}

        return {"valid": True, "violations": []}

    def destroy(self) -> None:
        self._registered_agents.clear()
        self._used_nonces.clear()
        self._message_history.clear()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _sign_message(self, message: AgentMessage) -> str:
        data = json.dumps({
            "messageId": message.message_id,
            "fromAgent": message.from_agent,
            "toAgent": message.to_agent,
            "type": message.type,
            "payload": message.payload,
            "timestamp": message.timestamp,
            "nonce": message.nonce,
            "replyTo": message.reply_to,
        }, separators=(",", ":"), ensure_ascii=False)

        return hmac.new(self._signing_key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _encrypt_payload(self, payload: Any) -> str:
        """
        Encrypt payload using simple XOR cipher.

        NOTE: The TypeScript version uses AES-256-GCM via Node crypto.
        Since we must stay zero-dependency (stdlib only), this uses a
        repeating-key XOR as a placeholder. For production use, swap in
        a real AES implementation (e.g. via the cryptography package).
        """
        if not self._encryption_key:
            raise ValueError("Encryption key not set")

        plaintext = json.dumps(payload).encode("utf-8")
        key = self._encryption_key
        encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))
        return encrypted.hex()

    def _decrypt_payload(self, encrypted_payload: str) -> Any:
        """Decrypt payload (XOR placeholder — see _encrypt_payload note)."""
        if not self._encryption_key:
            raise ValueError("Encryption key not set")

        encrypted = bytes.fromhex(encrypted_payload)
        key = self._encryption_key
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(encrypted))
        return json.loads(decrypted.decode("utf-8"))

    def _validate_payload(self, payload: Any) -> Dict[str, Any]:
        violations: List[str] = []
        risk_contribution = 0

        payload_str = json.dumps(payload)

        for pat in self.PAYLOAD_INJECTION_PATTERNS:
            if pat.pattern.search(payload_str):
                violations.append(f"payload_{pat.name}")
                risk_contribution += pat.severity

        if len(payload_str) > 100_000:
            violations.append("payload_too_large")
            risk_contribution += 20

        depth = self._get_object_depth(payload)
        if depth > 10:
            violations.append("payload_too_deep")
            risk_contribution += 15

        return {
            "safe": len(violations) == 0,
            "violations": violations,
            "risk_contribution": min(60, risk_contribution),
        }

    def _get_object_depth(self, obj: Any, current_depth: int = 0) -> int:
        if not isinstance(obj, (dict, list)):
            return current_depth
        if current_depth > 15:
            return current_depth

        max_depth = current_depth
        items = obj.values() if isinstance(obj, dict) else obj
        for value in items:
            depth = self._get_object_depth(value, current_depth + 1)
            max_depth = max(max_depth, depth)
        return max_depth

    def _lazy_cleanup_nonces(self) -> None:
        now = _now_ms()
        if now - self._last_cleanup < 60_000:
            return
        self._last_cleanup = now
        self._cleanup_nonces()

    def _cleanup_nonces(self) -> None:
        now = _now_ms()
        expiration = self._nonce_expiration

        expired_nonces = [n for n, ts in self._used_nonces.items() if now - ts > expiration]
        for n in expired_nonces:
            del self._used_nonces[n]

        expired_msgs = [m for m, ts in self._message_history.items() if now - ts > expiration * 2]
        for m in expired_msgs:
            del self._message_history[m]

    def _generate_recommendations(self, violations: List[str]) -> List[str]:
        recommendations: List[str] = []

        if any("signature" in v for v in violations):
            recommendations.append("Ensure messages are properly signed before sending")
        if any("nonce" in v or "duplicate" in v for v in violations):
            recommendations.append("Implement proper nonce generation to prevent replay attacks")
        if any("sender" in v for v in violations):
            recommendations.append("Register agents before they can communicate")
        if any("payload" in v for v in violations):
            recommendations.append("Sanitize message payloads before sending")
        if any("expired" in v or "timestamp" in v for v in violations):
            recommendations.append("Ensure agent clocks are synchronized")

        if not recommendations:
            recommendations.append("Message validated successfully")

        return recommendations
