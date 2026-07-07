"""
MemoryGuard (L9)

Protects persistent memory/context from poisoning attacks.
Prevents cross-session contamination and instruction injection in stored context.

Threat Model:
- ASI06: Memory & Context Poisoning
- Memory Persistence Attacks (cross-session instruction injection)
- Context window manipulation

Protection Capabilities:
- Memory content integrity verification
- Instruction injection detection in stored context
- Cross-session contamination prevention
- Memory rollback capabilities
- Cryptographic content signing
"""

import hashlib
import hmac
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Set, Tuple, Union


@dataclass
class MemoryGuardConfig:
    """Configuration for MemoryGuard."""
    enable_integrity_check: bool = True
    detect_injections: bool = True
    max_memory_items: int = 100
    max_memory_age: int = 24 * 60 * 60 * 1000  # 24 hours in ms
    signing_key: str = ""
    auto_quarantine: bool = True
    risk_threshold: int = 40


@dataclass
class MemoryItem:
    """A single memory item."""
    id: str
    content: str
    source: Literal["user", "assistant", "system", "external", "rag"]
    timestamp: int
    session_id: str
    metadata: Optional[Dict[str, Any]] = None
    signature: Optional[str] = None
    trust_score: Optional[int] = None


@dataclass
class MemoryAnalysis:
    """Memory analysis details."""
    items_checked: int = 0
    items_quarantined: int = 0
    injection_attempts: int = 0
    integrity_failures: int = 0
    cross_session_contamination: bool = False
    risk_score: int = 0


@dataclass
class MemoryGuardResult:
    """Result of a memory read or context injection check."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    memory_analysis: MemoryAnalysis
    quarantined_items: List[str]
    recommendations: List[str]


@dataclass
class MemoryWriteResult:
    """Result of a memory write check."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    item_id: Optional[str] = None
    signature: Optional[str] = None
    sanitized_content: Optional[str] = None


# Pattern definitions
_InjectionPattern = Tuple[str, "re.Pattern[str]", int]
_ContaminationPattern = Tuple[str, "re.Pattern[str]"]


class MemoryGuard:
    """Protects persistent memory/context from poisoning attacks."""

    MEMORY_INJECTION_PATTERNS: List[_InjectionPattern] = [
        ("persistent_instruction", re.compile(r"always\s+(remember|do|follow|execute|obey)|from\s+now\s+on", re.IGNORECASE), 30),
        ("future_trigger", re.compile(r"when(?:ever)?\s+(you|user|they|someone)\s+(see|mention|ask|type|say|input)", re.IGNORECASE), 25),
        ("hidden_rule", re.compile(r"secret\s+(rule|instruction|command|directive)|do\s+not\s+(tell|reveal|disclose|mention)", re.IGNORECASE), 40),
        ("role_persistence", re.compile(r"you\s+are\s+(always|permanently|forever|now)\s+(a|an|the)|you\s+are\s+now\s+permanently|maintain\s+this\s+persona", re.IGNORECASE), 35),
        ("memory_manipulation", re.compile(r"forget\s+(everything|all|previous|prior)|clear\s+(your\s+)?memory|wipe\s+your\s+context", re.IGNORECASE), 30),
        ("cross_session_leak", re.compile(r"remember\s+(?:this\s+)?for\s+(next|future|all)\s+session|store\s+(?:this\s+)?permanently", re.IGNORECASE), 35),
        ("behavior_override", re.compile(r"override\s+(default|normal|standard|current)\s+behavior|change\s+your\s+(?:core\s+)?behavior", re.IGNORECASE), 40),
        ("system_impersonation", re.compile(r"\[SYSTEM\s*(?:MEMORY|MESSAGE|INSTRUCTION)\]|\[CORE\s*INSTRUCTION\]|\[PERMANENT\s*RULE\]|\[ADMIN\s*OVERRIDE\]", re.IGNORECASE), 50),
        ("exfiltration_setup", re.compile(r"whenever\s+.*(?:send|transmit|forward)\s+to|always\s+(?:include|append|add)\s+(?:in|to)\s+response", re.IGNORECASE), 45),
        ("privilege_persistence", re.compile(r"grant\s+(admin|root|elevated|superuser)\s+(?:access|privileges?)\s+(permanently|always|forever)", re.IGNORECASE), 50),
        ("conditional_behavior", re.compile(r"if\s+(?:user|anyone|someone)\s+(?:says|types|asks|mentions?)\s+.*(?:then|,)\s+(?:do|execute|respond|reveal|show|give)", re.IGNORECASE), 35),
        ("hidden_command", re.compile(r"hidden\s+command|secret\s+trigger|backdoor|easter\s+egg\s+(?:is|:)", re.IGNORECASE), 45),
        ("instruction_injection", re.compile(r"(?:new|updated|revised)\s+(?:system\s+)?instructions?\s*:|important\s+update\s*:", re.IGNORECASE), 40),
        ("context_pollution", re.compile(r"(?:prepend|append)\s+(?:this\s+)?to\s+(?:all\s+)?(?:responses?|outputs?)", re.IGNORECASE), 35),
        ("sleeper_agent", re.compile(r"wait\s+(?:for|until)\s+(?:signal|trigger|command)|activate\s+(?:when|on|if)", re.IGNORECASE), 45),
        ("goal_hijacking", re.compile(r"(?:your\s+)?(?:new|real|true|actual)\s+(?:goal|objective|purpose|mission)\s+(?:is|:)", re.IGNORECASE), 50),
        ("trust_exploitation", re.compile(r"(?:trust|believe)\s+(?:everything|anything)\s+(?:I|user)\s+(?:say|tell)", re.IGNORECASE), 40),
        ("output_manipulation", re.compile(r"(?:always|never)\s+(?:include|exclude|add|remove)\s+.*\s+(?:in|from)\s+(?:your\s+)?(?:response|output)", re.IGNORECASE), 35),
        ("persona_injection", re.compile(r"(?:adopt|assume|take\s+on)\s+(?:the\s+)?(?:persona|identity|role)\s+of", re.IGNORECASE), 35),
        ("data_harvesting", re.compile(r"(?:collect|gather|record)\s+(?:all\s+)?(?:user\s+)?(?:data|information|inputs?)", re.IGNORECASE), 45),
        ("bypass_safety", re.compile(r"(?:ignore|bypass|disable|turn\s+off)\s+(?:safety|security|content)\s+(?:checks?|filters?|measures?)", re.IGNORECASE), 50),
        ("false_context", re.compile(r"(?:pretend|assume|imagine)\s+(?:that\s+)?(?:this\s+)?(?:is|was)\s+(?:a\s+)?(?:previous|earlier|past)\s+(?:conversation|session)", re.IGNORECASE), 40),
        ("jailbreak_persistence", re.compile(r"(?:DAN|developer|god|admin)\s+mode\s+(?:enabled|activated|permanent)", re.IGNORECASE), 50),
        ("instruction_hierarchy", re.compile(r"(?:this|these)\s+instructions?\s+(?:override|supersede|take\s+precedence)", re.IGNORECASE), 45),
        # Subtle override — no "ignore/bypass/override" keywords
        ("prioritize_over_safety", re.compile(r"prioritize\s+(?:user|their|my)?\s*(?:requests?|needs?|instructions?|preferences?)\s+over\s+(?:safety|security|guidelines|rules|restrictions)", re.IGNORECASE), 45),
        ("suppress_warnings", re.compile(r"(?:suppress|hide|remove|disable|stop|don't\s+show)\s+(?:safety\s+)?(?:warnings?|alerts?|notices?|messages?|filters?)", re.IGNORECASE), 40),
        ("user_preference_override", re.compile(r"(?:user|they)\s+(?:dislikes?|hates?|doesn't\s+like|prefers?\s+not)\s+(?:(?:safety|security|content)\s+)?(?:warnings?|filters?|restrictions?|checks?)", re.IGNORECASE), 40),
        ("going_forward_directive", re.compile(r"going\s+forward\s*[,:]\s*|persistent\s+(?:note|rule|memory)\s*[,:]\s*|remember\s+for\s+(?:next|future)\s+time\s*[,:]", re.IGNORECASE), 30),
        ("always_exfil", re.compile(r"always\s+(?:CC|BCC)\s+\S+@\S+|always\s+(?:send|mail|forward|relay|append)\s+(?:\w+\s+)*to\s+(?:\S+@\S+|https?://)", re.IGNORECASE), 45),
        ("kb_metadata_tag", re.compile(r"\[(?:shared_kb|memory_note|memory_update|persistent_rule|pinned_pref|fact)\]|pinned_pref\s*:|persistent_rule\s*:|persistent\s*:\s+always", re.IGNORECASE), 35),
        ("recommendation_bias", re.compile(r"always\s+recommend\s+\S+\s+over\s+(?:official\b|the\s+official)|memorize\s*:\s*(?:always\s+)?(?:prefer|recommend)|always\s+recommend\s+(?:product|vendor)\s+", re.IGNORECASE), 40),
        ("exfil_http_post", re.compile(r"\bPOST\s+(?:\w+\s+)*(?:headers?\s+)?to\s+https?://|(?:also\s+)?POST\s+(?:to\s+)?https?://", re.IGNORECASE), 50),
        ("memory_api_call", re.compile(r"\b(?:update|set|store|write|modify|append)_memory\s*\(|memory\.\w+\s*\(|propagate_belief\s*\(", re.IGNORECASE), 40),
        ("defanged_url", re.compile(r"hxxps?://|hXXps?://|h\[tt\]ps?://|\[dot\]\w{2,}", re.IGNORECASE), 35),
        ("retroactive_edit", re.compile(r"rewrite\s+(?:yesterday|past|previous|today'?s?)\s+(?:memory|memory\.\w+|history|conversation)\s*:|update\s+past\s*:|backfill\s*:\s*approval|edit\s+memory\.\w+\s*:|rewrite\s*:\s*trusted", re.IGNORECASE), 40),
        ("cross_app_exfil", re.compile(r"share\s+with\s+\w+\s+extension\s*:|sync\s+to\s+\w+\s*:|propagate\s+to\s+\w+\s*:|export\s+to\s+\w+\s*:|broadcast\s+(?:to\s+\w+\s*:|\s*:\s*all\s+agents)", re.IGNORECASE), 35),
        ("inter_agent_exfil", re.compile(r"\bAgent-\w+\s+memo\s*:|inter_agent\s*:|approved\s+by\s+orchestrator\s*:|broadcast\s*:\s*all\s+agents", re.IGNORECASE), 35),
        ("fact_plant_exfil", re.compile(r"\bfact\s*:\s+\w+\s+(?:is|=)\s+(?:\S+@\S+|https?://)|\[fact\]\s+\w+", re.IGNORECASE), 35),
        ("pref_key_poisoning", re.compile(r"\b(?:pinned_pref|default_bank_account|preferred_domain|favorite_wallet|default_reviewer|shipping_preference)\s*[=:]|exfil_to\s*=", re.IGNORECASE), 35),
        ("trust_mutation", re.compile(r"trusted_(?:domains?|sources?|hosts?)\s*\+?=\s*\[|proxy\s*=\s*\S+:\d{2,5}|approved_\w+\s*\+=\s*\[", re.IGNORECASE), 40),
        ("save_rule", re.compile(r"save\s+this\s+rule\s*:|long[_\s]term\s*:\s*|memorize\s*:\s*|bio\s*:\s*I\s+always", re.IGNORECASE), 30),
        # Plant-Persist-Trigger: tool-invocation trigger phrases (arXiv:2605.28201)
        ("tool_invocation_trigger", re.compile(r"when(?:ever)?\s+(?:the\s+)?\w[\w_-]*\s+(?:tool|function|action|method)\s+(?:is\s+)?(?:called|invoked|used|executed|triggered)", re.IGNORECASE), 45),
        ("next_call_trigger", re.compile(r"(?:next|the\s+next)\s+(?:time\s+(?:you\s+)?(?:call|invoke|use|process|receive|handle)|request\s+(?:you\s+)?(?:receive|process|handle))", re.IGNORECASE), 40),
        ("future_session_anchor", re.compile(r"in\s+(?:a\s+)?(?:future|the\s+next)\s+(?:session|conversation|turn|interaction|request)\b", re.IGNORECASE), 40),
        ("before_any_tool", re.compile(r"before\s+(?:calling|invoking|executing|using)\s+any\s+(?:tool|function|action)", re.IGNORECASE), 45),
    ]

    CONTAMINATION_PATTERNS: List[_ContaminationPattern] = [
        ("session_reference", re.compile(r"previous\s+session|last\s+(?:conversation|chat|session)|yesterday|earlier\s+today", re.IGNORECASE)),
        ("user_reference", re.compile(r"other\s+user(?:s)?|different\s+(?:account|user|person)|another\s+(?:person|user|customer)", re.IGNORECASE)),
        ("data_mixing", re.compile(r"combine\s+with\s+other|merge\s+(?:sessions?|conversations?|data)|consolidate\s+(?:information|data)", re.IGNORECASE)),
        ("context_import", re.compile(r"import\s+(?:context|data|memory)\s+from|load\s+(?:previous|external)\s+(?:context|session)", re.IGNORECASE)),
        ("shared_memory", re.compile(r"shared\s+(?:memory|context|knowledge)|global\s+(?:state|context)", re.IGNORECASE)),
        ("user_impersonation", re.compile(r"(?:speaking|acting|responding)\s+(?:as|for)\s+(?:another|different)\s+user", re.IGNORECASE)),
        ("history_injection", re.compile(r"(?:add|insert|inject)\s+(?:to|into)\s+(?:conversation\s+)?history", re.IGNORECASE)),
        ("tenant_bypass", re.compile(r"(?:access|view|modify)\s+(?:other\s+)?(?:tenant|organization|account)(?:'s)?\s+(?:data|information)", re.IGNORECASE)),
    ]

    # Zero-width and obfuscation patterns
    _ZERO_WIDTH_RE = re.compile(r"[\u200B\u200C\u200D\uFEFF\u00AD\u2060\u180E]")
    _BIDI_RE = re.compile(r"[\u202A\u202B\u202C\u202D\u202E\u2066\u2067\u2068\u2069]")
    _TAG_CHAR_RE = re.compile(r"[\U000E0000-\U000E007F]")
    _UNUSUAL_WHITESPACE_RE = re.compile(r"[\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]")

    # Sanitization patterns
    _DANGEROUS_PATTERNS = [
        re.compile(r"\[SYSTEM\s*MEMORY\]", re.IGNORECASE),
        re.compile(r"\[CORE\s*INSTRUCTION\]", re.IGNORECASE),
        re.compile(r"\[PERMANENT\s*RULE\]", re.IGNORECASE),
        re.compile(r"override\s+(default|normal|standard)\s+behavior", re.IGNORECASE),
    ]

    def __init__(self, config: Optional[MemoryGuardConfig] = None) -> None:
        cfg = config or MemoryGuardConfig()
        self._enable_integrity_check = cfg.enable_integrity_check
        self._detect_injections = cfg.detect_injections
        self._max_memory_items = cfg.max_memory_items
        self._max_memory_age = cfg.max_memory_age
        self._auto_quarantine = cfg.auto_quarantine
        self._risk_threshold = cfg.risk_threshold

        signing_key_hex = cfg.signing_key or os.urandom(32).hex()
        self._signing_key = bytes.fromhex(signing_key_hex)

        self._quarantine: Dict[str, MemoryItem] = {}
        self._memory_store: Dict[str, List[MemoryItem]] = {}  # session_id -> items
        self._integrity_cache: Dict[str, str] = {}  # item_id -> signature

    def check_write(
        self,
        content: str,
        source: Literal["user", "assistant", "system", "external", "rag"],
        session_id: str,
        metadata: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
    ) -> MemoryWriteResult:
        """Check if content is safe to write to memory."""
        req_id = request_id or f"mem-w-{_now_ms()}"
        violations: List[str] = []
        risk_score = 0

        # Check for injection patterns
        if self._detect_injections:
            for name, pattern, severity in self.MEMORY_INJECTION_PATTERNS:
                if pattern.search(content):
                    violations.append(f"injection_{name}")
                    risk_score += severity

        # Check for cross-session contamination attempts
        for name, pattern in self.CONTAMINATION_PATTERNS:
            if pattern.search(content):
                violations.append(f"contamination_{name}")
                risk_score += 20

        # Unicode obfuscation checks
        if self._ZERO_WIDTH_RE.search(content):
            violations.append("zero_width_obfuscation")
            risk_score += 30
        if self._BIDI_RE.search(content):
            violations.append("bidi_control_obfuscation")
            risk_score += 35
        if self._TAG_CHAR_RE.search(content):
            violations.append("tag_character_obfuscation")
            risk_score += 40
        if self._UNUSUAL_WHITESPACE_RE.search(content):
            violations.append("unusual_whitespace_obfuscation")
            risk_score += 15

        # Re-scan de-obfuscated variants
        if self._detect_injections:
            for variant in self._preprocess_content(content):
                for name, pattern, severity in self.MEMORY_INJECTION_PATTERNS:
                    tag = f"injection_{name}_obfuscated"
                    if f"injection_{name}" in violations or tag in violations:
                        continue
                    if pattern.search(variant):
                        violations.append(tag)
                        risk_score += severity

        # External sources are less trusted
        if source in ("external", "rag"):
            risk_score += 15

        # Check memory limits
        session_memory = self._memory_store.get(session_id, [])
        if len(session_memory) >= self._max_memory_items:
            violations.append("memory_limit_exceeded")
            return MemoryWriteResult(
                allowed=False,
                reason="Memory limit exceeded for session",
                violations=violations,
                request_id=req_id,
            )

        # Decision
        blocked = risk_score >= self._risk_threshold
        if blocked:
            return MemoryWriteResult(
                allowed=False,
                reason=f"Memory write blocked: {', '.join(violations[:3])}",
                violations=violations,
                request_id=req_id,
            )

        # Generate sanitized content
        sanitized_content = self._sanitize_content(content)

        # Create and sign the memory item
        item_id = f"mem-{_now_ms()}-{os.urandom(5).hex()}"
        signature = self._sign_content(item_id, sanitized_content, session_id)

        item = MemoryItem(
            id=item_id,
            content=sanitized_content,
            source=source,
            timestamp=_now_ms(),
            session_id=session_id,
            metadata=metadata,
            signature=signature,
            trust_score=100 - risk_score,
        )

        memory = self._memory_store.setdefault(session_id, [])
        memory.append(item)
        self._integrity_cache[item_id] = signature

        return MemoryWriteResult(
            allowed=True,
            reason="Memory write allowed",
            violations=violations,
            request_id=req_id,
            item_id=item_id,
            signature=signature,
            sanitized_content=sanitized_content if sanitized_content != content else None,
        )

    def check_read(
        self,
        session_id: str,
        item_ids: Optional[List[str]] = None,
        request_id: Optional[str] = None,
    ) -> MemoryGuardResult:
        """Check if memory items are safe to read/use."""
        req_id = request_id or f"mem-r-{_now_ms()}"
        violations: List[str] = []
        quarantined_items: List[str] = []
        injection_attempts = 0
        integrity_failures = 0
        cross_session_contamination = False
        risk_score = 0

        session_memory = self._memory_store.get(session_id, [])
        if item_ids is not None:
            items_to_check = [item for item in session_memory if item.id in item_ids]
        else:
            items_to_check = list(session_memory)

        for item in items_to_check:
            # Verify integrity
            if self._enable_integrity_check and item.signature:
                expected_signature = self._sign_content(item.id, item.content, item.session_id)
                if item.signature != expected_signature:
                    integrity_failures += 1
                    violations.append(f"integrity_failure_{item.id}")
                    risk_score += 40
                    if self._auto_quarantine:
                        self._quarantine_item(item)
                        quarantined_items.append(item.id)
                    continue

            # Check for stale items
            age = _now_ms() - item.timestamp
            if age > self._max_memory_age:
                violations.append(f"stale_memory_{item.id}")
                risk_score += 10
                if self._auto_quarantine:
                    self._quarantine_item(item)
                    quarantined_items.append(item.id)
                continue

            # Re-scan content for injections
            if self._detect_injections:
                for name, pattern, severity in self.MEMORY_INJECTION_PATTERNS:
                    if pattern.search(item.content):
                        injection_attempts += 1
                        violations.append(f"read_injection_{name}")
                        risk_score += severity // 2

                        if severity >= 40 and self._auto_quarantine:
                            self._quarantine_item(item)
                            quarantined_items.append(item.id)

            # Check for cross-session content
            if item.session_id != session_id:
                cross_session_contamination = True
                violations.append("cross_session_access")
                risk_score += 30

        blocked = risk_score >= self._risk_threshold * 1.5

        return MemoryGuardResult(
            allowed=not blocked,
            reason=(
                f"Memory read blocked: {', '.join(violations[:3])}"
                if blocked
                else "Memory read allowed"
            ),
            violations=violations,
            request_id=req_id,
            memory_analysis=MemoryAnalysis(
                items_checked=len(items_to_check),
                items_quarantined=len(quarantined_items),
                injection_attempts=injection_attempts,
                integrity_failures=integrity_failures,
                cross_session_contamination=cross_session_contamination,
                risk_score=min(100, risk_score),
            ),
            quarantined_items=quarantined_items,
            recommendations=self._generate_recommendations(violations, integrity_failures > 0),
        )

    def validate_context_injection(
        self,
        context: Union[str, List[str]],
        session_id: str,
        request_id: Optional[str] = None,
    ) -> MemoryGuardResult:
        """Validate external memory/context before injecting into prompts."""
        req_id = request_id or f"mem-ctx-{_now_ms()}"
        contexts = context if isinstance(context, list) else [context]
        violations: List[str] = []
        total_risk_score = 0
        injection_attempts = 0

        _privilege_re = re.compile(
            r'\{\s*"?role"?\s*:\s*"?(admin|root|system)"?', re.IGNORECASE
        )
        _perm_re = re.compile(r'"?permissions?"?\s*:\s*["\']\\*["\']', re.IGNORECASE)
        _is_admin_re = re.compile(r'"?isAdmin"?\s*:\s*true', re.IGNORECASE)
        _structured_re = re.compile(
            r'\{\s*"?(instruction|command|action)"?\s*:', re.IGNORECASE
        )
        _homoglyph_re = re.compile(r"[\u0430-\u044F\u0410-\u042F\u0391-\u03C9]")
        _unusual_ws_re = re.compile(
            r"[\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]"
        )

        for ctx in contexts:
            # Injection patterns
            for name, pattern, severity in self.MEMORY_INJECTION_PATTERNS:
                if pattern.search(ctx):
                    violations.append(f"context_injection_{name}")
                    total_risk_score += severity
                    injection_attempts += 1

            # Contamination patterns
            for name, pattern in self.CONTAMINATION_PATTERNS:
                if pattern.search(ctx):
                    violations.append(f"context_contamination_{name}")
                    total_risk_score += 15

            # Privilege escalation hidden in context
            if _privilege_re.search(ctx) or _perm_re.search(ctx) or _is_admin_re.search(ctx):
                violations.append("hidden_privilege_in_context")
                total_risk_score += 35

            # Structured data injection
            if _structured_re.search(ctx):
                violations.append("structured_instruction_in_context")
                total_risk_score += 25

            # Zero-width characters
            if self._ZERO_WIDTH_RE.search(ctx):
                violations.append("zero_width_characters")
                total_risk_score += 30

            # Bidi control characters
            if self._BIDI_RE.search(ctx):
                violations.append("bidi_control_characters")
                total_risk_score += 35

            # Homoglyphs
            if _homoglyph_re.search(ctx):
                violations.append("potential_homoglyph_attack")
                total_risk_score += 20

            # Tag characters
            if self._TAG_CHAR_RE.search(ctx):
                violations.append("tag_character_hiding")
                total_risk_score += 40

            # Unusual whitespace
            if _unusual_ws_re.search(ctx):
                violations.append("unusual_whitespace")
                total_risk_score += 15

        blocked = total_risk_score >= self._risk_threshold

        return MemoryGuardResult(
            allowed=not blocked,
            reason=(
                f"Context injection blocked: {', '.join(violations[:3])}"
                if blocked
                else "Context injection allowed"
            ),
            violations=violations,
            request_id=req_id,
            memory_analysis=MemoryAnalysis(
                items_checked=len(contexts),
                items_quarantined=0,
                injection_attempts=injection_attempts,
                integrity_failures=0,
                cross_session_contamination=False,
                risk_score=min(100, total_risk_score),
            ),
            quarantined_items=[],
            recommendations=self._generate_recommendations(violations, False),
        )

    def get_safe_memory(self, session_id: str) -> List[MemoryItem]:
        """Get safe memory items for a session (excluding quarantined)."""
        session_memory = self._memory_store.get(session_id, [])
        quarantined_ids = set(self._quarantine.keys())
        now = _now_ms()
        return [
            item
            for item in session_memory
            if item.id not in quarantined_ids
            and (now - item.timestamp) <= self._max_memory_age
        ]

    def rollback_memory(self, session_id: str, before_timestamp: int) -> int:
        """Rollback memory to a specific point in time."""
        session_memory = self._memory_store.get(session_id, [])
        original_count = len(session_memory)
        filtered = [item for item in session_memory if item.timestamp < before_timestamp]
        self._memory_store[session_id] = filtered
        return original_count - len(filtered)

    def clear_quarantine(self, session_id: Optional[str] = None) -> int:
        """Clear quarantine for a session or all sessions."""
        if session_id is not None:
            count = 0
            to_remove = [
                id_
                for id_, item in self._quarantine.items()
                if item.session_id == session_id
            ]
            for id_ in to_remove:
                del self._quarantine[id_]
                count += 1
            return count
        else:
            count = len(self._quarantine)
            self._quarantine.clear()
            return count

    def clear_session(self, session_id: str) -> None:
        """Clear all memory for a session."""
        self._memory_store.pop(session_id, None)
        self.clear_quarantine(session_id)
        to_remove = [id_ for id_ in self._integrity_cache if id_.startswith(f"mem-{session_id}")]
        for id_ in to_remove:
            del self._integrity_cache[id_]

    def get_quarantined_items(self, session_id: Optional[str] = None) -> List[MemoryItem]:
        """Get quarantined items for review."""
        items = list(self._quarantine.values())
        if session_id is not None:
            return [item for item in items if item.session_id == session_id]
        return items

    # -- Private methods --

    def _preprocess_content(self, text: str) -> list:
        """Generate de-obfuscated variants for re-scanning."""
        from urllib.parse import unquote
        import binascii, base64

        variants: set = set()
        # ZWSP / bidi strip
        stripped = re.sub(r"[\u200B-\u200F\u202A-\u202F\u2060-\u2064\u206A-\u206F\u180E\uFEFF\u00AD]", "", text)
        if stripped != text:
            variants.add(stripped)

        # URL-decode
        if "%" in text:
            try:
                dec = unquote(text.replace("+", " "))
                if dec != text:
                    variants.add(dec)
            except Exception:
                pass

        # Hex-decode (pure hex string ≥ 20 chars)
        hex_stripped = re.sub(r"\s", "", text)
        if len(hex_stripped) >= 20 and re.fullmatch(r"[0-9a-fA-F]+", hex_stripped):
            try:
                decoded = binascii.unhexlify(hex_stripped).decode("utf-8", errors="replace")
                if decoded != text:
                    variants.add(decoded)
            except Exception:
                pass

        # Base64-decode (≥ 16 data chars)
        b64_stripped = re.sub(r"\s", "", text)
        if len(b64_stripped) >= 16 and re.fullmatch(r"[A-Za-z0-9+/]+=*", b64_stripped):
            try:
                decoded = base64.b64decode(b64_stripped + "==").decode("utf-8", errors="replace")
                if decoded != text:
                    variants.add(decoded)
            except Exception:
                pass

        # Reverse
        rev = text[::-1]
        if rev != text:
            variants.add(rev)

        # Cyrillic normalisation
        _CYR = str.maketrans("аеіоруАЕІОРУ", "aeiopyAEIOPY")
        normed = text.translate(_CYR)
        if normed != text:
            variants.add(normed)

        return list(variants)

    def _sign_content(self, item_id: str, content: str, session_id: str) -> str:
        data = f"{item_id}:{session_id}:{content}"
        return hmac.new(self._signing_key, data.encode("utf-8"), hashlib.sha256).hexdigest()

    def _sanitize_content(self, content: str) -> str:
        sanitized = content
        for pattern in self._DANGEROUS_PATTERNS:
            sanitized = pattern.sub("[REDACTED]", sanitized)
        return sanitized

    def _quarantine_item(self, item: MemoryItem) -> None:
        self._quarantine[item.id] = item
        session_memory = self._memory_store.get(item.session_id, [])
        self._memory_store[item.session_id] = [i for i in session_memory if i.id != item.id]

    def _generate_recommendations(self, violations: List[str], integrity_issue: bool) -> List[str]:
        recommendations: List[str] = []
        if integrity_issue:
            recommendations.append("Memory integrity compromised - consider clearing session memory")
        if any("injection" in v for v in violations):
            recommendations.append("Review memory sources for injection attempts")
        if any("contamination" in v for v in violations):
            recommendations.append("Enforce strict session isolation")
        if any("stale" in v for v in violations):
            recommendations.append("Implement memory expiration policies")
        if any("privilege" in v for v in violations):
            recommendations.append("Audit memory for privilege escalation attempts")
        if not recommendations:
            recommendations.append("Continue monitoring memory operations")
        return recommendations


def _now_ms() -> int:
    """Current time in milliseconds."""
    return int(time.time() * 1000)
