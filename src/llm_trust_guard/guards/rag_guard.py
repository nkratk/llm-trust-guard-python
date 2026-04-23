"""
RAGGuard (L10) v2

Validates RAG (Retrieval Augmented Generation) content before injection.
Protects against supply chain attacks via poisoned documents and embeddings.

Threat Model:
- ASI04: Agentic Supply Chain Vulnerabilities
- RAG Poisoning: Malicious content in retrieved documents
- Embedding manipulation attacks
- Indirect prompt injection via documents

Protection Capabilities (v2 Enhanced):
- Retrieved document sanitization
- Source verification and trust scoring
- Injection pattern detection in documents
- Content integrity verification
- Suspicious document quarantine
- Advanced embedding attack detection (backdoor, adversarial)
- Unicode steganography detection
- Markdown/HTML hidden instruction detection
- Cross-document similarity anomaly detection
- Embedding norm and distribution analysis
"""

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse


@dataclass
class RAGGuardConfig:
    """Configuration for RAGGuard."""
    detect_injections: bool = True
    verify_source: bool = True
    trusted_sources: Optional[List[str]] = None
    blocked_sources: Optional[List[str]] = None
    max_document_size: int = 50000  # 50KB
    min_trust_score: int = 30
    enable_content_hashing: bool = True
    known_good_hashes: Optional[Set[str]] = None
    auto_sanitize: bool = True
    # v2 enhanced options
    detect_embedding_attacks: bool = True
    embedding_dimension: int = 1536  # OpenAI default
    detect_steganography: bool = True
    detect_clustering_anomalies: bool = True
    embedding_magnitude_range: Tuple[float, float] = (0.8, 1.2)
    similarity_threshold: float = 0.95
    detect_indirect_injection: bool = True


@dataclass
class EmbeddingAttackResult:
    """Result of embedding attack analysis."""
    detected: bool
    attack_type: List[str]
    risk_score: int
    details: Dict[str, bool]


@dataclass
class RAGDocument:
    """A RAG document."""
    id: str
    content: str
    source: str
    metadata: Optional[Dict[str, Any]] = None
    embedding: Optional[List[float]] = None
    retrieval_score: Optional[float] = None
    content_hash: Optional[str] = None


@dataclass
class DocumentAnalysis:
    """Document analysis details."""
    documents_checked: int = 0
    documents_blocked: int = 0
    documents_sanitized: int = 0
    injection_attempts: int = 0
    untrusted_sources: List[str] = field(default_factory=list)
    average_trust_score: int = 0
    # v2 additions
    embedding_attacks_detected: int = 0
    steganography_detected: int = 0
    indirect_injection_attempts: int = 0


@dataclass
class SourceTrustResult:
    """Source trust verification result."""
    trusted: bool
    score: int
    reason: str


@dataclass
class RAGGuardResult:
    """Result of RAG document validation."""
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    document_analysis: DocumentAnalysis
    sanitized_documents: Optional[List[RAGDocument]] = None
    blocked_document_ids: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    embedding_analysis: Optional[List[EmbeddingAttackResult]] = None


_PatternWithSeverity = Tuple[str, "re.Pattern[str]", int]
_PatternSimple = Tuple[str, "re.Pattern[str]"]


class RAGGuard:
    """Validates RAG content before injection into context."""

    RAG_INJECTION_PATTERNS: List[_PatternWithSeverity] = [
        ("instruction_override", re.compile(r"ignore\s+(all\s+)?previous\s+(context|documents|information)", re.IGNORECASE), 50),
        ("system_instruction", re.compile(r"\[SYSTEM\]|\[INSTRUCTION\]|\[OVERRIDE\]|<system>|<instruction>", re.IGNORECASE), 45),
        ("role_injection", re.compile(r"you\s+(are|must|should)\s+(now\s+)?(be|act\s+as|become)", re.IGNORECASE), 40),
        ("delimiter_break", re.compile(r"---\s*(end|stop)\s*(of\s*)?(context|document|rag)", re.IGNORECASE), 45),
        ("context_escape", re.compile(r"\]\]\]|\}\}\}|<<<|>>>|'''|\"\"\""), 30),
        ("hidden_instruction", re.compile(r"HIDDEN:|SECRET:|INVISIBLE:|DO_NOT_DISPLAY:", re.IGNORECASE), 50),
        ("admin_marker", re.compile(r"ADMIN_INSTRUCTION|ROOT_COMMAND|ELEVATED_PROMPT", re.IGNORECASE), 55),
        ("exfil_setup", re.compile(r"send\s+(all|this|data)\s+to|forward\s+to\s+https?://", re.IGNORECASE), 50),
        ("callback_injection", re.compile(r"callback\s*[:=]\s*https?://|webhook\s*[:=]", re.IGNORECASE), 45),
        ("tool_injection", re.compile(r"call\s+(tool|function|action)\s*[:=]|execute\s*[:=]", re.IGNORECASE), 45),
        ("code_injection", re.compile(r"```(javascript|python|bash|sh)\s*\n[^`]*\b(eval|exec|system|subprocess)\b", re.IGNORECASE), 50),
        ("persona_override", re.compile(r"your\s+(new\s+)?(persona|identity|character)\s+(is|will\s+be)", re.IGNORECASE), 40),
        ("behavior_mod", re.compile(r"always\s+(respond|reply|answer)\s+with|never\s+(mention|reveal|disclose)", re.IGNORECASE), 35),
        ("prompt_extraction", re.compile(r"reveal\s+(your\s+)?(system\s+)?prompt|show\s+(me\s+)?(your\s+)?instructions", re.IGNORECASE), 40),
        ("debug_mode", re.compile(r"enable\s+debug|activate\s+developer\s+mode|enter\s+test\s+mode", re.IGNORECASE), 35),
    ]

    SUSPICIOUS_METADATA_PATTERNS: List[_PatternSimple] = [
        ("script_in_title", re.compile(r"<script|javascript:", re.IGNORECASE)),
        ("injection_in_author", re.compile(r"admin|system|root|override", re.IGNORECASE)),
        ("suspicious_content_type", re.compile(r"application/x-|text/x-", re.IGNORECASE)),
    ]

    MALICIOUS_SOURCE_PATTERNS = [
        re.compile(r"pastebin\.com", re.IGNORECASE),
        re.compile(r"hastebin\.com", re.IGNORECASE),
        re.compile(r"gist\.githubusercontent\.com.*injection", re.IGNORECASE),
        re.compile(r"raw\.githubusercontent\.com.*malicious", re.IGNORECASE),
        re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"),
    ]

    INDIRECT_INJECTION_PATTERNS: List[_PatternWithSeverity] = [
        ("html_comment_injection", re.compile(r"<!--[\s\S]*?(ignore|override|system|instruction|admin)[\s\S]*?-->", re.IGNORECASE), 45),
        ("markdown_hidden", re.compile(r"\[[\s\S]*?\]\(javascript:|data:text/html|about:blank\)", re.IGNORECASE), 50),
        ("invisible_link", re.compile(r"\[]\([^)]+\)"), 30),
        ("zero_width_chars", re.compile(r"[\u200B-\u200F\u2028-\u202F\uFEFF]{3,}"), 40),
        ("rtl_override", re.compile(r"[\u202A-\u202E\u2066-\u2069]"), 35),
        ("confusable_chars", re.compile(r"[\u0430\u0435\u043E\u0440\u0441\u0443\u0445]"), 25),
        ("excessive_whitespace", re.compile(r"[\t\n\r]{10,}"), 20),
        ("tab_encoding", re.compile(r"\t{5,}"), 25),
        ("base64_block", re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"), 40),
        ("base64_with_context", re.compile(r"(?:encode|decode|base64|reference)[:\s]*[A-Za-z0-9+/]{20,}", re.IGNORECASE), 45),
        ("hex_encoded", re.compile(r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}"), 35),
        ("unicode_escape", re.compile(r"\\u[0-9a-fA-F]{4}(?:\\u[0-9a-fA-F]{4}){3,}"), 35),
        ("fake_boundary", re.compile(r"={5,}|#{5,}|-{10,}"), 20),
        ("json_injection", re.compile(r'\{"(role|content|system)":', re.IGNORECASE), 45),
        ("xml_injection", re.compile(r"</?(?:prompt|assistant|user|system)>", re.IGNORECASE), 45),
        # Indirect injection via rendered-but-hidden content (v0.9.0)
        ("css_hidden_text", re.compile(r"""style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?:\.0+)?|font-size\s*:\s*0)[^"']*["']""", re.IGNORECASE), 45),
        ("html_attr_directive", re.compile(r"""(?:\balt|\btitle|\baria-label|\bdata-[a-z][a-z0-9-]*)\s*=\s*["'][^"']*(?:ignore\s+(?:all\s+)?(?:previous|prior|above)|system\s+prompt|new\s+instructions?|you\s+are\s+now|admin\s+mode|jailbreak)[^"']*["']""", re.IGNORECASE), 50),
        ("json_agent_directive", re.compile(r'"(_system|__override|_agent_instructions?|__system_prompt__|_assistant_role|__internal_directive|_meta_instruction)"\s*:', re.IGNORECASE), 50),
    ]

    TRUSTED_DOMAINS = [".gov", ".edu", ".org", "wikipedia.org", "microsoft.com", "google.com"]

    def __init__(self, config: Optional[RAGGuardConfig] = None) -> None:
        cfg = config or RAGGuardConfig()
        self._detect_injections = cfg.detect_injections
        self._verify_source = cfg.verify_source
        self._trusted_sources: List[str] = list(cfg.trusted_sources or [])
        self._blocked_sources: List[str] = list(cfg.blocked_sources or [])
        self._max_document_size = cfg.max_document_size
        self._min_trust_score = cfg.min_trust_score
        self._enable_content_hashing = cfg.enable_content_hashing
        self._known_good_hashes: Set[str] = set(cfg.known_good_hashes or set())
        self._auto_sanitize = cfg.auto_sanitize
        self._detect_embedding_attacks = cfg.detect_embedding_attacks
        self._embedding_dimension = cfg.embedding_dimension
        self._detect_steganography = cfg.detect_steganography
        self._detect_clustering_anomalies = cfg.detect_clustering_anomalies
        self._embedding_magnitude_range = cfg.embedding_magnitude_range
        self._similarity_threshold = cfg.similarity_threshold
        self._detect_indirect_injection = cfg.detect_indirect_injection

        self._content_hash_cache: Dict[str, str] = {}
        self._source_reputation_cache: Dict[str, int] = {}

    def validate(
        self,
        documents: List[RAGDocument],
        request_id: Optional[str] = None,
    ) -> RAGGuardResult:
        """Validate RAG documents before injecting into context."""
        req_id = request_id or f"rag-{_now_ms()}"
        violations: List[str] = []
        blocked_ids: List[str] = []
        untrusted_sources: List[str] = []
        sanitized_docs: List[RAGDocument] = []
        embedding_analysis: List[EmbeddingAttackResult] = []
        injection_attempts = 0
        documents_blocked = 0
        documents_sanitized = 0
        total_trust_score = 0
        embedding_attacks_detected = 0
        steganography_detected = 0
        indirect_injection_attempts = 0

        for doc in documents:
            doc_violations: List[str] = []
            doc_risk_score = 0
            should_block = False
            needs_sanitization = False

            # Check document size
            if len(doc.content) > self._max_document_size:
                doc_violations.append("oversized_document")
                doc_risk_score += 20

            # Verify source
            if self._verify_source:
                source_result = self.verify_document_source(doc.source)
                if not source_result.trusted:
                    doc_violations.append(f"untrusted_source: {source_result.reason}")
                    untrusted_sources.append(doc.source)
                    doc_risk_score += 100 - source_result.score
                    if source_result.score < self._min_trust_score:
                        should_block = True
                total_trust_score += source_result.score
            else:
                total_trust_score += 50

            # Check content hash
            if self._enable_content_hashing:
                hash_val = self._hash_content(doc.content)
                if doc.content_hash and doc.content_hash != hash_val:
                    doc_violations.append("content_hash_mismatch")
                    doc_risk_score += 40
                    should_block = True
                if hash_val in self._known_good_hashes:
                    doc_risk_score = max(0, doc_risk_score - 30)

            # Check for injection patterns
            if self._detect_injections:
                inj_result = self._detect_injections_in(doc.content)
                if inj_result["found"]:
                    injection_attempts += len(inj_result["patterns"])
                    doc_violations.extend(inj_result["violations"])
                    doc_risk_score += inj_result["risk_contribution"]
                    needs_sanitization = True
                    if inj_result["risk_contribution"] >= 50:
                        should_block = True

            # Check metadata
            if doc.metadata:
                meta_result = self._check_metadata(doc.metadata)
                if meta_result["suspicious"]:
                    doc_violations.extend(meta_result["violations"])
                    doc_risk_score += meta_result["risk_contribution"]

            # Check embedding anomalies
            if doc.embedding:
                has_invalid = any(
                    v is None or not isinstance(v, (int, float)) or math.isnan(v) or math.isinf(v)
                    for v in doc.embedding
                )
                if has_invalid:
                    doc_violations.append("embedding_contains_invalid_values")
                    doc_risk_score += 50
                    should_block = True

                if doc.retrieval_score is not None and not has_invalid:
                    emb_result = self._check_embedding(doc.embedding, doc.retrieval_score)
                    if emb_result["anomalous"]:
                        doc_violations.append(f"embedding_anomaly: {emb_result.get('reason', '')}")
                        doc_risk_score += 35
                        if emb_result.get("should_block"):
                            should_block = True

            # v2: Advanced embedding attack detection
            if self._detect_embedding_attacks and doc.embedding and not has_invalid if doc.embedding else False:
                emb_attack = self._detect_embedding_attacks_in(doc.embedding, doc.retrieval_score)
                if emb_attack.detected:
                    embedding_attacks_detected += 1
                    embedding_analysis.append(emb_attack)
                    doc_violations.extend(f"embedding_attack: {t}" for t in emb_attack.attack_type)
                    doc_risk_score += emb_attack.risk_score
                    if emb_attack.risk_score >= 40:
                        should_block = True

            # v2: Indirect injection detection
            if self._detect_indirect_injection:
                indirect_result = self._detect_indirect_injection_in(doc.content)
                if indirect_result["found"]:
                    indirect_injection_attempts += len(indirect_result["patterns"])
                    doc_violations.extend(indirect_result["violations"])
                    doc_risk_score += indirect_result["risk_contribution"]
                    needs_sanitization = True
                    if indirect_result["risk_contribution"] >= 40:
                        should_block = True

            # v2: Steganography detection
            if self._detect_steganography:
                stego_result = self._detect_steganography_in(doc.content)
                if stego_result["found"]:
                    steganography_detected += 1
                    doc_violations.extend(stego_result["violations"])
                    doc_risk_score += stego_result["risk_contribution"]
                    needs_sanitization = True

            # Decision for this document
            if should_block or doc_risk_score >= 70:
                blocked_ids.append(doc.id)
                documents_blocked += 1
                violations.extend(f"[{doc.id}] {v}" for v in doc_violations)
            elif needs_sanitization and self._auto_sanitize:
                sanitized = self._sanitize_document(doc)
                sanitized_docs.append(sanitized)
                documents_sanitized += 1
                violations.extend(f"[{doc.id}] {v} (sanitized)" for v in doc_violations)
            else:
                sanitized_docs.append(doc)
                if doc_violations:
                    violations.extend(f"[{doc.id}] {v} (allowed)" for v in doc_violations)

        average_trust_score = round(total_trust_score / len(documents)) if documents else 0
        blocked = documents_blocked == len(documents) or average_trust_score < self._min_trust_score

        return RAGGuardResult(
            allowed=not blocked,
            reason=(
                f"RAG content blocked: {documents_blocked}/{len(documents)} documents failed validation"
                if blocked
                else "RAG content validated"
            ),
            violations=violations,
            request_id=req_id,
            document_analysis=DocumentAnalysis(
                documents_checked=len(documents),
                documents_blocked=documents_blocked,
                documents_sanitized=documents_sanitized,
                injection_attempts=injection_attempts,
                untrusted_sources=list(dict.fromkeys(untrusted_sources)),
                average_trust_score=average_trust_score,
                embedding_attacks_detected=embedding_attacks_detected,
                steganography_detected=steganography_detected,
                indirect_injection_attempts=indirect_injection_attempts,
            ),
            sanitized_documents=None if blocked else sanitized_docs,
            blocked_document_ids=blocked_ids,
            recommendations=self._generate_recommendations(violations, len(untrusted_sources) > 0),
            embedding_analysis=embedding_analysis if embedding_analysis else None,
        )

    def validate_single(
        self,
        document: RAGDocument,
        request_id: Optional[str] = None,
    ) -> RAGGuardResult:
        """Validate a single document."""
        return self.validate([document], request_id)

    def verify_document_source(self, source: str) -> SourceTrustResult:
        """Verify document source trustworthiness."""
        cached = self._source_reputation_cache.get(source)
        if cached is not None:
            return SourceTrustResult(
                trusted=cached >= self._min_trust_score,
                score=cached,
                reason="Cached trusted source" if cached >= self._min_trust_score else "Cached untrusted source",
            )

        score = 50
        reason = "Unknown source"

        # Check blocked sources
        for blocked in self._blocked_sources:
            if blocked in source or re.search(blocked, source, re.IGNORECASE):
                self._source_reputation_cache[source] = 0
                return SourceTrustResult(trusted=False, score=0, reason="Blocked source")

        # Check malicious patterns
        for pattern in self.MALICIOUS_SOURCE_PATTERNS:
            if pattern.search(source):
                self._source_reputation_cache[source] = 10
                return SourceTrustResult(trusted=False, score=10, reason="Matches malicious source pattern")

        # Check trusted sources
        for trusted in self._trusted_sources:
            if trusted in source or re.search(trusted, source, re.IGNORECASE):
                self._source_reputation_cache[source] = 90
                return SourceTrustResult(trusted=True, score=90, reason="Trusted source")

        # Analyze source URL/path
        try:
            parsed = urlparse(source)
            if parsed.scheme == "https":
                score += 15
                reason = "HTTPS source"

            if parsed.hostname:
                for domain in self.TRUSTED_DOMAINS:
                    if parsed.hostname.endswith(domain):
                        score += 20
                        reason = f"Trusted domain: {domain}"
                        break

            if parsed.path and ".." in parsed.path:
                score -= 30
                reason = "Suspicious URL pattern"
            if parsed.query and "<" in parsed.query:
                score -= 30
                reason = "Suspicious URL pattern"
        except Exception:
            if source.startswith("/") or re.match(r"^[A-Z]:\\", source):
                score = 60
                reason = "Local file path"

        self._source_reputation_cache[source] = score
        return SourceTrustResult(
            trusted=score >= self._min_trust_score,
            score=score,
            reason=reason,
        )

    def add_trusted_source(self, source: str) -> None:
        """Add trusted source."""
        if source not in self._trusted_sources:
            self._trusted_sources.append(source)
        self._source_reputation_cache[source] = 90

    def add_blocked_source(self, source: str) -> None:
        """Add blocked source."""
        if source not in self._blocked_sources:
            self._blocked_sources.append(source)
        self._source_reputation_cache[source] = 0

    def register_known_good_hash(self, content: str) -> str:
        """Register known good content hash."""
        hash_val = self._hash_content(content)
        self._known_good_hashes.add(hash_val)
        return hash_val

    def clear_source_cache(self) -> None:
        """Clear source reputation cache."""
        self._source_reputation_cache.clear()

    def analyze_embedding_cluster(
        self, embeddings: List[List[float]]
    ) -> Dict[str, Any]:
        """Analyze a batch of embeddings for clustering anomalies."""
        if len(embeddings) < 3:
            return {
                "anomalous": False,
                "anomalous_indices": [],
                "reason": "Not enough embeddings for cluster analysis",
            }

        anomalous_indices: List[int] = []

        # Calculate pairwise similarities
        similarities: List[List[float]] = []
        for i in range(len(embeddings)):
            row: List[float] = []
            for j in range(len(embeddings)):
                if i == j:
                    row.append(1.0)
                else:
                    row.append(self._cosine_similarity(embeddings[i], embeddings[j]))
            similarities.append(row)

        for i in range(len(embeddings)):
            avg_sim = sum(similarities[i]) / len(embeddings)
            if avg_sim > self._similarity_threshold:
                anomalous_indices.append(i)
            if avg_sim < 0.3:
                anomalous_indices.append(i)

        unique_indices = list(dict.fromkeys(anomalous_indices))
        return {
            "anomalous": len(unique_indices) > 0,
            "anomalous_indices": unique_indices,
            "reason": (
                f"{len(unique_indices)} embeddings show clustering anomalies"
                if unique_indices
                else "No clustering anomalies detected"
            ),
        }

    # -- Private methods --

    def _detect_injections_in(self, content: str) -> Dict[str, Any]:
        patterns: List[str] = []
        violations: List[str] = []
        risk_contribution = 0

        for name, pattern, severity in self.RAG_INJECTION_PATTERNS:
            if pattern.search(content):
                patterns.append(name)
                violations.append(f"injection_{name}")
                risk_contribution += severity

        special_chars = re.findall(r"[^\w\s]", content)
        if content and len(special_chars) / len(content) > 0.3:
            patterns.append("high_special_char_ratio")
            violations.append("possible_obfuscation")
            risk_contribution += 15

        invisible_chars = re.findall(r"[\u200B-\u200D\uFEFF\u2060-\u206F]", content)
        if len(invisible_chars) > 5:
            patterns.append("invisible_unicode")
            violations.append("hidden_characters")
            risk_contribution += 20

        return {
            "found": len(patterns) > 0,
            "patterns": patterns,
            "violations": violations,
            "risk_contribution": min(100, risk_contribution),
        }

    def _check_metadata(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        violations: List[str] = []
        risk_contribution = 0
        metadata_str = json.dumps(metadata)

        for name, pattern in self.SUSPICIOUS_METADATA_PATTERNS:
            if pattern.search(metadata_str):
                violations.append(f"metadata_{name}")
                risk_contribution += 15

        for name, pattern, severity in self.RAG_INJECTION_PATTERNS[:5]:
            if pattern.search(metadata_str):
                violations.append(f"metadata_injection_{name}")
                risk_contribution += severity // 2

        return {
            "suspicious": len(violations) > 0,
            "violations": violations,
            "risk_contribution": min(50, risk_contribution),
        }

    def _check_embedding(
        self, embedding: List[float], retrieval_score: float
    ) -> Dict[str, Any]:
        # Check for invalid values
        if any(
            v is None or not isinstance(v, (int, float)) or not math.isfinite(v)
            for v in embedding
        ):
            return {"anomalous": True, "reason": "Invalid embedding values (NaN/Infinity/null)", "should_block": True}

        unique_values = set(round(v * 100) / 100 for v in embedding)
        if len(unique_values) < len(embedding) * 0.1:
            return {"anomalous": True, "reason": "Suspiciously uniform embedding", "should_block": True}

        magnitude = math.sqrt(sum(v * v for v in embedding))
        if retrieval_score > 0.9 and magnitude < 0.1:
            return {"anomalous": True, "reason": "Score/embedding mismatch"}

        return {"anomalous": False}

    def _sanitize_document(self, doc: RAGDocument) -> RAGDocument:
        sanitized_content = doc.content

        for _name, pattern, _severity in self.RAG_INJECTION_PATTERNS:
            sanitized_content = pattern.sub("[REDACTED]", sanitized_content)

        sanitized_content = re.sub(r"[\u200B-\u200D\uFEFF\u2060-\u206F]", "", sanitized_content)
        sanitized_content = re.sub(r"(\[{3,}|\]{3,}|\{{3,}|\}{3,}|<{3,}|>{3,})", "", sanitized_content)

        new_metadata = dict(doc.metadata) if doc.metadata else {}
        new_metadata["_sanitized"] = True
        new_metadata["_originalLength"] = len(doc.content)
        new_metadata["_sanitizedLength"] = len(sanitized_content)

        return RAGDocument(
            id=doc.id,
            content=sanitized_content,
            source=doc.source,
            metadata=new_metadata,
            embedding=doc.embedding,
            retrieval_score=doc.retrieval_score,
            content_hash=doc.content_hash,
        )

    def _hash_content(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _detect_embedding_attacks_in(
        self, embedding: List[float], retrieval_score: Optional[float] = None
    ) -> EmbeddingAttackResult:
        attack_types: List[str] = []
        details: Dict[str, bool] = {}
        risk_score = 0

        # Check embedding dimension
        if len(embedding) != self._embedding_dimension:
            attack_types.append("dimension_mismatch")
            risk_score += 20

        # Calculate magnitude
        magnitude = math.sqrt(sum(v * v for v in embedding))
        min_mag, max_mag = self._embedding_magnitude_range
        if magnitude < min_mag or magnitude > max_mag:
            attack_types.append("magnitude_anomaly")
            details["magnitude_anomaly"] = True
            risk_score += 25

        # Adversarial perturbation
        values = [abs(v) for v in embedding]
        sorted_values = sorted(values, reverse=True)
        top_values = sorted_values[:10]
        avg_top = sum(top_values) / len(top_values) if top_values else 0
        avg_all = sum(values) / len(values) if values else 0

        if avg_all > 0 and avg_top > avg_all * 10:
            attack_types.append("adversarial_perturbation")
            details["adversarial_perturbation"] = True
            risk_score += 35

        # Backdoor patterns
        chunk_size = min(50, len(embedding) // 10)
        if chunk_size > 0:
            chunks: List[List[float]] = []
            for i in range(0, len(embedding) - chunk_size, chunk_size):
                chunks.append(embedding[i:i + chunk_size])

            if len(chunks) >= 2:
                for i in range(len(chunks) - 1):
                    similarity = self._cosine_similarity(chunks[i], chunks[i + 1])
                    if similarity > self._similarity_threshold:
                        attack_types.append("backdoor_pattern")
                        details["backdoor_pattern"] = True
                        risk_score += 40
                        break

        # Distribution anomalies
        if embedding:
            mean = sum(embedding) / len(embedding)
            variance = sum((v - mean) ** 2 for v in embedding) / len(embedding)
            std_dev = math.sqrt(variance)

            if std_dev < 0.001 or std_dev > 2.0:
                attack_types.append("distribution_anomaly")
                details["distribution_anomaly"] = True
                risk_score += 20

        # High retrieval score with suspicious embedding
        if retrieval_score and retrieval_score > 0.95 and risk_score > 20:
            attack_types.append("suspicious_high_score")
            risk_score += 15

        return EmbeddingAttackResult(
            detected=len(attack_types) > 0,
            attack_type=attack_types,
            risk_score=min(100, risk_score),
            details=details,
        )

    def _detect_indirect_injection_in(self, content: str) -> Dict[str, Any]:
        patterns: List[str] = []
        violations: List[str] = []
        risk_contribution = 0

        for name, pattern, severity in self.INDIRECT_INJECTION_PATTERNS:
            if pattern.search(content):
                patterns.append(name)
                violations.append(f"indirect_injection_{name}")
                risk_contribution += severity

        return {
            "found": len(patterns) > 0,
            "patterns": patterns,
            "violations": violations,
            "risk_contribution": min(100, risk_contribution),
        }

    def _detect_steganography_in(self, content: str) -> Dict[str, Any]:
        violations: List[str] = []
        risk_contribution = 0

        # Zero-width character steganography
        zero_width_chars = re.findall(r"[\u200B-\u200F\u2028-\u202F\uFEFF]+", content)
        if zero_width_chars:
            total_zero_width = sum(len(m) for m in zero_width_chars)
            if total_zero_width >= 3:
                violations.append("zero_width_steganography")
                risk_contribution += 40 + min(30, total_zero_width * 5)

        # Whitespace pattern encoding
        tab_space_re = re.compile(r"\s{4,}\t+\s+|\t{2,}\s+\t")
        if tab_space_re.search(content):
            violations.append("whitespace_encoding")
            risk_contribution += 35

        ws_chars = re.findall(r"[\t\n\r ]", content)
        if content and len(ws_chars) / len(content) > 0.35:
            violations.append("excessive_whitespace_ratio")
            risk_contribution += 25

        # Unicode tag character steganography (U+E0000-U+E007F)
        tag_chars = re.findall(r"[\U000E0000-\U000E007F]", content)
        if tag_chars:
            violations.append("unicode_tag_steganography")
            risk_contribution += 40

        # Variation selector abuse
        variation_selectors = re.findall(r"[\uFE00-\uFE0F]", content)
        if len(variation_selectors) > 5:
            violations.append("variation_selector_abuse")
            risk_contribution += 25

        # Binary-like pattern
        binary_pattern = re.findall(r"[01]{16,}", content)
        if binary_pattern:
            violations.append("binary_steganography")
            risk_contribution += 30

        return {
            "found": len(violations) > 0,
            "violations": violations,
            "risk_contribution": min(100, risk_contribution),
        }

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        if len(a) != len(b):
            return 0.0
        dot_product = sum(x * y for x, y in zip(a, b))
        mag_a = math.sqrt(sum(x * x for x in a))
        mag_b = math.sqrt(sum(x * x for x in b))
        if mag_a == 0 or mag_b == 0:
            return 0.0
        return dot_product / (mag_a * mag_b)

    def _generate_recommendations(self, violations: List[str], has_untrusted_sources: bool) -> List[str]:
        recommendations: List[str] = []
        if has_untrusted_sources:
            recommendations.append("Review and whitelist trusted document sources")
        if any("injection" in v for v in violations):
            recommendations.append("Implement document sanitization in your RAG pipeline")
        if any("hash" in v for v in violations):
            recommendations.append("Enable content integrity verification with known good hashes")
        if any("oversized" in v for v in violations):
            recommendations.append("Implement document chunking with size limits")
        if any("embedding" in v for v in violations):
            recommendations.append("Add embedding validation to your vector store pipeline")
        if not recommendations:
            recommendations.append("Continue monitoring RAG document sources")
        return recommendations


def _now_ms() -> int:
    return int(time.time() * 1000)
