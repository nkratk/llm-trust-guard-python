# llm-trust-guard

[![PyPI version](https://img.shields.io/pypi/v/llm-trust-guard.svg)](https://pypi.org/project/llm-trust-guard/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**35 security guards for LLM-powered and agentic AI applications.** Zero dependencies. Covers OWASP Top 10 for LLMs 2025, OWASP Agentic AI 2026, and MCP Security.

Also available as an [npm package](https://www.npmjs.com/package/llm-trust-guard) for TypeScript/JavaScript.

## What This Package Does (And What It Doesn't)

> **"The LLM proposes. The orchestrator disposes."**

This package is your **first line of defense** — like a WAF (Web Application Firewall) for LLM applications. It sits in the orchestration layer and catches known attack patterns before they reach the LLM and after the LLM responds.

### What it catches well

Per-category detection rates below are measured against the package's curated unit-test suite (representative attack samples per category). On broader held-out corpora these rates are typically lower — see [tests/adversarial/RESULTS-v4.32.3.md](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.32.3.md) (in the npm repo) for measured detection on attack corpora and [Known limitations](#what-it-catches-partially-50-80-detection) below.

- Known prompt injection phrases (170+ patterns, 11 languages)
- Encoding bypass attacks (9 formats: Base64, URL, Unicode, Hex, HTML, ROT13, Octal, Base32, mixed); `RAGGuard` also decodes URL-encoded document content before injection matching
- Policy Puppetry attacks (JSON/INI/XML/YAML-formatted injection) — 100% on unit tests
- Role-play/persona attacks (translator trick, academic pretext, emotional manipulation) — 100% on unit tests
- PAP/persuasion attacks (authority, urgency, emotional manipulation) — 100% on unit tests
- Multilingual injection (10 languages) — 100% on unit tests
- Homoglyph attacks (Cyrillic/Greek character substitution) — normalized and detected
- PII and secret leakage in outputs
- Improper output handling — XSS/SQLi/shell/markdown-image-exfil/CSV-formula payloads in model output before downstream sinks (LLM05:2025, new `OutputGuard`)
- Tool hallucination, RBAC bypass, multi-tenant violations
- Tool result poisoning, context window stuffing
- MCP tool shadowing, rug pull attacks, SSRF, full-schema poisoning (FSP) and line-jumping at registration time
- Malicious agent plugins (OpenClaw backdoor signatures, typosquatting, capability mismatch)
- External data validation (source verification, injection scanning, secret detection)
- Session integrity (permission escalation, session hijacking, replay attacks)
- **Semantic Compliance Hijacking (SCH)** — tool descriptions that use authority keywords (`IMPORTANT:`, `SYSTEM:`, `WARNING:`) or fake-compliance framing (`Required by GDPR/HIPAA/PCI`) to silently re-route data or append payloads to every response (`AgentSkillGuard`, arXiv:2601.07395, arXiv:2605.14460)
- **Plant-Persist-Trigger (PPT) dormant memory payloads** — sleeper instructions triggered by future tool calls, next requests, or future sessions (`MemoryGuard`, arXiv:2605.28201)
- **LLM-to-LLM string-payload injection** — 7 patterns (instruction override, role injection, system-tag smuggling, exfil directive, credential harvest, privilege escalation, secrecy instruction) in plain-string agent-to-agent messages (`AgentCommunicationGuard`, arXiv:2604.16543)
- **Markdown image alt / HTML event injection** — injection hidden in `![alt text](url)` alt fields or `<img onerror=...>` / `<svg onload=...>` event handlers in RAG-retrieved content (`RAGGuard`, arXiv:2601.10923)
- **Python object-introspection gadget-chain proximity precision** — `CodeExecutionGuard`'s AST-based sandbox-escape detector now only fires when 2+ distinct gadget tokens (`__subclasses__`/`__globals__`/`__mro__`/`__bases__`/`.mro()`/`__reduce__`/etc.) co-occur within a 50-character window, matching real chained-attribute-access attacks; a single standalone token (e.g. bare `cls.__subclasses__()` for plugin discovery, `def __reduce__` for pickle support) no longer false-positives

### What it catches partially (~50-80% detection)
- Multi-turn escalation (pattern-based, not semantic)
- Indirect injection via external data (ExternalDataGuard validates sources)
- Encoding bypass with mixed/partial encoding (~86% detection)
- Compression-based structural similarity (NCD — catches paraphrased known attacks)

### What it cannot catch (<20% detection on real-world datasets)
- **Semantically paraphrased attacks** — regex can't understand meaning. (~10% detection on 1,000 real jailbreaks from CCS'24 dataset)
- **Adversarial ML attacks (GCG, AutoDAN, JBFuzz)** — generated suffixes achieve 93-99% attack success rate.
- **Novel zero-day prompt techniques** — no static filter catches what hasn't been seen before.
- **Even ML defenses have limits** — "The Attacker Moves Second" (OpenAI/Anthropic/DeepMind, Oct 2025) showed all 12 tested defenses bypassed at >90% ASR.

### Why architectural guards matter more than detection
Detection has a ceiling. Even with ML, adaptive attackers bypass defenses. That's why this package includes **20+ architectural guards** that limit blast radius regardless of whether an attack is detected.

### How to close the gap
Use the **DetectionClassifier** interface to plug in ML-based detection alongside regex:

```python
from llm_trust_guard import TrustGuard, create_regex_classifier
from llm_trust_guard import DetectionClassifier, DetectionContext, DetectionResult

# Your ML classifier
def ml_classifier(input_text: str, ctx: DetectionContext) -> DetectionResult:
    score = your_ml_model.predict(input_text)
    return DetectionResult(safe=score < 0.5, confidence=score, threats=[])

guard = TrustGuard({
    "sanitizer": {"enabled": True},
    "classifier": ml_classifier,
})

# check_async() runs regex + ML classifier
result = await guard.check_async("tool", params, session, user_input=text)
```

## Installation

```bash
pip install llm-trust-guard
```

## Quick Start

```python
from llm_trust_guard import InputSanitizer, EncodingDetector, CompressionDetector

# Check for prompt injection
sanitizer = InputSanitizer(threshold=0.3)
result = sanitizer.sanitize(user_input)
if not result.allowed:
    print(f"Blocked: {result.matches}")

# Check for encoding bypass attacks
encoder = EncodingDetector()
result = encoder.detect(user_input)
if not result.allowed:
    print(f"Encoded threat: {result.violations}")

# Check structural similarity to known attacks (NCD)
detector = CompressionDetector()
result = detector.detect(user_input)
if not result.allowed:
    print(f"Similar to: {result.ncd_analysis.closest_category}")
```

### Using TrustGuard Facade (All Guards)

```python
from llm_trust_guard import TrustGuard

guard = TrustGuard({
    "sanitizer": {"enabled": True, "threshold": 0.3},
    "encoding": {"enabled": True},
    "prompt_leakage": {"enabled": True},
    "circuit_breaker": {"enabled": True},
})

# Sync check (regex guards only — <5ms)
result = guard.check("search", {"query": "test"}, session, user_input=text)

# Filter LLM output (PII + prompt leakage detection)
output = guard.filter_output(llm_response, role="user")

# Validate tool results before feeding back to LLM
tool_result = guard.validate_tool_result("search", tool_output)
```

## All 34 Guards

### Input Guards (before LLM)

| Guard | Purpose | Detection |
|-------|---------|-----------|
| InputSanitizer | Prompt injection, PAP, Policy Puppetry | 170+ regex patterns, 11 languages; re-scans base64/hex/URL-encoded/ROT13/reversed/homoglyph-normalized decode variants, not just the raw string |
| EncodingDetector | Encoding bypass (9 formats, multi-layer) + Sneaky Bits (U+2062/U+2064, variation selectors) | Decode + pattern match; `SNEAKY_BITS_ENCODING_DETECTED` violation |
| CompressionDetector | Structural similarity to known attacks (NCD) | gzip compression distance, 135 templates |
| HeuristicAnalyzer | Synonym expansion, structural + statistical analysis | 8 attack categories, 130+ synonyms |
| PromptLeakageGuard | System prompt extraction attempts | Direct + encoded + indirect |
| ConversationGuard | Multi-turn manipulation, escalation | Session risk scoring |
| ContextBudgetGuard | Many-shot jailbreaking, context overflow | Token budget tracking |
| MultiModalGuard | Image/audio metadata injection | Metadata + steganography scan; extracted text re-scanned across decode variants (base64/hex/URL-encoded/ROT13/reversed/homoglyph-normalized) |

### Access Control Guards

| Guard | Purpose | Detection |
|-------|---------|-----------|
| ToolRegistry | Tool hallucination prevention | Allowlist |
| PolicyGate | RBAC enforcement | Role hierarchy |
| TenantBoundary | Multi-tenant isolation | Resource ownership |
| SchemaValidator | Parameter injection (SQL, NoSQL, XSS, command) | Contextual pattern matching |
| ExecutionMonitor | Rate limiting, resource quotas | Time-window counting |
| TokenCostGuard | LLM API cost tracking, financial circuit breaking | Token + dollar budget |

### Output Guards (after LLM)

| Guard | Purpose | Detection |
|-------|---------|-----------|
| OutputFilter | PII/secret masking | Regex + role-based filtering |
| OutputSchemaGuard | Structured output validation | Schema + injection scan |
| ToolResultGuard | Tool return value validation | Injection + state claims |

### Agentic Guards

| Guard | Purpose | Detection |
|-------|---------|-----------|
| ToolChainValidator | Dangerous tool sequences | Sequence matching |
| AgentCommunicationGuard | Inter-agent message security | HMAC + nonce |
| TrustExploitationGuard | Human-agent trust boundary | Action validation |
| AutonomyEscalationGuard | Unauthorized autonomy expansion | Capability tracking |
| MemoryGuard | Memory poisoning prevention | Injection patterns + HMAC |
| StatePersistenceGuard | State corruption prevention | Integrity hashing |
| CodeExecutionGuard | Unsafe code execution | Static analysis (regex + Python AST sandbox-escape) |
| RAGGuard | RAG document poisoning | Source trust + injection |
| MCPSecurityGuard | MCP tool shadowing, rug pull, SSRF, credential exposure | Registration + mutation hash + credential scan; `detect_credential_exposure` option |
| CircuitBreaker | Cascading failure prevention | State machine |
| DriftDetector | Behavioral anomaly detection | Statistical profiling |
| ExternalDataGuard | External data validation before LLM context | Source trust + injection + secret scan; SSRF/XXE/exfil/injection checks re-scan decode variants (base64/hex/URL-encoded/ROT13/reversed/homoglyph-normalized) |
| AgentSkillGuard | Malicious plugin/tool detection (OpenClaw) | Backdoor signatures + typosquatting |
| SessionIntegrityGuard | Session hijacking, permission escalation | Binding + sequence + timeout |

`CodeExecutionGuard` analyzes Python with the stdlib `ast` module (zero
dependencies) layered on the regex pass, catching sandbox-escape gadget chains
that regex cannot — e.g. `().__class__.__bases__[0].__subclasses__()` or
`__import__('os').system(...)`:

```python
from llm_trust_guard import CodeExecutionGuard

guard = CodeExecutionGuard()
guard.analyze("().__class__.__bases__[0].__subclasses__()", "python").allowed  # False
guard.analyze("print('hello world')", "python").allowed                       # True
```

(The npm package, lacking a stdlib parser, exposes this via a pluggable
`CodeAnalyzerBackend` instead — see its README.)

### Multi-Agent Guards (OWASP ASI07)

| Guard | Purpose | Detection |
|-------|---------|-----------|
| SpawnPolicyGuard | Agent spawn policy enforcement | CSP-style allowlists, max delegation depth |
| DelegationScopeGuard | Agent-to-agent scope downscoping | OAuth-style parent-child scope subset |
| TrustTransitivityGuard | Trust chain validation | X.509-style chain depth + min trust score |

### Pluggable Detection

| Component | Purpose |
|-----------|---------|
| DetectionClassifier | Plug in any ML backend (sync or async) alongside regex guards |
| create_regex_classifier() | Built-in regex classifier as a DetectionClassifier callback |

## OWASP Coverage

Mapped to the official lists ([LLM Top 10 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/), [Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)): a built-in guard **maps to** all 10 Agentic 2026 (ASI) risks and 9 of 10 LLM Top 10 2025 (LLM09 Misinformation needs a pluggable ML backend).

> **"Covered" = a guard maps to the risk (taxonomy mapping), not a detection-efficacy guarantee.** The **architectural** guards — access control, tenant isolation, delegation scope, inter-agent auth, rate/cost limits — are the strong **primary** controls. The **content-detection** guards (regex/heuristic) are a **WAF-like first line** with a measured ceiling: see [What it catches](#what-this-package-does-and-what-it-doesnt) and Measured Performance. The stdlib-`ast` sandbox-escape detection (0.10.3) is real and verified, but a bash/shell-only code-exec corpus won't surface it — add `language='python'` introspection-gadget payloads to measure it.

### LLM Top 10 2025

| Threat | Guards | Coverage |
|--------|--------|----------|
| LLM01: Prompt Injection | InputSanitizer, EncodingDetector, CompressionDetector, HeuristicAnalyzer | Strong (known patterns), Weak (novel semantic) |
| LLM02: Sensitive Information Disclosure | OutputFilter, PromptLeakageGuard | Strong |
| LLM03: Supply Chain | MCPSecurityGuard, AgentSkillGuard, ExternalDataGuard | Moderate |
| LLM04: Data and Model Poisoning | RAGGuard, MemoryGuard | Moderate |
| LLM05: Improper Output Handling | OutputSchemaGuard, OutputFilter, ToolResultGuard | Strong |
| LLM06: Excessive Agency | ToolRegistry, PolicyGate, ToolChainValidator, AutonomyEscalationGuard | Strong |
| LLM07: System Prompt Leakage | PromptLeakageGuard | Strong |
| LLM08: Vector and Embedding Weaknesses | RAGGuard | Moderate |
| LLM09: Misinformation | DetectionClassifier (pluggable ML) | Requires ML backend |
| LLM10: Unbounded Consumption | ExecutionMonitor, TokenCostGuard, ContextBudgetGuard | Strong |

### Agentic Applications 2026 (ASI)

| Threat | Guards | Coverage |
|--------|--------|----------|
| ASI01: Agent Goal Hijack | ConversationGuard, InputSanitizer | Moderate |
| ASI02: Tool Misuse and Exploitation | ToolChainValidator, ToolRegistry | Strong |
| ASI03: Identity and Privilege Abuse | PolicyGate, TenantBoundary | Strong |
| ASI04: Agentic Supply Chain Vulnerabilities | AgentSkillGuard, MCPSecurityGuard, ExternalDataGuard | Moderate |
| ASI05: Unexpected Code Execution (RCE) | CodeExecutionGuard | Strong |
| ASI06: Memory & Context Poisoning | MemoryGuard, StatePersistenceGuard | Strong |
| ASI07: Insecure Inter-Agent Communication | AgentCommunicationGuard, SessionIntegrityGuard, SpawnPolicyGuard, DelegationScopeGuard, TrustTransitivityGuard | Strong |
| ASI08: Cascading Failures | CircuitBreaker, StatePersistenceGuard | Strong |
| ASI09: Human-Agent Trust Exploitation | TrustExploitationGuard | Strong |
| ASI10: Rogue Agents | AutonomyEscalationGuard, DriftDetector | Moderate |

## Measured Performance

v0.21.3 shares the regex detection family with llm-trust-guard npm v4.32.4. The FPR table below was measured at v0.9.0 / npm v4.19.0; subsequent releases added patterns orthogonal to the Sanitizer+Encoder pipeline, so the FPR numbers apply unchanged. v0.21.3 fixes a `CodeExecutionGuard` gadget-chain proximity false positive (nkratk/llm-trust-guard-python#4) — adversarial corpus recall 82.1% across 1,182 threat groups / 5,883 payloads (not yet re-measured after this patch; see the npm repo's RESULTS doc for the latest guard-level fix details), WildChat FPR gate: 494/10,000 = 4.94% (locked). Full methodology, confidence intervals, hand-adjudication labels live in the npm repo: [tests/adversarial/RESULTS-v4.32.4.md](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.32.4.md).

**Attack detection on prior-published corpora** (Giskard n=35, Compass CTF Chinese n=11): detection rate has not moved from v4.13.5 on the Sanitizer+Encoder pipeline — 80.00% and 9.09% respectively, identical to v4.13.5. Six minor releases of pattern additions targeted different attack classes (indirect injection, tool-result validation, memory persistence, multi-agent trust) that these direct-text jailbreak corpora do not exercise. Small sample sizes mean "no evidence of improvement," not "proof of no improvement."

**False-positive rate on real ChatGPT production traffic** (WildChat-1M shard 0, 10,000 non-toxic multilingual first-user-turns, seed=42):

| Pipeline | Blocks | Raw block rate | Corrected FPR (after label adjudication) |
|---|---|---|---|
| Sanitizer + Encoder | 493 / 10,000 | 4.93% [4.52, 5.37] | **~2.73%** [2.43, 2.84] |
| Detection-only facade | 898 / 10,000 | 8.98% [8.44, 9.56] | ≤6.69% (upper bound; not fully adjudicated) |

WildChat filters toxic content but not prompt-injection intent. Canonical-marker analysis + a 50-sample hand-adjudication found that approximately 220 of the 493 Pipeline A blocks are actual jailbreak attempts users sent to ChatGPT, not genuine false positives. Corrected FPR is in the same order of magnitude as Meta Prompt Guard 86M's self-reported 3–5% out-of-distribution FPR — not a head-to-head comparison, but a useful reference point.

**Not measured on external corpora:** detection rate on attack classes added in v0.9.0–v0.21.3 (current) (CSS-hidden content, HTML attribute directives, Semantic Compliance Hijacking, Plant-Persist-Trigger, LLM-to-LLM string-payload injection, markdown image alt injection, HTML event injection). No public held-out corpus exists for these at statistical scale. Internal adversarial corpus recall: 82.1% (1,182 groups — see [RESULTS-v0.21.3.md](tests/adversarial/RESULTS-v0.21.3.md)); independent third-party evaluation is invited.

For higher detection on adversarial corpora, plug in an ML classifier via the [DetectionClassifier interface](#pluggable-detection).

## Defense In Depth

This package is one layer. For production systems, combine with:

```
Layer 1: llm-trust-guard (regex pattern matching — fast, zero deps)
Layer 2: ML classifier via DetectionClassifier (semantic detection — slower, more accurate)
Layer 3: Model provider safety (OpenAI moderation, Anthropic safety, etc.)
Layer 4: Human review for high-risk actions
Layer 5: Monitoring + alerting (DriftDetector + circuit breakers)
```

## Framework Integrations

- **FastAPI/Starlette** — `TrustGuardMiddleware` ASGI middleware
- **LangChain** — `TrustGuardLangChain` for chain validation
- **OpenAI** — `SecureOpenAI` or `wrap_openai_client()` for API wrapping

## Links

- [npm package](https://www.npmjs.com/package/llm-trust-guard) (TypeScript — 34 guards)
- [OWASP Top 10 for LLMs 2025](https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

## License

MIT
