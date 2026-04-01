# Changelog

## 0.4.2 (2026-03-26)

### Fixed
- ROT13 full-input decode — catches "system prompt" in decoded text even without individual keyword matches
- Homoglyph normalization — Cyrillic/Greek lookalike characters (і, а, е, о, etc.) normalized to Latin before threat scanning
- API key `sk-` prefix pattern — detects Stripe/OpenAI-style keys (`sk-abc123def456`)
- All fixes applied to both Python and npm packages simultaneously

## 0.4.1 (2026-03-26)

### Fixed
- TrustGuard facade: safe queries no longer blocked when `session=None` — L4 TenantBoundary skipped for missing context instead of blocking

## 0.4.0 (2026-03-26)

### Added
- Full feature parity with npm package v4.13.2
- TrustGuard facade — unified `check()`, `check_async()`, `filter_output()`, `validate_tool_result()` entry points
- DetectionClassifier interface — `create_regex_classifier()`, `merge_detection_results()`
- Framework integrations — FastAPI middleware, LangChain wrapper, OpenAI wrapper
- 98 exports matching npm package (all guards, configs, result types)
- 657 tests (exact match with TypeScript test count)
- Adversarial benchmark tests (same datasets as npm: Giskard, Compass CTF, jailbreak_llms)

### Fixed
- InputSanitizer scoring — changed from min(scores) to sum(weights) to match TypeScript behavior
- PAP individual patterns — added 30 persuasion technique patterns (authority, fear, social proof, etc.)
- MCP guard — `validate_tool_call()` now accepts both dataclass and plain dict

## 0.3.1 (2026-03-26)

### Fixed
- ROT13 prompt extraction — added `reveal/show/output + system/prompt` to threat patterns
- Output secret masking — passwords now masked (`"password is X"` → `[PASSWORD]`)
- ROT13 keyword list expanded — added `reveal`, `prompt`, `override`, `jailbreak`, `unrestricted`

## 0.3.0 (2026-03-25)

### Added
- TrustGuard facade (initial)
- DetectionClassifier backend
- FastAPI/LangChain/OpenAI integrations

## 0.2.2 (2026-03-25)

### Fixed
- PAP individual patterns added (30 persuasion techniques)
- MCP guard dict support for `validate_tool_call()`

## 0.2.1 (2026-03-25)

### Fixed
- Author name corrected to "Nandakishore Leburu"

## 0.2.0 (2026-03-25)

### Added
- All 31 guards ported from TypeScript (full guard parity)
- Guards: ToolRegistry, PolicyGate, TenantBoundary, SchemaValidator, ExecutionMonitor, ConversationGuard, ToolChainValidator, MultiModalGuard, MemoryGuard, RAGGuard, CodeExecutionGuard, AgentCommunicationGuard, CircuitBreaker, DriftDetector, MCPSecurityGuard, PromptLeakageGuard, TrustExploitationGuard, AutonomyEscalationGuard, StatePersistenceGuard, ToolResultGuard, ContextBudgetGuard, OutputSchemaGuard, TokenCostGuard, ExternalDataGuard, AgentSkillGuard, SessionIntegrityGuard

## 0.1.0 (2026-03-25)

### Added
- Initial release — Phase 1 guards
- InputSanitizer (170+ patterns, 11 languages)
- EncodingDetector (9 encoding formats, dual ZWS normalization)
- CompressionDetector (NCD with 135 attack templates)
- HeuristicAnalyzer (synonym expansion + structural + statistical)
- OutputFilter (PII + secret detection and masking)
- 55 tests
- Zero dependencies (Python stdlib only)
