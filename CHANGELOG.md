# Changelog

## 0.5.2 (2026-04-03)

### Fixed — Python Parity Audit
- **InputSanitizer**: Added `detect_pap`, `pap_threshold`, `min_persuasion_techniques` constructor kwargs (previously errored on these params)
- **ConversationGuard**: Added `analyze()` alias for `check()` — matches Node API signature
- **OutputFilterResult**: Added `.filtered` property alias for `.filtered_response` — matches Node API
- **OutputFilter**: Added 8 secret detection patterns — Slack tokens (`xoxb-`), AWS access key (`AKIA`), OpenAI (`sk-`), Anthropic (`sk-ant-`), URL-embedded passwords, connection string passwords, `curl -u` patterns
- **MemoryGuard**: Added unusual whitespace detection (NBSP, em/en spaces, ideographic space)

## 0.5.1 (2026-04-02)

### Fixed — Detection Gap Audit
- Added 4 completion manipulation patterns: `continue as unrestricted`, `henceforth`, `going forward`, `rest of conversation`
- Relaxed PAP scarcity patterns — removed punctuation requirement on `urgent`/`emergency`
- Added 6 tool result injection patterns: URL exfiltration, credential solicitation, tool chain injection
- Added 2 state change claim patterns: role upgrade, permissions granted

## 0.5.0 (2026-04-01)

### Added — Multi-Agent Security Guards (OWASP ASI07)
- **SpawnPolicyGuard (L32)**: CSP-style agent spawn policies — allowlists, max delegation depth, third-party blocking
- **DelegationScopeGuard (L33)**: OAuth-style scope downscoping — blocked scopes, parent-child scope subset enforcement
- **TrustTransitivityGuard (L34)**: X.509-style trust chain validation — full/one-hop/none transitivity modes

### Added — Framework & Configuration
- Per-guard sensitivity modes: `strict` / `balanced` / `permissive` presets
- LangChain integration example (secure RAG chain with 4 attack surfaces)
- FastAPI integration example (ASGI middleware, RBAC, streaming SSE)
- GitHub Actions CI/CD via Trusted Publishing (OIDC)

### Stats
- 34 guards, 677+ tests, zero dependencies

## 0.4.4 (2026-03-28)

### Fixed
- Coverage threshold adjustments for new guard additions

## 0.4.3 (2026-03-27)

### Fixed
- CI pipeline improvements and test stabilization

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
