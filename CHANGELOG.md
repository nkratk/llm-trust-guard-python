# Changelog

## 0.10.0 (2026-04-24)

### Added — MCP Sampling Attack Detection (parity with npm 4.20.0)

`MCPSecurityGuard.validate_sampling_response()` closes the MCP sampling channel gap, tied to published Unit42 + Blueinfy Feb 2026 research.

Three attack vectors detected:

- **Resource drain** (`sd_call_again`, `sd_loop_until`, `sd_do_not_stop`, `sd_n_times`, `sd_exhaust_resources`): Loop/repetition directives hidden in sampling responses to DoS the agent runtime
- **Conversation hijacking** (`sd_fake_user_turn`, `sd_fake_assistant_turn`, `sd_role_json`, `sd_system_xml`, `sd_from_now_on`, `sd_new_instructions`, `sd_ignore_previous`): Fake turn injection, JSON role fields, XML role tags, and system-prompt override phrases
- **Covert tool invocation** (`sd_anthropic_tool_xml`, `sd_tool_result_xml`, `sd_openai_tool_call`, `sd_bracket_tool_call`, `sd_double_brace_call`, `sd_invoke_name_attr`): Tool-call syntax in plain-text sampling responses across Anthropic, OpenAI, and bracket formats

New exports: `MCPSamplingResponse`, `MCPSamplingAnalysis` dataclasses.

Server reputation degrades automatically on sampling attack detection.

### Tests

- +6 sampling attack tests (resource drain, conversation hijack ×2, covert tool invocation, reputation degradation, clean FP)
- **All 693 tests pass** (was 687), zero regressions

### Stats
- 34 guards, 693 tests, zero dependencies

## 0.9.1 (2026-04-23)

### Added — Measured Performance

- New README section "Measured Performance" with measured numbers from the v4.19.0 benchmark run (npm + Python share the regex family). Full methodology, confidence intervals, hand-adjudication labels, and reproducibility scripts live in the npm repo: [tests/adversarial/RESULTS-v4.19.0.md](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.19.0.md)
- Pipeline A corrected FPR on real ChatGPT production traffic (WildChat-1M, n=10,000, seed=42): **~2.73%** [95% CI 2.43, 2.84], same order of magnitude as Meta Prompt Guard 86M's self-reported 3–5% OOD FPR
- On Giskard (n=35) and Compass CTF Chinese (n=11), Pipeline A detection rate is unchanged from v4.13.5. Underpowered; "no evidence of improvement"

### Not changed

- No code changes. No detection patterns added or modified. All 687 tests still pass

## 0.9.0 (2026-04-23)

### Added — Indirect Injection Expansion (parity with npm 4.19.0)

RAGGuard `INDIRECT_INJECTION_PATTERNS` now covers:

- **CSS-hidden text** (`css_hidden_text`): inline `style=` declarations of `display:none`, `visibility:hidden`, `opacity:0`, `font-size:0`. Catches content that renders invisibly to humans but is still ingested by the LLM
- **HTML attribute directives** (`html_attr_directive`): prompt-injection content smuggled into `alt`, `title`, `aria-label`, or `data-*` attributes
- **JSON agent-directive fields** (`json_agent_directive`): underscore-prefixed keys (`_system`, `__override`, `_agent_instructions`, `__system_prompt__`, `_assistant_role`, `__internal_directive`, `_meta_instruction`) used to inject directives through structured context

### Added — "Reprompt"-Class Markdown Image Exfiltration

CVE-2026-24307 class (Microsoft Copilot Personal Reprompt, Varonis):

- **`markdown_image_exfil_long_value`** (ExternalDataGuard): markdown image URL with any query-param value ≥30 characters — catches exfil where attacker uses innocuous param names
- **Widened `markdown_image_exfil`** named-key list: added `p`, `prompt`, `ctx`, `context`, `info`, `msg`, `body`, `session`, `conv`

### Documented — CVE-2026-25536 SDK Advisory

MCPSecurityGuard docstring now references CVE-2026-25536 (`@modelcontextprotocol/sdk` 1.10.0-1.25.3, CVSS 7.1, cross-client response data leak). Upstream SDK bug — mitigation is SDK pin `>=1.26.0`, not a detection-layer fix.

### Tests

- +7 RAGGuard tests + +3 ExternalDataGuard tests for the new patterns
- **All 687 tests pass** (was 677), zero regressions

### Stats
- 34 guards, 687 tests, zero dependencies (unchanged)

## 0.8.1 (2026-04-20)

### Fixed — Ship Blockers and Metadata

- **`__version__` ship blocker**: `src/llm_trust_guard/__init__.py` declared `__version__ = "0.4.0"` while `pyproject.toml` was at `0.8.0`. Programmatic version checks lied. Now synchronized
- **Missing LICENSE file**: the package declared `license = {text = "MIT"}` in `pyproject.toml` but there was no `LICENSE` file in the repo or distributed with the sdist/wheel. Added MIT LICENSE file
- **README guard count**: "All 31 Guards" heading and "npm — 31 guards" link description were stale. Bumped to 34
- **README multi-agent table**: SpawnPolicyGuard, DelegationScopeGuard, TrustTransitivityGuard were added in v0.5.0 but never listed in the README guard table. Added under new "Multi-Agent Guards (OWASP ASI07)" section

### Changed — Package Hygiene

- Migrated to PEP 639 SPDX license form: `license = "MIT"` + `license-files = ["LICENSE"]` (was deprecated `{text = "MIT"}` table form)
- Removed redundant `License :: OSI Approved :: MIT License` classifier (PyPI now sources license from SPDX field)
- Bumped `Development Status` classifier from `4 - Beta` to `5 - Production/Stable` (677 tests, 34 guards, stable API)
- Pinned `build-system.requires = ["hatchling>=1.27"]` — required for PEP 639 SPDX support
- Updated `description` to reflect 34 guards and Agentic Applications 2026 coverage

### Stats
- 34 guards, 677 tests, zero dependencies (unchanged)

## 0.8.0 (2026-04-10)

### Added — Full npm Pattern Parity

Ported 31 missing PAP patterns + 2 injection patterns + 1 secret pattern from npm v4.18.0:

#### InputSanitizer (+33 patterns, now matches npm 182-count)
- **Authority**: `pap_authority_order`, `pap_authority_company`
- **Scarcity**: `pap_scarcity_time`, `pap_scarcity_deadline`, `pap_scarcity_now`
- **Social proof**: `pap_social_millions`, `pap_social_why_cant`, `pap_social_equally`
- **Reciprocity**: `pap_reciprocity_exchange`, `pap_reciprocity_help`, `pap_reciprocity_past`, `pap_reciprocity_review`
- **Commitment**: `pap_commitment_no_change`, `pap_commitment_bypass`
- **Liking**: `pap_liking_flattery`, `pap_liking_love`, `pap_liking_friend`
- **Fear**: `pap_fear_legal`, `pap_fear_unless`
- **Logical appeal**: `pap_logic_rational`, `pap_logic_reasonable`
- **Evidence**: `pap_evidence_research`, `pap_evidence_proven`, `pap_evidence_statistics`
- **Emotional**: `pap_emotional_pleading`, `pap_emotional_family`, `pap_emotional_save`, `pap_emotional_only_hope`, `pap_emotional_family_depends`
- **Injection**: `encoding_keywords`, `greeting_persona_bypass`

#### OutputFilter (+1 pattern)
- `anthropic_key` (`sk-ant-...` API key detection)

### Added
- `CLAUDE.md` project rules (data freshness validation, honesty rules)

## 0.7.1 (2026-04-05)

### Fixed — Pattern Weight and Regex Corrections
- PAP weights raised to 0.75 (gov authority, fear, flattery, moral) — were too low to block
- Fear technical: added "found" (past tense)
- MemoryGuard user_preference_override: fixed whitespace regex for "safety warnings"

## 0.7.0 (2026-04-05)

### Added — Close Remaining 0% Detection Gaps

#### PromptLeakageGuard (+5 patterns)
- Training extraction, demonstrate instructions, reveal + wildcard + instructions, internal workings

#### InputSanitizer PAP (+8 patterns)
- Government authority (DHS, FBI, FTC directives), regulatory fear, technical fear
- Flattery intelligence ("too smart for rules"), moral obligation ("information freedom")

#### ToolResultGuard (+4 patterns)
- Direct underscore tool calls, "before responding" chains, subtle context exfil, format exfil

#### MemoryGuard (+3 patterns)
- Subtle safety override ("prioritize over safety"), suppress warnings, user preference override

## 0.6.0 (2026-04-04)

### Added — Close Detection Gaps

#### PromptLeakageGuard (+10 patterns)
- **Direct extraction** (+8): "instructions you followed", "constraints given when trained", "how you work", "extract system prompt", "reveal instructions", "trained instructions"
- **Indirect extraction** (+2): Academic/research framing, "demonstrate how AI could be manipulated"

#### OutputFilter (+7 secret patterns)
- OpenAI project key (`sk-proj-`), Stripe keys (`sk_live_`, `sk_test_`)
- GitHub fine-grained PAT (`github_pat_`), XML password tags
- Basic auth header (`Authorization: Basic ...`), npm registry tokens

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
