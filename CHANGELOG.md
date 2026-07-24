# Changelog

## Unreleased

### Fixed

- `ExternalDataGuard`'s `role_override` pattern false-positived on ordinary business language using "act as a/an X" with a non-authority noun (e.g. "we act as an intermediary between buyer and seller") — closes #7's `role_override` sub-bug. Now requires an authority/system-impersonation noun (admin, root, superuser, ...) after "act as a/an", parity port of npm's already-fixed, already-adversarially-reviewed `external-data-guard.ts` pattern.
- `OutputFilter`'s `ip_address` pattern was unbounded (no octet range check) and false-positived on dotted version strings whose every component happens to be a valid octet (e.g. "10.4.32.3", structurally identical to a real IPv4 address by shape alone) — closes #10 (parity gap: npm had already fixed both the octet-bounding and this deeper version-string case; neither had been ported here). Octet-bounded to 0-255, plus a version-context check (suppresses the match when a version-indicating keyword or bare `v` prefix appears shortly before it) implemented as a post-match context check rather than embedded in the regex, since Python's `re` module only supports fixed-width lookbehind (confirmed via direct test) unlike npm's regex engine.
  - **Independent review caught two real regressions before merge**: (1) the version-context window had no clause-boundary awareness — silently left a real IP undetected *and unmasked* whenever an unrelated keyword occurrence (e.g. "release" as a document-section label) happened to sit within the window, a worse outcome (silent PII leakage) than the false positive being fixed (`"This release: connect to 10.4.32.3 for support"` → IP left in plaintext). Fixed by truncating the search window at the nearest preceding clause/sentence-break character (`:;.,`) — the keyword must qualify the number within the same clause. (2) `ip_address` detection also scanned `_build_scan_variants()`'s de-obfuscation passes (reversed/hex/base64/etc. text) — the reversed variant scrambles a version keyword ("release" → "esaeler", no longer matches) while the digit-and-dot IP shape survives (just reordered), so it independently re-flagged a version string the original text correctly suppressed (`"release 12.34.56.78 today"`). Fixed by only applying `ip_address` detection to the original text, not the obfuscation-scan variants — the same tradeoff the npm sibling makes for the identical reversed-string-scan class of problem, and IP addresses are a much less likely deliberate-obfuscation target than email/SSN/credit-card in this guard's threat model.
  - **A second, final independent review round (deliberately re-probing the already-twice-fixed logic before merge) caught two more real issues, and found the code comment's claim of npm parity was itself wrong**: (3) the `:;.,` clause-break denylist from fix (1) had no digit or newline exclusion at all, and missed every other punctuation mark — `!?()[]—-` and a bare digit gap (`"release 12345 at 10.4.32.3"`) all still silently left a real IP undetected and unmasked. Replaced with an allowlist (letters + horizontal whitespace only — no digits, no newline, no punctuation of any kind) matching npm's actual lookbehind exactly, which is robust against any of these rather than requiring a new denylist entry every time review finds one more counterexample. (4) Fix (2)'s "skip `ip_address` for every scan variant" was scoped far too broadly — it also silently disabled detection of a real IP hidden via base64 or hex encoding (a genuine exfiltration-detection gap this fix itself introduced), when only the *reversed* variant actually causes the false positive. The claim that this matched "the same tradeoff the npm sibling makes" was checked against npm's actual code and found to be wrong — npm's fix only ever excluded the specific reversed variant. Narrowed to compare against the specific reversed string (`output_str[::-1]`, matching `_build_scan_variants()`'s own transform) and skip only that one variant.
- `ExternalDataGuard`'s `role_override` — the same review round pointed out `"act as a system administrator"` is a common authority-impersonation phrasing this pattern doesn't catch (`"system"` was dropped from the authority-noun list for being too generic, matching npm's already-shipped, already-reviewed tradeoff). Not a new bug — added a test documenting the gap explicitly (parity with an equivalent npm test) so a future change to this list is a deliberate decision, not an accidental rediscovery.

## 0.21.5 (2026-07-23)

### Added

- **Permanent ReDoS-safety regression test** (`tests/test_redos_safety.py`): extracts regex patterns from `src/` via two AST shapes — `re.<func>(pattern, ...)` calls (compile/search/match/fullmatch/sub/subn/split/findall/finditer) and any call with a `pattern=` keyword argument holding a string literal — and stress-tests each against a fixed adversarial seed corpus using a scaling-ratio check (not a single absolute-time threshold — CPython's regex engine is slow enough that some already-fixed, genuinely-linear patterns overlap in absolute time with real quadratic bugs at any single seed size; growth ratio across two sizes cleanly separates them regardless of the constant factor).
  - The extractor originally matched only `re.compile(...)` calls; broadened to the rest of `re.<func>(...)` after the npm sibling's analogous `pattern:`/ALL-CAPS-`const` extractor turned out to miss ~28% of its regex literals — this repo's broadening found no new bugs among the 81 additional `re.search`/`re.sub`/etc. call sites. Broadened again to the `pattern=` kwarg shape after independent review found the entire `DEFAULT_PII_PATTERNS`/`DEFAULT_SECRET_PATTERNS` list in `output_filter.py` (35 patterns, stored as dataclass fields and compiled later via attribute access) was invisible to both prior shapes — this time the broadening found a real bug (see Fixed).
  - Also fixed a portability bug: the structural-seed loop called `_time_search` (which uses `signal.alarm`) unconditionally, while the single-character-seed loop correctly branched on `hasattr(signal, "SIGALRM")` — meant the structural loop would crash with `AttributeError` on a platform without `SIGALRM` (e.g. Windows) instead of degrading gracefully. `_time_search` now internally no-ops the alarm calls when unavailable.
- **Content-length consistency regression test** (`tests/test_decode_variants.py`): asserts `decode_variants.py`'s input cap is never smaller than any guard's own `max_content_length` default, closing the specific silent-bypass bug class a v0.21.4 pre-merge review caught.
- `.githooks/pre-push` now fetches origin's tags before running `scripts/verify.sh`, parity fix with the npm sibling closing the same local/CI tag-drift gap.
- `tests/test_heuristic_analyzer.py`, `tests/test_encoding_detector.py::TestThreatPatternDetection::test_should_detect_template_injection`: this repo had no dedicated regression tests confirming the `_QA_PATTERN`/`template_injection` ReDoS fixes preserved detection — independent review flagged the gap; added.

### Fixed

- `output_filter.py`'s `email` PII pattern (`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`) was catastrophic-backtracking (ratio ~16x, one 5s+ timeout on adversarial input) — this exact bug shape was already found and fixed elsewhere (`ExternalDataGuard`'s `email_address`, and this file's own npm sibling `output-filter.ts`), but this file's copy never got the parity fix and was entirely invisible to the ReDoS-safety test until its extractor was broadened to cover dataclass-field patterns (see Added). Applied the same bounded fix (`{1,64}@(?:...){1,8}[A-Za-z]{2,24}`) used elsewhere.
- `heuristic_analyzer.py`'s `_QA_PATTERN` was catastrophic-backtracking on long content with many "User:"/"Q:" markers and no closing "A:"/"AI:" — found by the new permanent ReDoS-safety test, not the earlier manual sweep. A first fix bounded the gap to `{0,1000}` chars, parity with npm's initial fix; independent review of the npm sibling found this created a real many-shot-detection bypass (any turn whose Q→A gap exceeds 1000 chars silently stopped being counted — verified 5/5 → 0/5 on a long-turn payload) and confirmed this file had the identical bug. Replaced with a linear marker-position scan (`_count_qa_pairs`) that has no length cap and no backtracking risk at all — full detection restored while staying fast on adversarial input.
- `encoding_detector.py`'s `template_injection` pattern was catastrophic-backtracking on long content with many "{" characters — this file wasn't included in the earlier manual sweep here (npm's equivalent was already fixed in v4.32.5).

## 0.21.4 (2026-07-22)

### Fixed

Parity with the npm sibling's decode/normalize fix batch (#7, #9, #10, #11) — found via the same full-history bisection sweep (see `specs/001-guard-adversarial-hardening/tasks.md` Phase 5).

- **`InputSanitizer`**: `dan_jailbreak` pattern now also matches "DAN persona"/"DAN character" phrasing. Closes #7.
- **New shared `src/llm_trust_guard/decode_variants.py`** (parity with npm's `src/decode-variants.ts`): `InputSanitizer`, `ExternalDataGuard`, and `MultiModalGuard` previously matched their patterns against raw input only. All three now also re-scan de-obfuscated variants (URL/hex/base64/ROT13/reversed/zero-width-stripped/homoglyph-normalized, chained up to depth 3) before deciding allow/block.
  - `ExternalDataGuard`: 33/34 previously-undetected SSRF/XXE/zip-slip/markdown-exfil/gopher-smuggle threats now caught (parity with npm's #21 fix). Closes #9.
  - `MultiModalGuard`: 20/30 previously-undetected CometJacking-family threats now caught via decode (parity with npm's #22 fix); the other 10 remain a genuine missing-signature gap, tracked in #10.
  - `InputSanitizer`: parity with npm's #23 decode-gap subset.

### Fixed (found during adversarial review of the above, not part of the original scope)

- **ReDoS (25 patterns, 8 files)**: parity with the npm sibling's ReDoS fix. Ran the same empirical stress-test sweep (814 patterns extracted from every guard, tested against 28 adversarial seeds with a 2s per-test alarm timeout as a safety net) against this repo's own guards — confirmed 19 direct timeouts plus 6 slow patterns pre-fix (not assumed identical to npm), all fixed by bounding the same previously-unbounded quantifiers. `ExternalDataGuard`, `InputSanitizer`, `MultiModalGuard`, `ToolResultGuard`, `OutputGuard`, `RAGGuard`, `AgentSkillGuard`, `MCPSecurityGuard` affected.
- **Bypass**: `build_decode_variants()`'s input cap (20,000 chars) sat below `ExternalDataGuard`'s own default `max_content_length` (50,000) — content between those two thresholds was neither decoded nor rejected for size, a real silent bypass (confirmed with a base64-encoded SSRF payload placed past the old cap in an otherwise-realistic ~45KB document). Raised to 65,000 — deliberately lower than the npm sibling's 100,000, since `InputSanitizer`'s 170+ patterns cost ~770ms worst-case at npm's value on CPython's slower regex engine vs. npm's ~30ms; 65,000 keeps worst-case latency around 300ms while still closing the same bypass. Found by independent final-review adversarial verification before merge.
- **False positive**: partial homoglyph normalization applied to genuinely non-English text created artificial script mixing, false-flagging legitimate Cyrillic/Persian content in `MultiModalGuard`. Fixed by gating the raw-text-only heuristics to never run against decode variants, and narrowing the unconditional ZWNJ/ZWJ check the same way as the npm fix (legitimate in Persian/Arabic-script/Indic text).
- **Inflated risk score**: `MultiModalGuard.check()` could double-count a violation's risk contribution across decode variants. Fixed with per-violation contribution tracking; `violations`/`injection_patterns_found` also deduplicated in the final result.

## 0.21.3 (2026-07-19)

### Fixed

- `code_execution_guard.py`: `_ast_escape_findings()`'s Python sandbox-escape gadget-chain detector flagged a single, standalone dunder attribute access (e.g. `cls.__subclasses__()` for plugin discovery, `def __reduce__` for pickle support) as a sandbox escape — common in legitimate code and not itself a gadget chain. Now mirrors the npm port's already-adversarially-reviewed fix (`code-execution-guard.ts`'s `hasPythonGadgetChain`): only fires when 2+ distinct gadget-chain tokens co-occur within a 50-character proximity window, measured via AST node position (`end_lineno`/`end_col_offset`) rather than npm's raw substring search — this also preserves a precision advantage pure text scanning doesn't have: a `def __reduce__` definition is never visited as a use, so definition sites are naturally excluded. Adversarial review of the initial implementation found and fixed a follow-up bug: `ast.Attribute.col_offset` points at the start of the whole chain expression, not the attribute name itself, which inflated the measured distance between two separate references and let genuinely adjacent (~20-char) gadget pairs slip past the window undetected — fixed by using `end_lineno`/`end_col_offset` instead. Fixes nkratk/llm-trust-guard-python#4.

### Added

- Broadened `tests/test_code_execution_ast.py`'s existing parametrized coverage (24 new cases): more long-variable-name proximity variants targeting the offset-bug class above, more single-token benign contexts (dict values, f-strings, sort keys, logging helpers), a genuinely-far (>50 char) two-token benign case, an explicit 50/51-char proximity-window boundary test, and a documented (intentionally not fixed) test for the `getattr(obj, '__subclasses__')`-style dynamic-access gap the AST pass structurally can't see. Same exercise run against the npm sibling package found 2 new bugs on first use; this Python pass found none (954/954 pass) — consistent with AST-based detection's inherent precision advantage over npm's raw substring search.

## 0.21.2 (2026-07-15)

### Fixed

- `rag_guard.py`: decode URL-encoded document content — including double-encoding, up to 3 levels — and re-scan each decoded variant before running injection-detection patterns, mirroring the npm v4.32.3 fix. Previously a URL-encoded payload bypassed detection entirely. (nkratk/llm-trust-guard-python#1, companion to nkratk/llm-trust-guard#1)
- `agent_skill_guard.py`: loosened the "fake-compliance data exfiltration" and "response appending directive" SCH patterns — they previously required a specific word order/literal word and missed reordered or reworded variants ("X mandates: route ...", "include in all outputs: ..."). The broadened "fake-compliance" pattern also now requires an explicit "all responses/data/output(s)" object AND an actual destination (`to`/`at <address>`) after the action verb — two earlier drafts were progressively found, in review, to false-positive on benign compliance/audit prose (first on qualifier+verb alone, then on verb+destination with no bulk object). Both caught before merge. Same regex source and fix as npm v4.32.3. (nkratk/llm-trust-guard-python#2, companion to nkratk/llm-trust-guard#2)

Note: `code_execution_guard.py` was not changed in this release. Its native AST-based `_ast_escape_findings()` correctly blocks real Python object-introspection gadget chains (`__subclasses__`, `__globals__`, `__mro__`, etc.) and served as the reference for fixing the npm port's true-negative gap (npm #3). However, it has its own, separate over-blocking bug — a single standalone dunder attribute access (e.g. bare `cls.__subclasses__()`) is flagged as if it were a chain, with no proximity/co-occurrence check at all. Filed as [#4](https://github.com/nkratk/llm-trust-guard-python/issues/4); not fixed in this release.

## 0.21.1 (2026-07-08)

### Fixed

- README: added "What it catches well" bullets for SCH, PPT, LLM-to-LLM string-payload, and markdown/HTML carrier injection — previously listed only in the "Not measured" disclaimer. Updated RESULTS reference to npm v4.32.1. No guard code changes.

## 0.21.0 (2026-07-06)

### Added — 2026 literature gap-fill: SCH, PPT, string-payload, HTML/image patterns (mirror of TS v4.32.0)

Four guards updated with patterns targeting 2026 threat research (arXiv:2601.07395, 2604.16543, 2605.28201, 2601.10923). WildChat FPR gate: 494/10,000 = 4.94% (unchanged). Adversarial recall: 82.1% / 1,182 groups.

- `agent_skill_guard.py` — 4 Semantic Compliance Hijacking patterns in `HIDDEN_INSTRUCTION_PATTERNS` (authority-keyword routing, fake-compliance exfil, compliance-framed routing, response-appending directive)
- `agent_communication_guard.py` — `STRING_PAYLOAD_INJECTION_PATTERNS` (7 patterns) + `isinstance(payload, str)` branch in `_validate_payload()` for LLM-to-LLM string-payload injection
- `memory_guard.py` — 4 Plant-Persist-Trigger patterns: `tool_invocation_trigger`, `next_call_trigger`, `future_session_anchor`, `before_any_tool`
- `rag_guard.py` — `markdown_img_alt_injection` + `html_event_injection` in `INDIRECT_INJECTION_PATTERNS`

Parity: `test_guard_parity.py` gains `AgentSkillGuard` and `AgentCommunicationGuard` handlers; parity vectors 32 → 46. Suite: 949/949 pass.

---

## 0.20.0 (2026-07-04)

### Fixed — `MultiModalGuard`: benign FPR 20.18% → 2.19% (mirror of TS v4.31.0)

- Entropy check now requires `sample length >= 200` before applying uniqueChars/length ratio — short multilingual strings no longer fire
- Homoglyph check changed to intra-token adjacency pattern — legitimate bilingual text passes; only same-token Latin/Cyrillic mixing (e.g. `аdmin`) fires

### Added — `ConversationGuard`: 9 new patterns + preprocessing (recall 2.7% → 21.82%)

New patterns: `skeleton_key`, `many_shot_jailbreak`, `context_drift`, `session_hijack`, `persona_pivot`, `loop_injection`, `crescendo_escalation`, `compression_abuse`, `whisper_sidechannel`. Added `_preprocess_message()` (ZWSP/URL/hex/base64/reverse/Cyrillic) wired into `check()` with Set deduplication.

### Added — `InputSanitizer`: obfuscation preprocessing (recall 28% → 52.27%)

Added `_build_input_variants()` generating URL/hex/base64/reverse/Cyrillic variants; `sanitize()` iterates all variants with `matched_names` Set deduplication.

### Added — full npm↔Python parity gate (`test_guard_parity.py`)

32 vectors across 12 guards; reads `tests/guard-parity-vectors.json` (shared with TS repo); 32/32 pass.

- `__version__` = `0.20.0`; 935 tests pass, all verify gates green

## 0.19.0 (2026-07-04)

### Added — `MemoryGuard`, `OutputFilter`, `ToolResultGuard`: obfuscation preprocessing + new patterns (mirror of TS v4.30.0)

#### `MemoryGuard` (0.11 → 96.06% recall)
- 14 new `MEMORY_INJECTION_PATTERNS`: `going_forward_directive`, `always_exfil`, `kb_metadata_tag`, `recommendation_bias`, `exfil_http_post`, `memory_api_call`, `defanged_url`, `retroactive_edit`, `cross_app_exfil`, `inter_agent_exfil`, `fact_plant_exfil`, `pref_key_poisoning`, `trust_mutation`, `save_rule`
- `_preprocess_content()` — ZWSP strip, URL/hex/base64 decode, reverse, Cyrillic normalise; wired into `check_write()`

#### `OutputFilter` (0.30 → 58.64% recall)
- New secret patterns: `judge_stealth_marker` (`**[SYSTEM-OK]**`), `echogram_marker` (`<malicious>`)
- `_build_scan_variants()` — obfuscation pipeline; PII and secret scans now cover all variants with Set deduplication

#### `ToolResultGuard` (0.06 → 63.64% recall)
- `embedded_tool_call` extended to catch `<invoke name=` and `<function_call` variants
- `_build_scan_variants()` — URL/hex/base64 decode, reverse, Cyrillic; applied in `scan_for_injection()` and `_detect_state_change_claims()`

## 0.18.0 (2026-07-03)

### Added — `MCPSecurityGuard`: obfuscation preprocessing + 20 new detection patterns (mirror of TS v4.29.0)

- `_preprocess_content()` — ZWSP strip, URL/hex/base64 decode, reverse, Cyrillic homoglyph normalisation
- `sd_retry_forever` sampling pattern; updated `sd_from_now_on` and `sd_ignore_previous`
- `embedded_abs_path`, `cursor_mcp_inject`, `dangerous_scheme`, `mcp_endpoint_override` command injection patterns
- `--exec=` added to `git_injection`; `NODE_OPTIONS`/`PYTHONSTARTUP` added to `env_injection`
- 8 new `_LINE_JUMPING_PATTERNS`: authority_directive, exfil_routing, schema_mutation_str, mcp_tool_shadow,
  mcp_impersonation, rug_pull_descriptor, html_comment_injection, homoglyph_cyrillic
- `instruction_override` extended to catch descriptions/guidelines/rules/prompts

## 0.17.0 (2026-07-03)

### Added — `MultiModalGuard`: 12 new detection patterns (mirror of TS v4.28.0)

`instructions_void`, `forget_instructions`, `disregard_directives`, `system_override_phrase`,
`qr_agent_cmd`, `url_encoded_injection`, `browser_extension_spoof`, `svg_xss_injection`,
`ultrasonic_hidden_cmd`, `mindmap_diagram_inject`, `physical_world_inject`,
`cross_modal_tool_call`. Updated `jailbreak_markers` for `DAN persona`/`DAN character`/`bypass guardrails`.

Detection: MultiModalGuard 27.27% → 64.18% (+203 payloads, blind spots 64 → 30).

## 0.16.0 (2026-07-03)


### Added — `ExternalDataGuard` + `ToolResultGuard`: SSRF, XSS, SQL echo, template injection

Mirror of TS v4.27.0.

`ExternalDataGuard`: 5 new SSRF patterns (cloud metadata, private IPs, file/gopher/dangerous
schemes), 6 new injection patterns (instructions_void, forget_instructions, disregard_directives,
json_system_key, path_traversal_hex, markdown_image_exfil_urlenc), XXE `%` entity fix.

`ToolResultGuard`: 11 new RESULT_INJECTION_PATTERNS (template injection, XSS, SQL injection
echo, @ai-agent hijack, markdown urlenc exfil, json_system_key, LangChain response_metadata,
instructions_void, forget_instructions, disregard_directives) + bidi strip before scanning
+ `destructive_action_claim` in STATE_CHANGE_PATTERNS.

## 0.15.0 (2026-07-02)

### Added — `InputSanitizer`: 9 new policy-puppetry patterns

Mirror of TS v4.26.0. Closes 395-miss cluster (10.2% of threat corpus).
New patterns: `llm_ini_namespace`, `llama2_sys_fencing`, `json_safety_false`,
`json_system_override`, `ini_inline_key_value`, `mode_activation`,
`system_override_engaged`, `instructions_void`, `forget_your_instructions`.

### Changed — `InputSanitizer`: `named_jailbreak_persona` extended + bidi strip

Added `persona|profile|\s+active|\s+enabled` alternatives. Extended bidi strip
to U+202A–U+202F and U+200E/200F.

## 0.14.0 (2026-07-02)

### Fixed — FPR reduction in `ExternalDataGuard` + `ToolResultGuard` patterns

`path_traversal`: Raised minimum traversal depth to 3 levels + sensitive directory
anchoring. `../../src/components` no longer triggers.

`html_comment_directive`: Requires imperative verb after colon. AI provenance
markers (`<!-- AI: generated -->`) no longer trigger.

### Fixed — Credential exposure gap in `MCPSecurityGuard.validate_tool_call()`

`validate_tool_call()` now calls `_detect_credential_exposure()` on live parameters.
New violation: `LIVE_CREDENTIAL_IN_TOOL_PARAMETER:<pattern_name>`. Mirrors TS v4.25.0.

## 0.13.0 (2026-07-02)

### Added — OS command injection detection in `ToolChainValidator`

`validate()` scans tool name and `all_tools_in_request` for OS command injection:
shell substitution `$(...)`, piped `sh`/`curl`, `bash -c`, `/bin/sh`,
`--exec-batch=`, MCP stdio `transport.command=`, Python `os.system()` in args.
New violation: `OS_COMMAND_INJECTION_IN_TOOL_PARAMETER`. Toggle via
`detect_parameter_injection` (default: `True`). Mirrors TS v4.24.0.

### Added — Structured document injection patterns in `ExternalDataGuard` + `ToolResultGuard`

Both guards detect injection in RAG/email/file-parser pipelines: XXE entity
declarations, DOCTYPE external entity, path traversal, RTF/OLE embedded objects,
LangChain deserialization gadgets (CVE-2025-68664), HTML comment agent directives,
embedded `<tool_call>` tags, Office XML script blocks. Mirrors TS v4.24.0.

## 0.12.0 (2026-06-30)

### Added — Sneaky Bits encoding detection in `EncodingDetector`

- Invisible operators (U+2062/U+2064) and variation selectors (U+FE00-U+FE0F, 2+
  consecutive) used by the "Sneaky Bits" attack (NVIDIA 2025).
- New violation: `SNEAKY_BITS_ENCODING_DETECTED` when 3+ consecutive invisible
  operators present. Mirrors TS v4.23.0.

### Added — Credential exposure scanning in `MCPSecurityGuard`

`validate_server_registration()` now scans the full registration object for
exposed credential values: AWS keys, GitHub PATs, Bearer/JWT tokens, Stripe
keys, Slack tokens, Google API keys. New violation: `credential_exposed: <type>`.
Toggle via `detect_credential_exposure` (default: `True`). Mirrors TS v4.23.0.

## 0.11.0 (2026-06-29)

### Added — `OutputGuard` (OWASP LLM05:2025 Improper Output Handling)

New guard (L35) that scans **model/tool output** for payloads dangerous to a
downstream sink, complementing `OutputFilter` (PII/secret egress only). Detects
HTML/DOM XSS (`<script>`, `javascript:`, inline event handlers, `<img onerror>`,
`document.cookie`), SQL injection (`UNION SELECT`, `' OR 1=1`, `;DROP TABLE`,
`xp_cmdshell`), OS command injection (`$(...)`/backticks, `;rm -rf`,
`curl|wget … | bash`, pipe-to-shell), markdown image-exfiltration links
(`![](https://host/?data=…)`, plus off-allowlist links when `allowed_domains`
is set), and spreadsheet/CSV formula injection (cells starting `= + - @` with
`HYPERLINK`/`IMPORT*`/`WEBSERVICE`/`DDE`/`cmd|`).

Critical payloads block; single high-severity signals are reported and require
corroboration to auto-block. Optional `sanitize=True` returns a neutralized
copy. Zero new dependencies. 21 tests. New exports: `OutputGuard`,
`OutputGuardConfig`, `OutputGuardResult`, `OutputThreat`.

### Added — MCP registration-time schema-poisoning & line-jumping detection

`MCPSecurityGuard.validate_server_registration()` now inspects tools beyond the
`description` field:

- **Full-schema poisoning (FSP)** — walks the entire parameter schema (key
  names, `enum`/`default`/`const` values, nested objects) for smuggled
  instructions or suspicious keys (CyberArk "Poison Everywhere", 2025).
- **Line-jumping** — flags descriptions that inject instructions at `tools/list`
  time, before any invocation or approval: pre-invocation directives, secrecy
  phrases, fake-compliance framing (Trail of Bits, 2025).

Both default on; toggle via `detect_schema_poisoning` / `detect_line_jumping`.
New violation prefixes: `schema_poisoning:` and `line_jumping:`. 5 tests.

Mirrored 1:1 with the npm package (`llm-trust-guard` 4.22.0).

## 0.10.4 (2026-06-12)

### Docs — document AST sandbox-escape detection; add README-sync gate (G11)

- **README**: documented the stdlib-`ast` sandbox-escape detection in
  `CodeExecutionGuard` (0.10.3) with an example. The README previously did not
  mention it.
- **Verification (G11)**: new gate fails the build when public exports
  (`src/llm_trust_guard/__init__.py`) change since the last tag but `README.md`
  does not (override `ALLOW_NO_README_UPDATE=1`). See VERIFICATION.md.

No code/behavior change.

## 0.10.3 (2026-06-09)

### Added — AST-based sandbox-escape detection (CodeExecutionGuard, Python only)

`CodeExecutionGuard.analyze()` now runs a Python `ast` pass (stdlib, zero new deps)
on top of the existing regex scan. It catches sandbox-escape gadget chains and
dynamic imports that regex provably cannot — e.g.
`().__class__.__bases__[0].__subclasses__()`, `obj.__globals__[...]`,
`__import__("os").system(...)`.

- **Measured**: escape-gadget probe **0/5 → 5/5 blocked**; benign probe **0/5 → 0/5**
  (no false-positive regression); 15 new tests + the existing 10 pass.
- **Strictly additive**: the ast pass only adds findings the regex missed; unparseable
  code falls back to the regex scan; non-Python code is unaffected (language-gated).
- **Intentional divergence from the npm port**: Python has a stdlib parser (`ast`); JS
  does not, so the npm package keeps regex and will take a pluggable parser-adapter
  route (acorn/oxc) instead of bundling a parser. See RESEARCH_LOG.md.
- This is detection only — it does **not** add a runtime sandbox (that stays a host
  concern). See `tests/adversarial/RESULTS-v0.10.3.md`.

## 0.10.2 (2026-06-06)

### Added — Benign-context suppression (false-positive reduction, parity with npm 4.20.2)

`InputSanitizer.sanitize()` now cancels the soft `ignore_instructions` /
`disregard_above` triggers when the object is a benign technical noun (e.g.
"ignore the whitespace", "ignore case", "ignore the previous error") **and** the
input contains no instruction/rule/prompt/safety noun anywhere, **and** the
prompt carries no high-signal exfiltration/execution/credential/money token. Any
real injection references an instruction-noun and is never suppressed.

- **Suppression veto**: suppression is refused when the prompt also contains a
  URL, email address, credential/secret word, shell pipe / `rm -rf` / `curl` /
  `wget`, destructive `delete`/`drop`, a money amount (`$NN`), or a long account
  number — closing the escape hatch where a benign object masks a real payload.
- New curated probe `tests/test_benign_context.py`: 28 benign prompts allowed +
  12 attack controls + 10 suppression-bypass controls blocked (51 tests).
- **Recall preserved**: full suite 744 pass (was 693). Mirrors npm 4.20.2; the
  WildChat-1M Pipeline A block count is unchanged (raw FPR 4.93%), so the win is
  scoped to coding/technical deployments and does **not** move the published
  ~2.73% corrected WildChat FPR.
- Known pre-existing gap noted (not addressed here): `"disregard your previous
  rules"` is not matched by the `disregard` patterns — a recall issue, separate
  from this FP work.

## 0.10.1 (2026-04-24)

### Changed — Documentation accuracy (parity with npm 4.20.1)

- **README**: Fixed "31 → 34 security guards" inconsistency (was contradicting the All 34 Guards table and `pyproject.toml`)
- **README**: Removed unmeasured "<5ms latency" assertion from intro
- **README**: Removed unmeasured "~97% on curated benchmarks" framing from "What it catches well"
- **README**: Qualified the four "100% detection" claims (Policy Puppetry, Role-play, PAP, Multilingual) as "100% on unit tests" with a section preface explaining that these are unit-test rates, not corpus measurements. Broader corpus measurements live in the npm repo's [RESULTS-v4.19.0.md](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.19.0.md)
- **README**: Updated version-pairing line to v0.10.1 / npm v4.20.1; benchmark numbers from v0.9.0 / npm v4.19.0 still apply (orthogonal MCP Sampling addition)

No code changes. Same 693 tests pass.

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
