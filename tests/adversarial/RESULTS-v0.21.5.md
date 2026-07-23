# Adversarial Benchmark Results — v0.21.5

> **Safety-net + review-driven fix release.** No new adversarial-corpus run — this release adds permanent, automated regression tests (ReDoS-safety, config-consistency) and fixes real bugs those tests (and two rounds of independent adversarial review) found, but does not change any guard's steady-state detection logic relative to v0.21.4's measured corpus results, with one exception noted below. Recall against the 1,182-group corpus is unchanged; see [RESULTS-v0.21.4.md](RESULTS-v0.21.4.md) for those numbers, which remain the current basis for detection-rate claims.

Run date: 2026-07-23
Pytest: **988 tests, all pass** (up from 982 in v0.21.4 — new `tests/test_redos_safety.py` (2 tests), `tests/test_heuristic_analyzer.py` (4 tests), plus 2 new cases each in `tests/test_decode_variants.py` and `tests/test_encoding_detector.py`)
G5 recall ratchet (`recall-baseline.json`): unchanged, passed.

---

## Changes in v0.21.5

Full detail in CHANGELOG.md `[0.21.5]`. Summary:

- **Permanent ReDoS-safety regression test** (`tests/test_redos_safety.py`): extracts regex patterns via `re.<func>(...)` calls and `pattern=` keyword-argument dataclass fields, and stress-tests each with a scaling-ratio check. Found and fixed three real catastrophic-backtracking regexes: `heuristic_analyzer.py`'s `_QA_PATTERN`, `encoding_detector.py`'s `template_injection` (neither had ever shipped in a released version — found and fixed within the same unreleased branch), and **`output_filter.py`'s `email` PII pattern** — this one *was* live in v0.21.4 and every prior release. It's a parity gap: the exact same bug shape was already found and fixed in `ExternalDataGuard` and in the npm sibling's `output-filter.ts`, but this file's own copy never got the parity fix, and was entirely invisible to the ReDoS-safety test until its extractor was broadened (per independent review) to cover dataclass-field patterns, not just `re.compile()` call arguments.
- **Content-length consistency regression test** (`tests/test_decode_variants.py`).
- **`.githooks/pre-push`** now fetches origin's tags before running `scripts/verify.sh`.
- **Review-driven fix**: the first fix for `_QA_PATTERN` (bounding its unbounded gap to 1000 chars) closed the ReDoS but silently created a many-shot-jailbreak detection bypass — any turn whose Q→A gap exceeds 1000 chars stopped being counted. Independent adversarial review of the npm sibling's identical fix caught this and confirmed it here too (verified 5/5 → 0/5 on a long-turn payload). Replaced with a linear marker-position scan (`_count_qa_pairs`) with no length cap at all — detection fully restored, still ReDoS-safe. **Net effect on the many-shot heuristic: neutral relative to v0.21.4** (this bug was found and fixed within the same unreleased branch, never shipped in a tagged release).
- **Review-driven fix**: a portability bug in the ReDoS test itself (`signal.alarm` called unconditionally on a code path that should have degraded gracefully without `SIGALRM`) — test-infrastructure only, no production code affected.

## Security-relevant note on the `output_filter.py` email fix

Unlike the other fixes in this release, the `output_filter.py` email-pattern fix changes behavior that **was live in v0.21.4 and prior releases**: an attacker-reachable input (any text passed through `OutputFilter` with PII detection enabled and containing a long run of `.`-adjacent characters near an `@`) could trigger multi-second-plus backtracking, a real, if narrow, denial-of-service surface on LLM output filtering. The fix bounds the pattern's quantifiers (`{1,64}@(?:...){1,8}[A-Za-z]{2,24}`, identical to the already-fixed `ExternalDataGuard`/npm versions) with no change to which strings are detected as emails on realistic input (verified against the existing `test_should_detect_email_addresses` test and several representative email formats).
