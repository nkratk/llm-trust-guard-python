# Adversarial Benchmark Results — v0.21.6

> **False-positive/false-negative fix, no new adversarial-corpus run.** This release fixes `OutputFilter`'s `ip_address` PII pattern false-positiving on version strings (issue #10, parity gap) and `ExternalDataGuard`'s `role_override` false-positive on ordinary business language (issue #7 sub-bug, parity gap) — no other guard's detection logic changed. Recall against the 1,182-group corpus is unchanged; see [RESULTS-v0.21.5.md](RESULTS-v0.21.5.md) for those numbers, which remain the current basis for detection-rate claims.

Run date: 2026-07-23
Pytest: **1001 tests, all pass** (up from 998 in v0.21.5)

---

## Changes in v0.21.6

Full detail in CHANGELOG.md `[0.21.6]`. Summary — mirrors npm v4.32.7 exactly:

- **`OutputFilter`'s `ip_address` false positive on version strings (#10), fixed properly across two independent-review rounds:**
  - Base fix: octet-bounding (0-255) plus a post-match context check (`_is_version_context`) suppressing the match when a version-indicating keyword qualifies the number within the same clause — implemented as code rather than an embedded regex lookbehind, since Python's `re` module only supports fixed-width lookbehind.
  - Round 1 review caught two regressions: a context window with no clause-boundary awareness (a real IP silently left unmasked when an unrelated keyword sat nearby), and an obfuscation-scan-variant bypass (the reversed-text variant scrambles the keyword while preserving the IP shape) — my own first fix attempt for the latter reproduced the identical bug via a different path before being corrected.
  - Round 2 review (a second, deliberate re-probe of the already-twice-fixed logic before merge) caught two more regressions, and found a code comment's claim of "parity with npm" was itself factually wrong when checked against npm's actual source: the clause-break denylist (`:;.,`) still missed every other punctuation mark and digit/newline gaps, and "skip for every scan variant" was scoped too broadly, itself disabling real-IP detection in base64/hex-obfuscated output.
  - Final design: an **allowlist** (letters + horizontal whitespace only) for the clause gap, matching npm's actual lookbehind exactly, and a narrowly-scoped skip for only the specific reversed scan variant. Verified exhaustively: every ASCII punctuation character correctly preserves detection; every non-reversal obfuscation variant (base64, hex) still catches a real IP.
- **`ExternalDataGuard`'s `role_override` false positive on ordinary business language, ported from npm** (this repo had never received the fix — a real, unattempted parity gap). A pre-existing, intentional gap in this same pattern ("act as a system administrator" isn't caught — the same tradeoff npm already shipped) is now documented with an explicit test, parity with an equivalent npm test.
- **Issue #7's `fetch_url`/`markdown_image_exfil` sub-bugs and #5 (npm-tracked, no Python-specific issues filed) were investigated with genuinely different angles, not changed** — all three independently reconfirmed the original 2026-07-16 conclusion that any pattern-based carve-out here either reopens a real bypass or is trivially gameable.

## Note on review process

This release went through **two full rounds of independent adversarial review**, both of which found real, previously-unnoticed regressions in the immediately-preceding fix — including one case where a code comment's explicit claim of matching the npm sibling's design was checked against npm's actual source and found to be wrong. Documenting this explicitly: a security-relevant regex/logic fix that looks complete after one round of scrutiny has, more than once now, still had real gaps a second round found. The final design in this release (allowlist over denylist, narrowly-scoped exclusions verified exhaustively rather than against a handful of examples, verified npm parity claims against npm's actual code rather than trusting a comment) is intended to close the *class* of bug, not just the specific reproductions found so far.
