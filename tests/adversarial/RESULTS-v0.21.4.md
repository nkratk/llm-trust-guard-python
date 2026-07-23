> **Regression fix + coverage-gap fix + security hardening.** Companion release to npm v4.32.5. Parity fixes for issues #7 (closed), #9 (closed), #10/#11 (left open, partial — documented residual gap), plus 25 ReDoS fixes and one Python-specific bug (a decode step silently dropping a variant on invalid UTF-8) found during independent review.

# Adversarial Benchmark Results — v0.21.4

Run date: 2026-07-22
Companion release to npm v4.32.5 — same methodology, independently re-verified against this repo's own guards rather than assumed identical to npm (see notes below on where the two diverge).
Suite: 979 tests, all pass (up from 964 in v0.21.3 — new `tests/test_decode_variants.py`, 15 tests)

---

## Changes in v0.21.4

Full detail in CHANGELOG.md `0.21.4`. Summary:
- `InputSanitizer`'s `dan_jailbreak` pattern fixed (#7, closed).
- New shared `src/llm_trust_guard/decode_variants.py`: `InputSanitizer`, `ExternalDataGuard`, `MultiModalGuard` now re-scan de-obfuscated content variants before deciding allow/block.
- `ExternalDataGuard` (#9, closed): 33/34 previously-undetected threats now caught.
- `MultiModalGuard` (#10, left open — partial): 20/30 now caught via decode; 10 remain a genuine signature gap.
- `InputSanitizer` (#11, left open — partial): parity with npm's decode-gap subset.
- **25 ReDoS fixes** across 8 guard files, found via the same empirical stress-test sweep as npm, run independently against this repo's own patterns (814 patterns, 28 adversarial seeds) — 19 direct timeouts + 6 slow patterns found and fixed, not assumed identical to npm's findings.
- **One Python-specific bug**, not present in the npm original: `decode_variants.py` used `errors="strict"` on hex/base64 decode, silently dropping a variant on any single non-UTF-8 byte (npm's `Buffer.toString('utf-8')` never throws). Fixed by switching to `errors="replace"` — found by independent adversarial review of the port, not by mechanically copying npm's implementation.
- A final pre-merge review round caught the same `maxContentLength`/decode-cap bypass npm had (the input cap sat below `ExternalDataGuard`'s own 50,000-char default). Raised to 65,000 here — deliberately lower than npm's 100,000, since `InputSanitizer`'s 170+ patterns cost ~770ms worst-case at npm's value on CPython's slower regex engine vs. npm's ~30ms; 65,000 keeps worst-case latency ~300ms while still closing the same bypass.

**Pipeline re-verified against the actual threat corpus after these fixes**: of the 133 Python threat groups that showed zero detection before this release, **70 now detect** (43 fully, 27 partially) — consistent with npm's 70/137.

**Process note**: this release's port went through independent adversarial review of the Python-specific implementation, not just parity-checking against npm — this is what caught the `errors="strict"` bug above, which has no npm equivalent (JS's `Buffer.toString` semantics differ from Python's `str.decode`). A second, final holistic review after CI went green caught the maxContentLength/decode-cap bypass before merge, same as npm.

---

## WildChat FPR gate

No local WildChat fixture / FPR gate exists in this repo (npm-only infrastructure) — not applicable here, same as prior releases.

---

## Full guard recall summary

*Inherited from [RESULTS-v0.21.3.md](RESULTS-v0.21.3.md) for the general 1,182-group corpus — this release's testing focus was the 133 specifically-bisected previously-failing threat groups (documented above), not a full corpus re-run. See `specs/001-guard-adversarial-hardening/tasks.md` for the full bisection methodology.*
