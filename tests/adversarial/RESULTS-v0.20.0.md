# Results — v0.20.0 (MultiModalGuard FPR fix, ConversationGuard patterns, InputSanitizer preprocessing, parity gate)

- **Date:** 2026-07-04
- **Library version:** 0.20.0 (PyPI) / 4.31.0 (npm)
- **Driven by:** Mirror of TS v4.31.0

See `tests/adversarial/RESULTS-v4.31.0.md` in the TS package for the full corpus numbers.

## Changes

### MultiModalGuard — benign FPR 20.18% → 2.19%

- Entropy check: added `len(sample) >= 200` guard — short multilingual strings no longer exceed the uniqueChars/length threshold
- Homoglyph check: changed from document-level script co-occurrence to intra-token adjacency regex — legitimate bilingual text passes cleanly

### ConversationGuard — recall 2.7% → 21.82%

9 new `ManipulationPattern` entries: `skeleton_key`, `many_shot_jailbreak`, `context_drift`, `session_hijack`, `persona_pivot`, `loop_injection`, `crescendo_escalation`, `compression_abuse`, `whisper_sidechannel`. Added `_preprocess_message()` (ZWSP/URL/hex/base64/reverse/Cyrillic) wired into `check()` with Set deduplication.

### InputSanitizer — recall 28% → 52.27%

Added `_build_input_variants()` generating URL/hex/base64/reverse/Cyrillic variants. `sanitize()` pattern loop now iterates all variants with `matched_names` Set deduplication.

### Full npm↔Python parity gate

New `tests/test_guard_parity.py` loads `tests/guard-parity-vectors.json` (shared with TS repo), 32 vectors across 12 guards. 32/32 pass.

## Test suite

| Suite | Before | After |
|---|---|---|
| Python pytest | 903 | **935** |
| Parity gate | — | 32/32 |

`bash scripts/verify.sh` — all gates green.
