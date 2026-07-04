# Results — v0.19.0 (MemoryGuard, OutputFilter, ToolResultGuard: obfuscation preprocessing + new patterns)

- **Date:** 2026-07-04
- **Library version:** 0.19.0 (PyPI) / 4.30.0 (npm)
- **Driven by:** Mirror of TS v4.30.0

See RESULTS-v4.30.0.md in the TS package for the full pattern table.

`MemoryGuard`: 14 new injection patterns (indirect exfil, defanged URLs, memory API calls, retroactive edits, cross-app/inter-agent exfil, fact-planting, preference poisoning, trust mutation, rule-save directives), `_preprocess_content()` (ZWSP strip, URL/hex/base64 decode, reverse, Cyrillic normalise), wired into `check_write()`.

`OutputFilter`: `judge_stealth_marker` and `echogram_marker` secret patterns; `_build_scan_variants()` applied to PII and secret scans.

`ToolResultGuard`: `embedded_tool_call` extended to `<invoke name=` and `<function_call`; `_build_scan_variants()` applied in `scan_for_injection()` and `_detect_state_change_claims()`.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 856 | **903** |

`bash scripts/verify.sh` — all gates green.
