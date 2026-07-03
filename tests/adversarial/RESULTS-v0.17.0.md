# Results — v0.17.0 (MultiModalGuard: 12 new patterns, 27.27% → 64.18%)

- **Date:** 2026-07-03
- **Library version:** 0.17.0 (PyPI) / 4.28.0 (npm)
- **Driven by:** Mirror of TS v4.28.0

See RESULTS-v4.28.0.md in the TS package for the full pattern table.

`MultiModalGuard`: 12 new INJECTION_PATTERNS (instruction-void forms, QR agent-cmd, browser extension
spoof, SVG XSS, ultrasonic hidden command, mind-map/diagram injection, physical billboard, cross-modal
tool_call). Updated `jailbreak_markers` for DAN persona/character and bypass guardrails.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 874 | **874** |

`bash scripts/verify.sh` — all gates green.
