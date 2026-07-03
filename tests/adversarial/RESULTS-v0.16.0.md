# Results — v0.16.0 (ExternalDataGuard + ToolResultGuard: SSRF, XSS, SQL echo, template injection)

- **Date:** 2026-07-03
- **Library version:** 0.16.0 (PyPI) / 4.27.0 (npm)
- **Driven by:** Mirror of TS v4.27.0

## Changes

See RESULTS-v4.27.0.md in the TS package for the full table.

`ExternalDataGuard`: 5 SSRF patterns, 6 injection patterns, XXE `%` entity fix.
`ToolResultGuard`: 11 new patterns, destructive_action_claim, bidi strip.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 874 | **874** (unchanged) |

WildChat FPR: 494/10,000 (unchanged). `bash scripts/verify.sh` — all gates green.
