# Results — v0.14.0 (FPR fixes + credential gap in validate_tool_call)

- **Date:** 2026-07-02
- **Library version:** 0.14.0 (PyPI) / 4.25.0 (npm)
- **Driven by:** Advisor critique of v4.24.0 / v0.13.0

## Changes

Same as TS v4.25.0:

- `path_traversal`: Raised to 3+ levels OR 2+ into sensitive system directory.
  `../../src/components` no longer triggers.
- `html_comment_directive`: Requires imperative verb after colon. AI provenance
  markers no longer trigger.
- `validate_tool_call()`: Now calls `_detect_credential_exposure()` on live
  parameters. New violation: `LIVE_CREDENTIAL_IN_TOOL_PARAMETER:<pattern>`.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 852 | **856** (+4) |
| npm vitest | 779 | **783** (+4) |

WildChat FPR: 493/10,000 (unchanged). `bash scripts/verify.sh` — all gates green.
