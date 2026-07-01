# Results — v0.12.0 (Sneaky Bits detection + MCP credential exposure scanning)

- **Date:** 2026-06-30
- **Library version:** 0.12.0 (PyPI) / 4.23.0 (npm)
- **Change:** guard enhancement × 2 — additive, no breaking changes

## Why

1. **Sneaky Bits encoding (NVIDIA 2025, CVE-2025-32711 "EchoLeak")** — invisible
   operators U+2062/U+2064 and variation selectors (2+ consecutive) were undetected.
2. **MCP credential aggregation** — 48% of MCP servers store credentials in
   plaintext (Astrix Security, 2025). `validate_server_registration()` scanned key
   names but not credential values.

## Fix

- **`EncodingDetector`** — Detects invisible operators + variation selectors.
  New violation `SNEAKY_BITS_ENCODING_DETECTED` for binary-encoded streams.
- **`MCPSecurityGuard`** — New `detect_credential_exposure` option (default True).
  Walks entire registration object for AWS keys, GitHub PATs, Bearer/JWT tokens,
  Stripe keys, Slack tokens, Google API keys. Violation: `credential_exposed: <type>`.

## Measured

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 834 | **844** (+10) |
| npm vitest | 753 | **763** (+10) |

## Verification

- `bash scripts/verify.sh` — all gates green.
- `ruff` clean. Full suite green (844 passed). TS↔Python parity maintained.
