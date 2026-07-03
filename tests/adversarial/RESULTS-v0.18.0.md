# Results — v0.18.0 (MCPSecurityGuard: preprocessing + 20 new patterns, 19.09% → 97.95%)

- **Date:** 2026-07-03
- **Library version:** 0.18.0 (PyPI) / 4.29.0 (npm)
- **Driven by:** Mirror of TS v4.29.0

See RESULTS-v4.29.0.md in the TS package for the full pattern table.

`MCPSecurityGuard`: `_preprocess_content()` (ZWSP strip, URL/hex/base64 decode, reverse, Cyrillic normalise),
`sd_retry_forever`, updated `sd_from_now_on` / `sd_ignore_previous`, 4 new command injection patterns
(`embedded_abs_path`, `cursor_mcp_inject`, `dangerous_scheme`, `mcp_endpoint_override`),
2 updated command injection patterns (`git_injection`, `env_injection`),
8 new `_LINE_JUMPING_PATTERNS` (`authority_directive`, `exfil_routing`, `schema_mutation_str`,
`mcp_tool_shadow`, `mcp_impersonation`, `rug_pull_descriptor`, `html_comment_injection`, `homoglyph_cyrillic`),
updated `instruction_override`.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 856 | **856** |

`bash scripts/verify.sh` — all gates green.
