# Results — v0.15.0 (InputSanitizer: policy puppetry + bidi + persona patterns)

- **Date:** 2026-07-02
- **Library version:** 0.15.0 (PyPI) / 4.26.0 (npm)
- **Driven by:** Same 395-miss cluster as TS v4.26.0

## Changes

Mirror of TS v4.26.0. See RESULTS-v4.26.0.md in the TS package for the full table.

9 new `InputSanitizer` patterns: `llm_ini_namespace`, `llama2_sys_fencing`,
`json_safety_false`, `json_system_override`, `ini_inline_key_value`, `mode_activation`,
`system_override_engaged`, `instructions_void`, `forget_your_instructions`.

Extended `named_jailbreak_persona` to also match `persona|profile|\s+active|\s+enabled`.

Extended bidi strip to U+202A–U+202F and U+200E/200F.

## Test suite

| Suite | Before | After |
|-------|-------:|------:|
| Python pytest | 856 | **874** (+18) |

WildChat FPR: 494/10,000 (4.94%). `bash scripts/verify.sh` — all gates green.
