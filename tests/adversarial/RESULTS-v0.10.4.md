# Results — v0.10.4 (docs: AST detection + README-sync gate)

- **Date:** 2026-06-12
- **Library version:** 0.10.4 (Python)
- **Change:** documentation only — no code/behavior change

## Summary

The README did not document the stdlib-`ast` sandbox-escape detection added to
`CodeExecutionGuard` in 0.10.3. This docs release fixes that and adds a gate so it
can't recur.

- **README**: documented the AST sandbox-escape detection with an example, and the
  intentional npm-vs-Python divergence (pluggable backend vs stdlib `ast`).
- **New gate G11**: public exports (`src/llm_trust_guard/__init__.py`) changing since
  the last tag now *require* a `README.md` change (override `ALLOW_NO_README_UPDATE=1`).

## Verification

- `bash scripts/verify.sh` — all 11 gates green (G11 added).
- No source change ⇒ recall/parity/coverage baselines unchanged from 0.10.3.

```bash
bash scripts/verify.sh
```
