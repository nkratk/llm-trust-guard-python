# Implementation Plan: Guard Adversarial Hardening

**Branch**: `main` (ongoing process documentation, not a single feature branch) | **Date**: 2026-07-19 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `specs/001-guard-adversarial-hardening/spec.md`

## Summary

Mirrors the npm sibling package's identical plan — this documents the
repeatable *process* for finding and fixing guard detection gaps in this
repo, not a single code artifact to build. `tasks.md` is the living status
ledger a future session should read before trusting any prior summary.

## Technical Context

**Language/Version**: Python 3.9-3.13, mirrored from `llm-trust-guard` (npm)

**Primary Dependencies**: None at runtime beyond stdlib for detection logic
(e.g. `ast` for `CodeExecutionGuard`); `pytest` for testing, `specify` CLI
for this process itself

**Storage**: N/A — status lives in `tasks.md` (this spec) + GitHub
issues/PRs, reconciled against each other at session start (spec.md FR-001)

**Testing**: `pytest --ignore=tests/adversarial -q`, plus the guard's own
existing parametrized adversarial-array test files (e.g.
`tests/test_code_execution_ast.py`); gate suite `scripts/verify.sh` (G1-G13)

**Target Platform**: N/A (process/tooling, not a deployed artifact)

**Project Type**: Process documentation + status tracking for an existing
library project

**Performance Goals**: N/A

**Constraints**: Must not disrupt the existing, working guard-hardening
workflow already proven across the 2026-07-15/19 fixes.

**Scale/Scope**: Currently tracking 1 open issue (#4) in this repo, plus
cross-repo awareness of the npm sibling's 12 open issues (parity not yet
checked — see tasks.md T-series).

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Compliance | Notes |
|---|---|---|
| I. Adversarial-test every change, both directions (NON-NEGOTIABLE) | ✅ | This plan doesn't change guard code; already applied to issue #4's fix (caught the col_offset bug). |
| II. Prefer recall over precision for security patterns | ✅ | N/A to this plan directly; documented as a standing rule. |
| III. Every fix ships with permanent regression + sweep coverage | ✅ | Issue #4's fix extended `test_code_execution_ast.py` with 24 new cases. |
| IV. Live-verify against the real installed package | ✅ | Issue #4 was found and verified this way. |
| V. Close the loop — merged fixes close their issue | ✅ | tasks.md flags PR #5 as needing `Closes #4` before merge. |
| VI. npm/Python parity verified live, not assumed | ✅ | This is the principle issue #4 itself validates — this repo was wrongly assumed correct by analogy before being tested. |
| VII. Merge/release always separate from fix | ✅ | tasks.md lists "decide merge/release for PR #5" as a distinct, not-yet-completed task. |

**Verdict**: No violations.

## Project Structure

### Documentation (this feature)

```text
specs/001-guard-adversarial-hardening/
├── plan.md              # This file
├── spec.md              # Problem statement, user stories, requirements
├── tasks.md             # Living status ledger — READ THIS FIRST in a new session
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code (repository root)

No new source directories. Existing structure this process operates on:

```text
src/llm_trust_guard/guards/*.py          # Guard implementations
tests/test_*.py                          # Per-guard unit test suites
tests/test_code_execution_ast.py         # Existing parametrized adversarial-array pattern (this process's model to extend, not replace)
tests/adversarial/                       # Corpus-based benchmarks, recall-baseline ratchet
scripts/verify.sh                        # G1-G13 release gate suite
CHANGELOG.md, README.md                  # Must be updated alongside any guard behavior change
```

**Structure Decision**: No structural changes. This plan's only new
artifacts are this `specs/001-guard-adversarial-hardening/` directory and
(already delivered prior to this plan) the 24-case expansion of
`tests/test_code_execution_ast.py`.

## Complexity Tracking

No constitution violations. Table omitted.
