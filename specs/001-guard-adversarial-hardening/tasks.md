---
description: "Living status ledger for guard adversarial hardening — READ THIS FIRST in a new session before trusting any prior summary"
---

# Tasks: Guard Adversarial Hardening

**Input**: `specs/001-guard-adversarial-hardening/{spec.md,plan.md}`

**How to use this file**: This is NOT a queue for `/speckit-implement` to
mechanically execute. It is a status ledger, updated at the end of every
guard-hardening work session. Before trusting it, reconcile against live
state: `gh issue list --repo nkratk/llm-trust-guard-python --state all`,
`gh pr list --repo nkratk/llm-trust-guard-python --state all`, PyPI JSON API
for the published version. **Last reconciled against live state: 2026-07-19.**

**Current published version**: PyPI `llm-trust-guard` v0.21.2 (does NOT yet
include the fix below — it's on unmerged PR #5)

## Phase 1: Fix batch #1 (issues #1-#2) — COMPLETE, RELEASED

- [x] T001 RAGGuard URL-decode gap, parity with npm #1 (#1) — fixed, merged (PR #3), released v0.21.2
- [x] T002 AgentSkillGuard SCH regex brittleness, parity with npm #2 (#2) — fixed, merged (PR #3), released v0.21.2
- [x] T003 Close issues #1, #2 on GitHub — done 2026-07-16 (they had stayed open post-merge; same housekeeping gap found in the npm sibling repo)

## Phase 2: Fix batch #2 (issue #4) — FIXED, TESTED, GATE-GREEN, **NOT MERGED**

**PR**: [#5](https://github.com/nkratk/llm-trust-guard-python/pull/5), branch
`fix/gadget-chain-proximity`, state OPEN as of 2026-07-19. 954/954 tests
passing, all `scripts/verify.sh` gates green. Already references `Closes #4`
(Constitution Principle V, FR-002).
**Correction (2026-07-19, same day): an earlier version of this file
incorrectly claimed no `Closes #N` reference existed — an independent judge
review caught this before it was pushed anywhere. The same error was made,
and caught the same way, in the npm sibling repo's tasks.md — see that
repo's correction note for the full incident.**

- [x] T004 `CodeExecutionGuard._ast_escape_findings()` flags a single standalone gadget-chain dunder as a sandbox escape (#4) — ported npm's 2-distinct-token/50-char-proximity-window fix, using AST node position instead of npm's raw substring search
- [x] T005 Follow-up bug found by independent adversarial review of T004's first attempt: `ast.Attribute.col_offset` measures from the start of the whole chain expression, not the attribute name, inflating measured distance and letting genuinely-adjacent (~20-char) gadget pairs through undetected — fixed via `end_lineno`/`end_col_offset` before merge
- [x] T006 Extended `tests/test_code_execution_ast.py` with 24 new cases (long-variable-name proximity variants targeting T005's bug class, more single-token benign contexts, a genuinely-far two-token case, 50/51-char boundary-inclusivity test, documented `getattr()`-gap test) — same exercise on the npm sibling found 2 new bugs; this pass found none

Documented, intentionally out of scope (not a defect to fix under this
issue):
- [ ] T007 `getattr(obj, '__subclasses__')`-style dynamic string-based attribute access is invisible to the AST pass (never produces an `ast.Attribute`/`ast.Name` node) — only the regex fallback (`getattr_dynamic`, below default risk threshold) sees it. Making every `getattr()` call itself suspicious would be a large false-positive-risk redesign, not a proximity-window tweak. Documented via a test that asserts current (accepted) behavior, not a TODO to silently change later.

## Phase 3: Process infrastructure — COMPLETE

- [x] T008 spec-kit set up in this repo (`.specify/`, `.claude/skills/speckit-*`, this spec) — 2026-07-19, mirroring the npm sibling's setup for the same reason

## Phase 4: Next steps — NOT STARTED

- [x] T009 ~~Add `Closes #4`~~ — already present (see correction note above).
- [ ] T010 **Explicit merge/release decision for PR #5** — deliberately not yet made; requires separate, explicit user confirmation per Constitution Principle VII. Typically decided alongside the npm sibling's PR #17 since both were part of the same session's fix batch, but each repo's release is independent — confirm both, not just one, before assuming "released" applies to both.
- [ ] T011 After T010, close issue #4 on GitHub (full fix, no residual gap — unlike several of the npm sibling's partial fixes, this one closes cleanly)
- [ ] T012 Cross-check whether any of the npm sibling's confirmed-but-unfixed/partially-fixed bugs (#7, #10, #11, #13, #15, #16 in that repo's tasks.md) have a Python-side equivalent that hasn't been checked yet — Constitution Principle VI explicitly warns against assuming either parity or divergence without live testing, and this check has not yet been done for the #7-#16 batch (only the original #1-#3 batch was cross-checked).
