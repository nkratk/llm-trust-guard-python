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
for the published version. **Last reconciled against live state: 2026-07-19
(post-release).**

**Current published version**: PyPI `llm-trust-guard` v0.21.3 — confirmed
live via the PyPI JSON API after `gh release create` triggered the publish
workflow (GitHub Actions run succeeded). Issue #4 remained correctly closed
through the release tagging.

Note: unlike the npm sibling repo, squash-merging this PR did **not** cause
any stray issue auto-closes — `git log` across the full commit range showed
only the intended `Closes #4` reference, no leftover stale closing keywords
from an earlier, later-reverted attempt (this repo's fix for #4 didn't need
a revert-and-retry cycle the way several of npm's did). Verified by the same
grep-based check the npm incident prompted adding to this file's process.

## Phase 1: Fix batch #1 (issues #1-#2) — COMPLETE, RELEASED

- [x] T001 RAGGuard URL-decode gap, parity with npm #1 (#1) — fixed, merged (PR #3), released v0.21.2
- [x] T002 AgentSkillGuard SCH regex brittleness, parity with npm #2 (#2) — fixed, merged (PR #3), released v0.21.2
- [x] T003 Close issues #1, #2 on GitHub — done 2026-07-16 (they had stayed open post-merge; same housekeeping gap found in the npm sibling repo)

## Phase 2: Fix batch #2 (issue #4) — FIXED, TESTED, GATE-GREEN, **MERGED, NOT RELEASED**

**PR**: [#5](https://github.com/nkratk/llm-trust-guard-python/pull/5), branch
`fix/gadget-chain-proximity`, **MERGED to main 2026-07-19 19:35 UTC**
(squash). Also required a follow-up commit post-merge: merging `main` in
surfaced a genuine G11 gate failure (README.md never got an entry for this
fix — CHANGELOG.md did, README.md was missed) that the pre-merge local
`verify.sh` runs hadn't caught, since G11 diffs against the last *tagged*
release and that comparison only became fully accurate once main's real
history was merged in. Fixed same-day before pushing. 964/964 tests passing
post-merge, all `scripts/verify.sh` gates green. Already references
`Closes #4`
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

## Phase 4: Next steps

- [x] T009 ~~Add `Closes #4`~~ — already present (see correction note above).
- [x] T010 **Explicit merge decision for PR #5** — user confirmed 2026-07-19, alongside the npm sibling's PR #17; merged (squash) to main.
- [x] T010b **Explicit release decision** — user confirmed 2026-07-19 alongside the npm sibling's release; `gh release create v0.21.3` run, publish workflow succeeded, confirmed live on PyPI.
- [x] T011 Issue #4 auto-closed correctly on merge (full fix, no residual gap — confirmed via `gh issue view 4`, no incident here unlike the npm sibling repo's #5/#11/#15).
- [ ] T012 Cross-check whether any of the npm sibling's confirmed-but-unfixed/partially-fixed bugs (#7, #10, #11, #13, #15, #16 in that repo's tasks.md) have a Python-side equivalent that hasn't been checked yet — Constitution Principle VI explicitly warns against assuming either parity or divergence without live testing, and this check has not yet been done for the #7-#16 batch (only the original #1-#3 batch was cross-checked).
