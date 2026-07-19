# Feature Specification: Guard Adversarial Hardening

**Feature Branch**: `001-guard-adversarial-hardening` (tracking-only — this is an ongoing initiative documented on `main`, not a single feature branch; see plan.md)

**Created**: 2026-07-19

**Status**: In Progress (ongoing — this spec is re-read and its tasks.md updated at the start of each future guard-hardening session, not "completed" once)

**Input**: User request: "we should use the spec kit to improve this process, otherwise we are losing track between sessions, and one session says things are good, in other sessions multiple bugs, it's not scaling." (Same request as the npm sibling package's spec — both repos are maintained under the same practice.)

## Problem Statement

Across multiple sessions of hardening the sibling `llm-trust-guard` (npm)
and this package's guards against adversarial bypass, state repeatedly
drifted between sessions:
- A session's memory summary declared "5 bugs fixed and released, all good"
  while GitHub issues #1-#2 in this repo still showed OPEN (the merging PR
  didn't reference `Closes #N`).
- A live-verify sweep against the npm package found 12 more bugs; this
  repo's own sibling issue (#4, the `CodeExecutionGuard` AST proximity bug)
  was found the same way, and was initially assumed unnecessary — the
  `CodeExecutionGuard` was cited as the "reference implementation" the npm
  fix was modeled on, before independent testing found it had its own bug.
- This session's fix for #4 itself needed a follow-up correction after
  independent adversarial review found the first-attempt AST offset
  calculation was wrong.

Root cause: nothing durable and structured lived in the repo itself. Ground
truth was reconstructed each session from a mix of chat memory, `gh issue
list`, and re-reading source — all of which can and did drift from reality.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Systematic gap-finding, not report-driven firefighting (Priority: P1)

As the maintainer, I need a repeatable methodology for finding detection gaps
in shipped guards, so bugs surface from our own process before an external
report finds them.

**Why this priority**: Issue #4 was found by a live-verify adversarial sweep,
not a bug report, and its "reference implementation" reputation almost caused
it to be skipped entirely.

**Independent Test**: Run a live-verify sweep (install the published PyPI
package, construct adversarial probes per guard, run them) against the
current published version and confirm zero new findings, or file+fix what's
found.

**Acceptance Scenarios**:

1. **Given** a guard has shipped detection patterns, **When** a live-verify
   sweep is run against the real published PyPI package, **Then** every
   finding is judge-verified (re-run against the real package) before being
   trusted as real.
2. **Given** a candidate fix for a detection gap, **When** the fix is
   implemented, **Then** an independent adversarial-review pass runs before
   the fix is considered done.

---

### User Story 2 - Fixing a false positive must not silently reopen a false negative (Priority: P1)

As the maintainer, when I narrow a detection pattern to fix a reported false
positive, I need to verify I haven't reopened detection of a real attack.

**Why this priority**: this repo's `code_execution_guard.py` proximity-window
fix for #4 initially measured AST node distance incorrectly (`col_offset`
instead of `end_col_offset`), silently letting a genuinely-adjacent gadget
pair slip through — caught only by an independent adversarial-review pass.

**Independent Test**: For every detection-pattern narrowing, run both the
original false-positive reproduction (must now pass) AND adversarial
variants of the original attack class (must still block).

**Acceptance Scenarios**:

1. **Given** a pattern is narrowed to fix a false positive, **When** the
   fix is tested against attack variants the original broader pattern
   caught, **Then** none of those variants newly bypass detection.
2. **Given** ambiguity between "fix the false positive" and "keep full
   recall," **When** the two conflict, **Then** recall is kept and the
   false positive is documented, not silently traded away.

---

### User Story 3 - Current status is readable without reconstructing it from chat history (Priority: P1)

As the maintainer (or a future session), I need the current status of every
known guard issue visible by reading a file in the repo, not by asking a
prior session or cross-checking memory notes against `gh issue list`.

**Why this priority**: this is the literal problem statement that motivated
adopting spec-kit, in both repos.

**Independent Test**: A fresh session, given only this repo and no prior
chat context, can read `specs/001-guard-adversarial-hardening/tasks.md` and
correctly state which issues are open/fixed/merged/released without running
`gh issue list` or asking the user.

**Acceptance Scenarios**:

1. **Given** a PR merges and its release ships, **When** the next session
   starts, **Then** `tasks.md` already reflects the merged/released status.
2. **Given** a new bug is found via live-verify sweeping, **When** it's
   filed as a GitHub issue, **Then** `tasks.md` is updated in the same
   work session.

### Edge Cases

- What happens when a GitHub issue's state and this repo's `tasks.md`
  disagree? `tasks.md` is a snapshot as of its last edit — a session picking
  up work MUST reconcile against `gh issue list --state all` at the start of
  a session and correct `tasks.md` if it's stale.
- What happens when this repo's guard is cited as a "reference
  implementation" for the npm sibling's fix (or vice versa)? Per
  Constitution Principle VI, that reputation MUST NOT substitute for
  independently, live-testing this repo's own implementation — exactly what
  went wrong with issue #4 before it was caught.
- What happens when npm and Python diverge? Each repo's tasks.md records its
  own state; cross-repo parity status is called out explicitly, not assumed.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Every guard-hardening session MUST reconcile `tasks.md` against
  live GitHub issue/PR state at session start if picking up prior work.
- **FR-002**: Every merged PR that fixes a filed issue MUST reference
  `Closes #N` for each issue it resolves (Constitution Principle V).
- **FR-003**: Every detection-pattern fix MUST pass an independent
  adversarial-review pass before being considered complete (Constitution
  Principle I).
- **FR-004**: Every guard touched by a fix batch MUST have corresponding
  coverage extended in that guard's existing parametrized adversarial-array
  test file, not just a one-off regression test for the literal reported
  case (Constitution Principle III).
- **FR-005**: `tasks.md` MUST record known, intentionally-unfixed gaps with
  the reason they were left open.
- **FR-006**: Merging and releasing MUST remain separate, explicitly-approved
  steps from implementing and testing a fix (Constitution Principle VII).
- **FR-007**: A guard's status as an npm-sibling "reference implementation"
  MUST NOT exempt it from independent, live adversarial testing when a
  related fix ships on either side (Constitution Principle VI).

### Key Entities

- **Guard Issue**: A filed GitHub issue describing a detection gap in a
  specific guard. States: open (unfixed) → fixed-unmerged (PR open) →
  merged (on `main`, unreleased) → released (published on PyPI, issue
  closed).
- **Adversarial Test Coverage**: This repo's existing per-guard parametrized
  test pattern (e.g. `tests/test_code_execution_ast.py`'s array-based
  true-positive/false-positive/boundary cases), extended rather than
  replaced when a new class of gap is found.
- **Fix**: Tracked individually here since, unlike the npm sibling's larger
  batch, this repo currently has a single open issue/PR pair.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of merged guard-fix PRs from this point forward reference
  the issues they close via `Closes #N`.
- **SC-002**: Every guard touched by a fix from this point forward has
  corresponding extended coverage in its adversarial test file.
- **SC-003**: A fresh session reading `tasks.md` alone can correctly answer
  "what's currently open, what's fixed-but-unreleased, and what's released."
- **SC-004**: Zero instances, going forward, of a guard being assumed
  correct (or assumed to need a fix) purely by analogy to the npm sibling
  package without independent live verification.

## Assumptions

- This spec documents an ongoing practice/process, not a one-time feature —
  `Status: In Progress` is expected to remain accurate indefinitely.
- This repo maintains its own mirrored spec at the same path as the npm
  sibling's (`specs/001-guard-adversarial-hardening/`) rather than sharing
  one, since the two repos have independent release cycles and issue
  trackers (Constitution Principle VI).
- `/speckit-implement` is not used to execute this spec's "tasks" — they are
  a status ledger, not a queue.
