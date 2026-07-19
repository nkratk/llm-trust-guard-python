<!--
SYNC IMPACT REPORT
==================
Version change: (none — template placeholder) → 1.0.0 (user-directed initial ratification)

Bump rationale: Initial ratification, not a template fill-in. Mirrors
  llm-trust-guard's (the npm sibling package's) constitution principle-for-
  principle — same 7 principles, same incidents, since both repos are
  maintained by the same person under the same guard-hardening practice and
  most bugs/fixes get ported between them. Adapted for Python specifics
  (pytest/pyproject.toml/AST-based detection) where the underlying incident
  was Python-specific. Ratified alongside the npm repo's constitution on the
  same date, for the same reason: the project owner asked for spec-kit
  specifically because prior sessions lost track of state between each
  other across BOTH repos (e.g. issues #1-#2 here showed open on GitHub for
  days after their fix shipped in v0.21.2).

Principles, sections:
  - 7 principles, same set as llm-trust-guard's constitution v1.0.0
  - Principle I: tagged NON-NEGOTIABLE
  - Renamed [SECTION_2_NAME] -> Tech & Release Standards
  - Renamed [SECTION_3_NAME] -> Development Workflow & Quality Gates

Templates requiring updates:
  - .specify/templates/plan-template.md: Constitution Check gate resolves
    against this file at plan time; no template edit required.
  - .specify/templates/spec-template.md, tasks-template.md,
    checklist-template.md: no constitution-specific sections; no changes.

Follow-up TODOs: none.
-->

# llm-trust-guard-python Constitution

## Core Principles

### I. Adversarial-Test Every Detection-Pattern Change, Both Directions (NON-NEGOTIABLE)
Any change to a regex, AST-detection rule, threshold, or pattern in a guard
MUST be verified two ways before merge: (a) it still catches the attack(s) it
targets (recall), and (b) it does not newly flag plausible benign input
(precision) — verified with hand-constructed adversarial probes run against
the actual installed code, not reasoned about from the diff alone. A single
self-review pass is insufficient; an independent adversarial-review pass MUST
run after every first-attempt fix to a detection pattern.
**Rationale**: on 2026-07-19, `code_execution_guard.py`'s first-attempt
proximity-window fix for issue #4 used AST node position (`col_offset`) to
measure distance between gadget-chain tokens — an independent adversarial
review found `col_offset` actually measures from the start of the whole
attribute-chain expression, not the token itself, silently letting genuinely
adjacent (~20-char) gadget pairs slip past the window undetected. Fixed by
switching to `end_lineno`/`end_col_offset` before merge. Caught only because
a review pass specifically tried to break the fix, not just confirm it.

### II. Prefer Recall Over Precision for Security-Relevant Patterns When Forced to Choose
When a false-positive fix and full attack recall are mutually exclusive, keep
detecting the attack and accept the documented false positive, rather than
narrow a pattern to fix the false positive at the cost of missing real
attacks. Document the trade-off explicitly in code comments and CHANGELOG.
**Rationale**: mirrors the npm sibling repo's identical principle and
incidents (`fetch_url`, `markdown_image_exfil`, `html_comment_directive`
narrowings that each silently reopened a worse detection gap than the false
positive they fixed) — the same regex source and reasoning is shared between
both packages, so the same trade-off discipline applies here.

### III. Every Bug Fix Ships With a Permanent Regression Test, Not Just an Assertion of the Reported Case
A fix for a reported detection gap MUST add a test that would fail without the
fix. Where the bug belongs to a class of "input nobody thought to test," the
fix SHOULD also extend the guard's existing parametrized adversarial-array
test file (e.g. `tests/test_code_execution_ast.py`'s `ESCAPE_GADGETS`/
`BENIGN_SINGLE_TOKEN`/`BENIGN_DISTANT_TOKENS` pattern) — not just assert the
one literal reproduction string from the bug report.
**Rationale**: `code_execution_guard.py`'s false-positive bug (issue #4) was
invisible to the existing test suite until a live-verify sweep against the
published package found it — the same root cause as the npm repo's 12 bugs.
Broadened, adversarially-constructed test coverage (24 new cases added
2026-07-19: long-variable-name proximity variants, boundary-inclusivity
tests, a documented `getattr()`-gap test) is what actually closes that class
of gap going forward, not a single literal assertion.

### IV. Live-Verify Against the Real Installed Package, Not the Source Diff
Before trusting that a fix resolves an issue, or that a suspected bug is real,
run the actual reproduction against the real installed PyPI package (or the
local `src/` build), not just against reasoning about the source diff.
**Rationale**: issue #4 and every fix in this repo's guard-hardening history
were found and verified this way — `pip install llm-trust-guard==<version>`
in an isolated venv, then adversarial probes run against the real package,
not just a source read.

### V. Close the Loop: Merged + Released Fixes MUST Close Their GitHub Issue
Every PR that fixes a filed issue MUST include a closing reference
(`Closes #N`) in its description, for every issue it addresses.
**Rationale**: PR #3 (merged 2026-07-15, shipped in v0.21.2) fixed issues #1
and #2 without `Closes #N` references — both stayed open on GitHub for days
after the fix was live, requiring a manual catch-up close once the drift was
noticed. Exactly the cross-session state loss this constitution exists to
prevent.

### VI. npm/Python Guard Parity Is Not Automatic — Verify Both Sides Live
When a bug is found or fixed in the npm sibling package's guard
implementation, this repo's equivalent MUST be independently, live-tested
before assuming it either (a) needs the same fix, or (b) is already correct
and needs no fix. Never assume parity or divergence from a description alone.
**Rationale**: on 2026-07-15, this repo's `code_execution_guard.py` was
initially assumed to need no fix and was cited in CHANGELOG as the "reference
implementation" the npm gadget-chain fix was modeled on. It turned out to
have its own, different over-blocking bug (filed as #4), caught only because
it was independently tested rather than trusted on its reputation as the
"correct" reference.

### VII. Merging and Releasing Are Always Separate, Explicitly-Confirmed Steps From Fixing
A fix being correct, tested, and gate-green is necessary but not sufficient
to merge or release it. Merging to the default branch and publishing a new
PyPI release are each their own explicit decision point — never bundled into
the approval that authorized writing the fix.
**Rationale**: standing operating rule for this project, reinforced by this
repo's own practice of shipping fix batches as reviewable, gate-verified PRs
before any merge or `gh release create` is even proposed, let alone executed.

## Tech & Release Standards
- Language/runtime: Python 3.9-3.13 compatibility maintained (per
  `pyproject.toml` coverage-floor comment); stdlib-only detection where
  possible (e.g. `ast` module for `CodeExecutionGuard` — zero-dependency,
  a load-bearing project property mirroring the npm repo's zero-dependency
  standard).
- Release gate: `bash scripts/verify.sh` (G1-G13, including `__version__` /
  `pyproject.toml` sync via G13) MUST pass before any PR is opened.
- Recall ratchet: `tests/adversarial/recall-baseline.json` — mirrors the npm
  repo's baseline-ratchet discipline; recall may not silently regress below
  the locked floor without an explicit, reviewed baseline update.
- CHANGELOG.md and README.md MUST be updated in the same PR as any
  user-visible guard behavior change (enforced by verify.sh gates G7/G11/G12).
- `__version__` in the package MUST match `pyproject.toml`'s version
  (G13) — this repo has an extra gate the npm sibling doesn't, since npm's
  `package.json` is the single source of truth but Python needs both files
  kept in sync manually.

## Development Workflow & Quality Gates
- Guard-hardening workflow: live-verify sweep against the published PyPI
  package → judge-verify each candidate issue → implement fix →
  adversarial-review pass (Principle I) → extend permanent test coverage
  (Principle III) → gates green → open PR with `Closes #N` (Principle V) →
  explicit merge/release decision (Principle VII).
- Spec Kit flow for larger initiatives: `/speckit-specify` →
  `/speckit-clarify` (as needed) → `/speckit-plan` → `/speckit-tasks` →
  `/speckit-implement`, with `/speckit-analyze` as an optional cross-artifact
  consistency pass. `specs/001-guard-adversarial-hardening/` is the living
  record of this repo's ongoing hardening effort — a future session should
  read its `tasks.md` for current ground truth before trusting any prior
  session's summary, and should cross-check the npm sibling repo's
  equivalent spec for parity status (Principle VI).
- Commits: Conventional Commits (`fix:`, `feat:`, `test:`, `docs:`, `chore:`).

## Governance
This constitution supersedes ad-hoc practice for guard-hardening work in this
repository. Amendments go through `/speckit-constitution`, updating this
file's Sync Impact Report, version line, and any dependent template — and
SHOULD be mirrored to the npm sibling repo's constitution unless the change
is Python-specific. Every `/speckit-plan` run executes a Constitution Check
gate before and after design. Versioning: MAJOR (principle removed/redefined
incompatibly), MINOR (principle added or materially expanded), PATCH
(wording/typo clarification). Day-to-day operational guidance lives in
`CLAUDE.md`; this file holds the planning/design-time principles a
`/speckit-plan` run is checked against.

**Version**: 1.0.0 | **Ratified**: 2026-07-19 | **Last Amended**: 2026-07-19
