# Project Rules for Claude

## CRITICAL: Data Freshness Validation

**Before starting ANY task involving datasets, training data, or benchmarks:**

1. **Check data dates FIRST** — look at filenames, headers, and file mtimes. Flag anything older than 12 months.
2. **Web search for newer alternatives** — search for `"<domain> dataset <current year>"` before using local data.
3. **Report findings to user** — tell the user what data is available, its age, and newer alternatives. Wait for approval before proceeding.
4. **Never silently use stale data** — if local data is from >12 months ago, STOP and ask.

This rule exists because I once trained a classifier on Dec 2023 data in April 2026 and wasted hours. Don't repeat that.

## Honesty Rules

1. **Never claim detection percentages without measuring them** — if you don't have numbers from an actual test run, say "I don't have numbers yet."
2. **Never claim "improvement" without a baseline measurement** — measure before AND after, not just after.
3. **Always use train/test splits for ML** — never evaluate on training data.
4. **Flag dataset quality issues** — label noise, contamination, bias. Tell the user.

## CHANGELOG Rule

Every version bump MUST include a CHANGELOG.md update before commit. Both npm (`CHANGELOG.md`) and Python (`CHANGELOG.md`) repos.

## Git Rules

- No `Co-Authored-By` trailer on commits in this project
- Never use `--no-verify` to skip hooks
- Always run tests before pushing

## Build Requirements

- npm: `npm test` must pass all 695+ tests
- Python: `pytest --ignore=tests/adversarial` must pass all 677+ tests
- Coverage thresholds must not be lowered to make builds pass

## Testing Against Real Data

When benchmarking detection:
- Use HELD-OUT data the model never saw during training
- Test on MULTIPLE datasets (not just training distribution)
- Report FP rate on safe-prompt datasets representative of production traffic
- Distinguish between curated test suites and real-world data
