# Contributing to llm-trust-guard (Python)

This package is a line-for-line port of the npm `llm-trust-guard` security library
and tracks the same threat model and version cadence.

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"        # pytest, pytest-cov, ruff
pytest --ignore=tests/adversarial
```

## Verification (required before push)

Run one command — it runs compile, the full suite, the coverage floor, the curated
benign probe, and the adversarial-bypass probe, plus the changelog/results checks:

```bash
bash scripts/verify.sh
```

This is enforced both locally (`.githooks/pre-push`, install via
`bash scripts/install-hooks.sh`) and in CI, so it can't be skipped. See
[VERIFICATION.md](VERIFICATION.md) for the eight gates.

## PR checklist

- [ ] `bash scripts/verify.sh` is green (see [VERIFICATION.md](VERIFICATION.md))
- [ ] New/changed `src/` ships with tests (gate **G6**)
- [ ] `CHANGELOG.md` top entry matches the `pyproject.toml` version (gate **G7**)
- [ ] `tests/adversarial/RESULTS-v<version>.md` written for any release/claim (gate **G8**)
- [ ] `RESEARCH_LOG.md` entry added if the change cites a threat/technique/benchmark
- [ ] Parity with the npm package preserved (same patterns, weights, thresholds)

## Commit format

Conventional Commits (`feat(scope):`, `fix:`, `chore:`, `docs:`, `test:`). No
`Co-Authored-By` trailer. Never use `--no-verify`.
