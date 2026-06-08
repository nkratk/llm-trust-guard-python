# Verification standard

This repo ships a security library. We hold changes to an **eval-gated,
reproducibility-first** bar: nothing is pushed until an automated pipeline proves
it doesn't break the previous version, ships its own tests, is backed by
re-runnable numbers, and is documented for consumers.

> **Framing.** This is *our* standard, inspired by how eval-gated releases work in
> general. It is **not** a description of any third party's internal process —
> inventing that would violate the very "don't claim what you can't show" rule
> this document exists to enforce.

One command runs everything:

```bash
bash scripts/verify.sh          # PYTHON=python3 by default
```

Enforced in **two places**:

1. **Local** — `.githooks/pre-push` runs `scripts/verify.sh` before every push (and
   chains the Git-LFS pre-push hook). Install once: `bash scripts/install-hooks.sh`.
2. **CI** — `.github/workflows/ci.yml` runs the same script server-side.

## The eight gates

| # | Gate | What it proves | The concern it answers |
|---|------|----------------|------------------------|
| G1 | Compile (`python -m compileall src`) | code imports cleanly | not breaking |
| G2 | Lint (`ruff check src`, non-blocking) | style | quality |
| G3 | Full unit suite (`pytest --ignore=tests/adversarial`) | behavior intact | "all tests pass" |
| G4 | Coverage floor (`fail_under` in `pyproject.toml`, currently 70%) | new code is exercised | "new changes have test cases" |
| G5 | **Regression**: curated benign probe = 0 blocked; adversarial bypass probe = 0 leaked | no FP/FN regression | **"not breaking the previous version"** |
| G6 | **New-tests gate**: `src/` changed since last tag ⇒ `tests/` changed too (override `ALLOW_NO_TESTS=1`) | every change is tested | **"new changes should have test cases"** |
| G7 | **CHANGELOG gate**: top version == `pyproject.toml` version | release is documented | **"consumers know what changed"** |
| G8 | **Results gate**: `tests/adversarial/RESULTS-v<version>.md` exists | claims are published | **"publish the basis for claims"** |

**WildChat note (G5).** The 10,000-prompt WildChat-1M fixture lives only in the npm
`llm-trust-guard` repo, to avoid duplicating ~10 MB across packages. This package's
sanitizer logic is a line-for-line port, so the npm WildChat regression (block count
≤ baseline) covers it; here, regression is guarded by the corpus-free curated benign
probe and adversarial bypass probe in `tests/test_benign_context.py`.

## How each recurring concern is enforced (not remembered)

- **Research current?** → dated entries with source links in [`RESEARCH_LOG.md`](./RESEARCH_LOG.md).
- **Breaking previous version?** → G3 + G5.
- **Making numbers up?** → every CHANGELOG/RESULTS number is produced by a committed
  test; "before" numbers measured against the prior tag.
- **Consumers informed?** → G7 + a per-release `RESULTS-v<version>.md`.
- **New code untested?** → G6 fails the push.

## Release flow

```
1. Change + tests.                    4. Write tests/adversarial/RESULTS-v<version>.md.
2. RESEARCH_LOG.md entry if needed.   5. bash scripts/verify.sh   # green
3. Bump pyproject version + CHANGELOG.6. git tag -a v<version> ; push main + tag.
```

## Overrides

- `ALLOW_NO_TESTS=1 bash scripts/verify.sh` — pure refactor/doc change (say why in the commit).
