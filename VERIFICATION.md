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
| G5 | **Two-sided regression**: (a) recall — per-category detection ≥ `recall-baseline.json`; (b) curated benign = 0 blocked, adversarial bypass = 0 leaked; (c) **TS↔Python parity** — this port reproduces `parity-vectors.json` | no recall drop, no port drift | **"not breaking the previous version"** |
| G6 | **New-tests gate**: `src/` changed since last tag ⇒ `tests/` changed too (override `ALLOW_NO_TESTS=1`) | every change is tested | **"new changes should have test cases"** |
| G7 | **CHANGELOG gate**: top version == `pyproject.toml` version | release is documented | **"consumers know what changed"** |
| G8 | **Results gate**: `tests/adversarial/RESULTS-v<version>.md` exists | claims are published | **"publish the basis for claims"** |
| G9 | **Patch coverage**: changed `src/` lines since last tag must be ≥80% covered (`diff-cover` on `coverage.xml`) | new code is *actually* tested | **"new changes should have test cases"** |
| G10 | **Freshness cadence**: `freshness.json` `lastFullScan` / each `checkedAt` within `ttlDays` (180) — `scripts/check-freshness.py`, date-only/offline | staleness *blocks* a push | **"definitely verify freshness"** |
| G11 | **README documents API changes**: `src/llm_trust_guard/__init__.py` exports changed since last tag ⇒ `README.md` changed too (override `ALLOW_NO_README_UPDATE=1`) | docs can't drift behind the public API | **"keep README current with new changes"** |

### Freshness (G10 + the weekly scan)

`RESEARCH_LOG.md` stays append-only (the audit trail; deleting it would remove the
evidence, not the staleness). G10 fails the push once any `checkedAt`/`lastFullScan` in
`freshness.json` exceeds the TTL, so you must re-scan and bump the dates before pushing.
The weekly `.github/workflows/freshness.yml` cron additionally checks source link-rot and
opens a *Freshness re-check due* issue when stale/dead — the **relevance judgment of new
research is the human/LLM step** that issue triggers, not a script decision.

**WildChat note (G5).** The 10,000-prompt WildChat-1M fixture lives only in the npm
`llm-trust-guard` repo, to avoid duplicating ~10 MB across packages. This package's
sanitizer logic is a line-for-line port, so the npm WildChat regression (block count
≤ baseline) covers it; here, regression is guarded by the **recall ratchet**
(`tests/adversarial/test_adversarial_benchmark.py` vs `recall-baseline.json`), the
corpus-free curated benign + adversarial bypass probes (`tests/test_benign_context.py`),
and the **TS↔Python parity gate** (`tests/test_parity.py`) that fails the moment this
port diverges from the npm verdicts.

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
