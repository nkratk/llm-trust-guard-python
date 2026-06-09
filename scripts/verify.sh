#!/usr/bin/env bash
#
# Eval-gated verification — run before every push. See VERIFICATION.md.
# Exits non-zero if any blocking gate fails. CI and the .githooks/pre-push hook
# both call this script.
#
set -uo pipefail
cd "$(dirname "$0")/.." # repo root

PY="${PYTHON:-python3}"
FAILED=0
hr() { printf '%s\n' "────────────────────────────────────────────────────────"; }

gate() { local name="$1"; shift; hr; echo "▶ $name"
  if "$@"; then echo "  ✓ PASS — $name"; else echo "  ✗ FAIL — $name"; FAILED=1; fi; }
soft_gate() { local name="$1"; shift; hr; echo "▶ $name (non-blocking)"
  if "$@" >/tmp/verify_soft_py.log 2>&1; then echo "  ✓ PASS — $name"; else echo "  ! WARN — $name (not blocking)"; fi; }

# ── G1: compile / typecheck
gate "G1 compile" "$PY" -m compileall -q src

# ── G2: lint (non-blocking, mirrors CI)
soft_gate "G2 lint (ruff)" "$PY" -m ruff check src

# ── G3 + G4 + G5: full suite + coverage threshold (fail_under in pyproject).
# The suite includes the curated benign probe and the adversarial bypass probe
# (tests/test_benign_context.py). The 10k WildChat fixture lives only in the npm
# repo; Python regression is guarded by the corpus-free probes.
gate "G3+G4 tests + coverage" \
  "$PY" -m pytest --ignore=tests/adversarial --cov=llm_trust_guard \
  --cov-report=term-missing --cov-report=xml -q

# ── G5: two-sided regression — recall ratchet on the adversarial benchmark
# (excluded from the default run above, so run it explicitly here) plus the
# corpus-free benign/bypass probes already covered by G3.
gate "G5 recall ratchet (recall-baseline.json)" \
  "$PY" -m pytest tests/adversarial/test_adversarial_benchmark.py -q

# ── G9: patch coverage — CHANGED src lines (since last tag) must be covered.
# Enforced in CI; degrades to a skip locally if diff-cover isn't installed.
patch_cov() {
  "$PY" -m diff_cover.diff_cover_tool --version >/dev/null 2>&1 || {
    echo "  diff-cover not installed — skipping locally (CI enforces). pip install diff-cover"; return 0; }
  local tag; tag=$(git describe --tags --abbrev=0 2>/dev/null) || { echo "  no tag — skipping"; return 0; }
  [ -f coverage.xml ] || { echo "  coverage.xml missing"; return 1; }
  "$PY" -m diff_cover.diff_cover_tool coverage.xml --compare-branch "$tag" --fail-under "${PATCH_COV_MIN:-80}"
}
gate "G9 patch coverage (changed src lines >=${PATCH_COV_MIN:-80}%)" patch_cov

# ── G6: new code must ship with tests (hard gate; override ALLOW_NO_TESTS=1)
gate "G6 new code has tests" bash -c '
  tag=$(git describe --tags --abbrev=0 2>/dev/null) || { echo "  no tag yet — skipping G6"; exit 0; }
  changed=$( { git diff --name-only "$tag" --; git ls-files --others --exclude-standard; } | sort -u )
  src=$(echo "$changed" | grep -E "^src/" || true)
  tst=$(echo "$changed" | grep -E "^tests/" || true)
  if [ -n "$src" ] && [ -z "$tst" ]; then
    if [ "${ALLOW_NO_TESTS:-0}" = "1" ]; then echo "  src/ changed without tests/, but ALLOW_NO_TESTS=1"; exit 0; fi
    echo "  src/ changed since $tag but no tests/ change:"; echo "$src" | sed "s/^/    /"; exit 1
  fi
  echo "  ok (changed since $tag)"; exit 0'

# ── G7: CHANGELOG top version == pyproject version
gate "G7 changelog matches version" bash -c '
  pv=$(grep -m1 -oE "^version = \"[0-9.]+\"" pyproject.toml | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
  cv=$(grep -m1 -oE "## [0-9]+\.[0-9]+\.[0-9]+" CHANGELOG.md | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
  echo "  pyproject=$pv  CHANGELOG=$cv"
  [ "$pv" = "$cv" ]'

# ── G8: published results doc exists for this version
gate "G8 results doc present" bash -c '
  pv=$(grep -m1 -oE "^version = \"[0-9.]+\"" pyproject.toml | grep -oE "[0-9]+\.[0-9]+\.[0-9]+")
  f="tests/adversarial/RESULTS-v$pv.md"
  echo "  expecting $f"; test -f "$f"'

hr
if [ "$FAILED" = "0" ]; then echo "✅ verify: ALL GATES PASSED"; else echo "❌ verify: ONE OR MORE GATES FAILED — push is not allowed"; fi
exit $FAILED
