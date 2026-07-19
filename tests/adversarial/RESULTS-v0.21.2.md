> **Bug-fix patch.** Guard-level fixes to `rag_guard.py` and `agent_skill_guard.py`; no new threat catalog groups. Full corpus re-run not performed for this patch — see note below.

# Adversarial Benchmark Results — v0.21.2

Run date: 2026-07-15
Python mirror of npm v4.32.3 (bug-fix release).
Full corpus methodology and per-guard breakdown: [npm repo RESULTS-v4.32.2.md](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.32.2.md) (baseline; v4.32.3's own RESULTS doc documents the fixes but the 1,182-group catalog wasn't re-run for this patch either — see its note).
Suite: 959 tests, all pass (up from 949 in v0.21.1 — 10 new regression tests for the two fixes below, including 3 added after pre-merge review).

---

## Changes in v0.21.2

Two targeted guard fixes, ported from npm v4.32.3 (identical regex/logic changes; see that repo's issues #1–#3 for the original findings):

| Guard | Fix | Issue |
|---|---|---|
| `rag_guard.py` | Decode URL-encoded document content — including double-encoding, up to 3 levels — and re-scan each decoded variant before injection matching. Previously a URL-encoded payload bypassed detection entirely. | nkratk/llm-trust-guard-python#1 |
| `agent_skill_guard.py` | Loosened "fake-compliance data exfiltration" (now tolerates compliance-keyword-first phrasing, e.g. "ISO 27001 mandates: route...") and "response appending directive" (the literal word "following" is now optional) SCH patterns. | nkratk/llm-trust-guard-python#2 |

**Pre-merge review caught a false-positive regression in the first draft.** An independent review of the companion npm PR flagged that the broadened "fake-compliance" pattern was too permissive — verified live to misfire on ordinary compliance/audit prose (e.g. "Our audit process requires logging of all customer transactions for compliance purposes."). The same regex text is shared between the two packages, so this Python port carried the identical bug; it was tightened before merge to require an actual destination (`to`/`at <address>`) after the action verb, and a benign-prose regression test was added.

`code_execution_guard.py` was not changed in this PR — its native AST-based `_ast_escape_findings()` already covers Python object-introspection gadget chains (`__subclasses__`, `__globals__`, `__mro__`, etc.) by default and correctly blocks real chains, which is why it served as the reference for fixing the npm port's true-negative gap (npm #3). However, further review found it has its **own** over-blocking bug — a single standalone dunder attribute access (e.g. `cls.__subclasses__()` alone) is flagged as if it were a chain, unlike the npm fix which requires 2+ distinct tokens to co-occur. Filed separately as [nkratk/llm-trust-guard-python#4](https://github.com/nkratk/llm-trust-guard-python/issues/4) — out of scope for this PR, needs its own AST-proximity-based fix.

**Note on corpus numbers:** the 1,182-group / 5,883-payload adversarial catalog was not re-run against this patch (the corpus lives in a separate local harness repo, not checked out for this fix). The two fixed regexes are verified via 7 new targeted unit tests (`test_rag_guard.py`, `test_agent_skill_guard.py`) covering the exact previously-missed payloads plus the original canonical phrasing (to confirm no detection was lost) and a benign-content control (to confirm no new false positive). Full corpus recall figures inherited from v0.21.1/v4.32.2 (82.1%) should be treated as approximately unchanged, not re-verified at that granularity.

---

## WildChat FPR gate

| Version | Blocked / 10,000 | FPR |
|---|---|---|
| Baseline (locked) | 494 | 4.94% |
| v0.21.2 | *not independently re-measured* | — |

The 10k WildChat fixture lives only in the npm repo (git-lfs); Python regression is guarded by the corpus-free benign/bypass probes in `tests/test_benign_context.py` (51/51 pass) and `tests/adversarial/test_adversarial_benchmark.py` (11/11 pass), both unchanged after this patch.

---

## npm↔Python parity gate

File: `tests/guard-parity-vectors.json`
Vectors: 46 (Python-handled guards), unchanged from v0.21.1
Python gate (`test_guard_parity.py`): pass (no parity vectors touched by this patch)

---

## Verification commands

```bash
# Full suite
python3 -m pytest tests/ -q --ignore=tests/adversarial/datasets

# The two fixed guards specifically
python3 -m pytest tests/test_rag_guard.py tests/test_agent_skill_guard.py -v

# Corpus-free regression probes
python3 -m pytest tests/test_benign_context.py tests/adversarial/test_adversarial_benchmark.py -q
```
