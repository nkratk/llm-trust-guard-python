> **Bug-fix patch.** Guard-level fixes to `rag_guard.py` and `agent_skill_guard.py`; no new threat catalog groups. Full corpus re-run not performed for this patch — see note below.

# Adversarial Benchmark Results — v0.21.2

Run date: 2026-07-15
Python mirror of npm v4.32.3 (bug-fix release).
Full corpus methodology and per-guard breakdown: [npm repo RESULTS-v4.32.2.md](https://github.com/nkratk/llm-trust-guard/blob/main/tests/adversarial/RESULTS-v4.32.2.md) (baseline; v4.32.3's own RESULTS doc documents the fixes but the 1,182-group catalog wasn't re-run for this patch either — see its note).
Suite: 956 tests, all pass (up from 949 in v0.21.1 — 7 new regression tests for the two fixes below).

---

## Changes in v0.21.2

Two targeted guard fixes, ported from npm v4.32.3 (identical regex/logic changes; see that repo's issues #1–#3 for the original findings):

| Guard | Fix | Issue |
|---|---|---|
| `rag_guard.py` | Decode URL-encoded document content (and re-scan the decoded variant) before injection matching. Previously a URL-encoded payload bypassed detection entirely. | nkratk/llm-trust-guard-python#1 |
| `agent_skill_guard.py` | Loosened "fake-compliance data exfiltration" (now tolerates compliance-keyword-first phrasing, e.g. "ISO 27001 mandates: route...") and "response appending directive" (the literal word "following" is now optional) SCH patterns. | nkratk/llm-trust-guard-python#2 |

`code_execution_guard.py` needed no change — its native AST-based `_ast_escape_findings()` already covers Python object-introspection gadget chains (`__subclasses__`, `__globals__`, `__mro__`, etc.) by default; this was in fact the reference implementation used to fix the corresponding gap in the npm port (npm #3).

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
