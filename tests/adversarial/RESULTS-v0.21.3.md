> **Bug-fix patch.** Guard-level fix to `code_execution_guard.py`; no new threat catalog groups. Full corpus re-run not performed for this patch — see note below.

# Adversarial Benchmark Results — v0.21.3

Run date: 2026-07-19
Companion release to npm v4.32.4 (bug-fix release), though this patch fixes a different, Python-specific bug than npm's v4.32.4 batch (npm's fixes were in `ExternalDataGuard`/`OutputFilter`/`OutputGuard`/`PromptLeakageGuard`; this repo's fix is in `CodeExecutionGuard`, which npm's own v4.32.3 already fixed independently — see below).
Suite: 964 tests, all pass (up from 954 pre-merge — includes the merge of `main`'s intervening changes plus a follow-up README fix).

---

## Changes in v0.21.3

One targeted guard fix (issue nkratk/llm-trust-guard-python#4), porting an already-adversarially-reviewed npm fix:

| Guard | Fix | Issue |
|---|---|---|
| `code_execution_guard.py` | `_ast_escape_findings()`'s gadget-chain detector flagged a single, standalone dunder attribute access (e.g. `cls.__subclasses__()` for plugin discovery, `def __reduce__` for pickle support) as a sandbox escape. Now mirrors npm's `hasPythonGadgetChain` fix (shipped in npm v4.32.3): only fires when 2+ distinct gadget-chain tokens co-occur within a 50-character proximity window. | nkratk/llm-trust-guard-python#4 |

**Independent adversarial review of the first implementation attempt found a real follow-up bug before merge.** The initial proximity-window implementation measured distance using `ast.Attribute.col_offset`, which actually points at the start of the *whole chain expression*, not the attribute name itself — this inflated the measured gap between two separate references and let a genuinely-adjacent (~20-char) gadget pair slip past the window undetected. Fixed by using `end_lineno`/`end_col_offset` instead, which lands right after the attribute name. Confirms the standing practice (this repo's Constitution Principle I) of never trusting a single implementation pass for a detection-pattern change.

Extended `tests/test_code_execution_ast.py`'s existing parametrized coverage with 24 new cases (documented in CHANGELOG). The same broadened-sweep exercise run against the npm sibling package found 2 new bugs on first use; this Python pass found none — consistent with AST-based detection's inherent precision advantage over npm's raw substring search.

**Note on corpus numbers:** the 1,182-group / 5,883-payload adversarial catalog was not re-run against this patch. The fix is independently verified via 30 targeted unit tests in `tests/test_code_execution_ast.py` (6 pre-existing + 24 new), covering the exact previously-missed payload class, the previously-existing true positives (to confirm no detection was lost), and multiple benign-content controls (to confirm no new false positive). Full corpus recall figures inherited from v0.21.2 (82.1%) should be treated as approximately unchanged, not re-verified at that granularity.

---

## WildChat FPR gate

No local WildChat fixture / FPR gate exists in this repo (npm-only infrastructure) — see this repo's constitution note on npm/Python parity not being automatic. Not applicable here.

---

## Full guard recall summary

*Inherited from [RESULTS-v0.21.2.md](RESULTS-v0.21.2.md) — not independently re-verified for this patch. This fix should only move `CodeExecutionGuard` recall/precision, specifically narrowing a false-positive class, per the targeted test evidence above.*
