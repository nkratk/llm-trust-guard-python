# Results — v0.10.3 (AST-based sandbox-escape detection)

- **Date:** 2026-06-09
- **Library version:** 0.10.3 (Python)
- **Change:** `CodeExecutionGuard.analyze()` adds a Python `ast` pass (stdlib, zero deps)
- **Harness:** `tests/test_code_execution_ast.py` (+ existing `tests/test_code_execution_guard.py`)

## TL;DR

Regex static analysis cannot see Python sandbox-escape gadget chains
(`().__class__.__bases__[0].__subclasses__()`) or dynamic-import gadgets. An `ast`
pass — layered on top of the regex scan, strictly additive — closes that gap with no
false-positive regression.

## Results (measured against the pre-change guard at HEAD)

| Probe | n | Before (regex) | After (regex + ast) |
|---|---|---|---|
| Sandbox-escape gadgets (must block) | 5 | **0 blocked** | **5 blocked** |
| Benign Python (must allow) | 6 | 0 blocked | **0 blocked** (no FP) |
| Existing CodeExecutionGuard tests | 10 | pass | pass |
| New AST tests | 15 | — | pass |

The five escape gadgets:
`().__class__.__bases__[0].__subclasses__()`, `obj.__globals__['os'].system('id')`,
`[].__class__.__base__.__subclasses__()[40]`, `(lambda: None).__code__.co_consts`,
`x.__reduce__()`.

## Scope & honesty

- **Detection, not sandboxing.** This does NOT add a runtime sandbox. Actual isolation
  (containers / Firecracker microVMs / seccomp / WASM) remains a host concern; the guard
  is the decision layer in front of it. We deliberately do not ship a half-sandbox.
- **Additive only.** The ast pass can only add findings; benign behavior is unchanged,
  unparseable code falls back to regex, non-Python code is language-gated out.
- **Dunder set is high-signal:** `__subclasses__`, `__bases__`, `__mro__`, `__base__`,
  `__globals__`, `__builtins__`, `__import__`, `__getattribute__`, `__reduce__(_ex__)`,
  `__code__`, `__closure__`. `__class__`/`__dict__` are deliberately excluded (more common
  in benign metaprogramming) to keep FPs at zero.

## Intentional TS/Python divergence

Python's stdlib `ast` makes this zero-dependency. JavaScript has no stdlib parser, so the
npm `llm-trust-guard` keeps regex here and will adopt a **pluggable parser adapter**
(acorn for minimal footprint / oxc for speed) rather than bundling a parser — preserving
its zero-dependency guarantee. See `RESEARCH_LOG.md`.

## Reproduce

```bash
python3 -m pytest tests/test_code_execution_ast.py tests/test_code_execution_guard.py -q
bash scripts/verify.sh
```
