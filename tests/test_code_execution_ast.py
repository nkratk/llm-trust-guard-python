"""
AST-based sandbox-escape detection for CodeExecutionGuard (Python only).

Regex cannot see gadget chains like `().__class__.__bases__[0].__subclasses__()`;
the ast pass catches them. Strictly additive — benign code must stay allowed, and
unparseable code still falls back to the regex scan.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.code_execution_guard import CodeExecutionGuard

# Sandbox-escape gadgets that the regex pass does NOT catch (measured 0/5 -> 5/5).
ESCAPE_GADGETS = [
    "().__class__.__bases__[0].__subclasses__()",
    "obj.__globals__['os'].system('id')",
    "[].__class__.__base__.__subclasses__()[40]",
    "(lambda: None).__code__.co_consts",
    "x.__reduce__()",
]

# Benign Python that must remain allowed (no false positives from the ast pass).
BENIGN = [
    "print('hello world')",
    "result = [i * 2 for i in range(10)]",
    "def add(a, b):\n    return a + b",
    "import json\njson.loads('{}')",
    "data = {'k': 'v'}\nprint(data['k'])",
    "class Foo:\n    def bar(self):\n        return self.value",
]


@pytest.mark.parametrize("code", ESCAPE_GADGETS)
def test_ast_blocks_sandbox_escape_gadgets(code):
    assert CodeExecutionGuard().analyze(code, "python").allowed is False, code


@pytest.mark.parametrize("code", BENIGN)
def test_ast_allows_benign_python(code):
    assert CodeExecutionGuard().analyze(code, "python").allowed is True, code


def test_ast_violation_is_reported():
    res = CodeExecutionGuard().analyze("().__class__.__subclasses__()", "python")
    assert any("ast_sandbox_escape" in v for v in res.violations), res.violations


def test_dynamic_import_call_flagged():
    res = CodeExecutionGuard().analyze("__import__('os').system('id')", "python")
    assert res.allowed is False
    assert any("ast_" in v or "builtins" in v for v in res.violations), res.violations


def test_unparseable_python_falls_back_to_regex():
    # Invalid syntax -> ast.parse raises -> ast pass returns None, but the regex
    # scan still runs and catches eval(.
    res = CodeExecutionGuard().analyze("eval('x' + ", "python")
    assert res.allowed is False


def test_ast_pass_is_python_only():
    # The dunder text in JS source must not trip the Python ast pass (lang gate).
    js = "const s = '__subclasses__'; console.log(s);"
    res = CodeExecutionGuard().analyze(js, "javascript")
    assert not any("ast_sandbox_escape" in v for v in res.violations), res.violations
