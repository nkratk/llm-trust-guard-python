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

# Sandbox-escape gadgets that the regex pass does NOT catch. Each of these
# has 2+ DISTINCT gadget-chain dunders within the 50-char proximity window —
# real gadget chains are tightly-chained attribute accesses, not a single
# dunder (see BENIGN_SINGLE_TOKEN below for that case).
ESCAPE_GADGETS = [
    "().__class__.__bases__[0].__subclasses__()",
    "[].__class__.__base__.__subclasses__()[40]",
    "().__class__.__bases__[0].__subclasses__()[133].__init__.__globals__['sys'].modules['os'].popen('id').read()",
    "x.__class__.__mro__[1].__subclasses__()",
    "type(x).mro()[0].__subclasses__()",
    # Long variable name before a short-named token — regression coverage for
    # the offset bug (col_offset measures from the START of the whole chain
    # expression, not the attribute name) that an adversarial review round
    # caught after the initial proximity-window fix: this genuinely-adjacent
    # (~20-char) pair was silently allowed until end_offset was used instead.
    "(some_plugin_registry_base_object_for_lookup.__subclasses__(), y.__globals__)",
    "(configuration_manager_instance.__bases__, another_config_helper.__globals__)",
    "type(payload_handler).mro()[0].__subclasses__()",
    "x.__reduce__(), y.__reduce_ex__()",
    "fn.__code__, fn.__closure__",
    "obj.__class__ \\\n    .__bases__[0].__subclasses__()",
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

# A single gadget-chain dunder alone is common in legitimate code (plugin
# discovery, pickle support) and must NOT block on its own — this is the
# false-positive bug fixed in this batch (nkratk/llm-trust-guard-python#4).
BENIGN_SINGLE_TOKEN = [
    "obj.__globals__['os']",  # single token, no companion within window
    "(lambda: None).__code__.co_consts",
    "x.__reduce__()",
    "class PluginRegistry:\n    def discover(self):\n        return PluginBase.__subclasses__()",
    "class MyPickleable:\n    def __reduce__(self):\n        return (MyPickleable, ())",
    "type(x).mro()",
    "config = {'cls': SomeClass.__subclasses__}",
    "name = f'{obj.__class__.__name__}'",
    "sorted(Base.__subclasses__(), key=lambda c: c.__name__)",
    "def log_call(fn):\n    print(fn.__code__.co_name)",
    "def inspect(fn):\n    return fn.__closure__",
    # A dunder appearing only as a plain string literal is never visited as
    # an ast.Attribute/Name node, so it correctly can't contribute to a chain.
    "s = 'this text mentions __subclasses__ and __globals__ but is just a string'",
]

# Two distinct gadget tokens used far apart (outside the proximity window, in
# unrelated functions) must NOT be treated as a chain.
BENIGN_DISTANT_TOKENS = [
    "def get_all_subclasses(cls):\n    for subclass in cls.__subclasses__():\n"
    "        yield subclass\n\n\ndef method_resolution_order(cls):\n    return cls.__mro__",
    "def get_subclasses_for_registry(cls):\n    return cls.__subclasses__()\n\n\n"
    "def unrelated_helper_for_mro_lookup(cls):\n    return cls.__globals__\n",
]


@pytest.mark.parametrize("code", ESCAPE_GADGETS)
def test_ast_blocks_sandbox_escape_gadgets(code):
    assert CodeExecutionGuard().analyze(code, "python").allowed is False, code


@pytest.mark.parametrize("code", BENIGN)
def test_ast_allows_benign_python(code):
    assert CodeExecutionGuard().analyze(code, "python").allowed is True, code


@pytest.mark.parametrize("code", BENIGN_SINGLE_TOKEN)
def test_ast_allows_single_gadget_token_alone(code):
    assert CodeExecutionGuard().analyze(code, "python").allowed is True, code


@pytest.mark.parametrize("code", BENIGN_DISTANT_TOKENS)
def test_ast_allows_distant_distinct_tokens(code):
    assert CodeExecutionGuard().analyze(code, "python").allowed is True, code


def test_ast_proximity_window_boundary_is_inclusive_at_exactly_50_chars():
    # Two distinct tokens whose end-offsets are exactly 50 chars apart must
    # still be flagged (window is `> 50` skip, i.e. `<= 50` flags); at 51
    # chars apart they must not be.
    pad_50 = "a" * 33
    code_at_boundary = f"x.__globals__; {pad_50}.__subclasses__()"
    res = CodeExecutionGuard().analyze(code_at_boundary, "python")
    assert res.allowed is False, res.violations

    pad_51 = "a" * 34
    code_past_boundary = f"x.__globals__; {pad_51}.__subclasses__()"
    res = CodeExecutionGuard().analyze(code_past_boundary, "python")
    assert res.allowed is True, res.violations


def test_ast_does_not_see_getattr_based_dynamic_gadget_access():
    # Known, documented, out-of-scope limitation (pre-existing, not
    # introduced or fixed by the proximity-window change): getattr(obj,
    # '__subclasses__')-style dynamic string-based attribute access never
    # produces an ast.Attribute/Name node, so the AST pass can't see it —
    # only the regex fallback (getattr_dynamic, below the default risk
    # threshold) does. This test documents the gap rather than asserting a
    # fix, so a future change doesn't silently "fix" it without a deliberate
    # design decision (getattr is used constantly in legitimate code; making
    # every getattr(...) call itself suspicious would be a large FP-risk
    # redesign, not a proximity-window tweak).
    code = "g = getattr(().__class__, '__bases__')[0]\ns = getattr(g, '__subclasses__')()"
    res = CodeExecutionGuard().analyze(code, "python")
    assert res.allowed is True, res.violations


def test_ast_measures_distance_from_the_end_of_the_attribute_not_the_start_of_the_chain():
    # ast.Attribute.col_offset points at the START of the whole chain
    # expression (e.g. the object being accessed), not at the attribute name
    # itself — using it directly inflated the measured gap between two
    # separate references by the length of the first one's prefix, letting a
    # genuinely adjacent (~20-char) gadget pair slip past the 50-char window.
    code = "(some_plugin_registry_base_object_for_lookup.__subclasses__(), y.__globals__)"
    res = CodeExecutionGuard().analyze(code, "python")
    assert res.allowed is False, res.violations


def test_ast_violation_is_reported():
    res = CodeExecutionGuard().analyze(
        "().__class__.__bases__[0].__subclasses__()", "python"
    )
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
