"""
Permanent ReDoS (catastrophic-backtracking) safety net.

Born from the v0.21.4 fix batch: an empirical stress-test sweep (written as
a one-off script, run manually against this repo's own guards rather than
assumed identical to the npm sibling) found and fixed catastrophic-
backtracking regexes here. That sweep is now this permanent test, so a NEW
regex added later gets the same scrutiny automatically instead of relying
on someone remembering to re-run a throwaway script. Writing this permanent
version is itself what found two more real bugs (heuristic_analyzer.py,
encoding_detector.py) the earlier manual rounds had missed.

Every `re.<func>(pattern, ...)` regex literal in src/ is extracted (not a
hand-maintained list — new files/patterns are picked up automatically),
covering compile/search/match/fullmatch/sub/subn/split/findall/finditer.
An earlier version only matched `re.compile(...)` calls; an audit (prompted
by finding the analogous gap in the npm sibling's extractor, which missed
~28% of its regex literals) found 81 inline `re.search`/`re.sub`/etc. calls
in this repo that never go through `re.compile()` and were entirely
invisible to that narrower extractor. Broadening it found no new bugs among
those 81 — worth confirming rather than assuming, given the npm sibling's
analogous gap did hide a real one.

Detection strategy: SCALING RATIO, not a single absolute-time threshold.
Several already-fixed, genuinely-safe patterns (bounded quantifiers, linear
in input size) still take 500ms-2s+ on CPython's slower regex engine at the
seed sizes needed to reliably expose a real quadratic bug — at any single
seed size, a safe-but-slow-constant pattern and a real quadratic bug can
land in overlapping absolute-time ranges. Growth ratio between two sizes
doesn't have that problem: linear time roughly doubles when input doubles
(ratio ~2x for a 2x size step, ~4x for this test's 4x size step);
quadratic time roughly quadruples when input doubles (ratio ~16x for a 4x
size step). A generous ratio threshold well below 16x but above the
linear~4x range cleanly separates the two regardless of the absolute
constant factor. A `signal.alarm` hard timeout remains the backstop for
anything so catastrophic it never returns at all.
"""

import ast
import os
import re
import signal
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

SRC_DIR = os.path.join(os.path.dirname(__file__), "..", "src")
ALARM_TIMEOUT_S = 5
SMALL_REPS = 2000
LARGE_REPS = SMALL_REPS * 4  # 4x size step
RATIO_THRESHOLD = 6.0  # linear ~4x, quadratic ~16x at a 4x size step — 6x cleanly separates them
MIN_SMALL_MS = 5  # ignore near-zero timings where a ratio is just noise
ABS_CEILING_MS = 4000  # even a "linear" pattern shouldn't take this long at LARGE_REPS


class _TimeoutErr(Exception):
    pass


def _alarm_handler(signum, frame):
    raise _TimeoutErr()


def _walk_py_files(root):
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.endswith(".py"):
                yield os.path.join(dirpath, name)


# re module functions whose first positional argument is a pattern string.
# An earlier version of this extractor only matched re.compile(...) — an
# audit (prompted by finding the analogous gap in the npm sibling's
# text-scanning extractor) found 81 inline re.search/match/sub/split/etc.
# calls in src/ that never go through re.compile() at all, entirely
# invisible to that narrower extractor.
_RE_FUNCS_WITH_PATTERN_ARG = {
    "compile", "search", "match", "fullmatch", "sub", "subn", "split", "findall", "finditer",
}


def _extract_patterns():
    """Statically extract every re.<func>(pattern, ...) call's pattern
    string (compile/search/match/fullmatch/sub/subn/split/findall/finditer),
    using the AST so multi-line / concatenated string literals resolve
    correctly (a plain regex extractor mis-parsed some of these)."""
    patterns = []
    for filepath in _walk_py_files(SRC_DIR):
        relpath = os.path.relpath(filepath, os.path.join(os.path.dirname(__file__), ".."))
        with open(filepath) as f:
            source = f.read()
        try:
            tree = ast.parse(source, filename=filepath)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in _RE_FUNCS_WITH_PATTERN_ARG
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "re"
                and node.args
            ):
                try:
                    pattern_str = ast.literal_eval(node.args[0])
                except Exception:
                    continue
                if not isinstance(pattern_str, str):
                    continue
                try:
                    compiled = re.compile(pattern_str, re.IGNORECASE)
                except re.error:
                    continue
                patterns.append((relpath, pattern_str, compiled))
    return patterns


# The structural seed *templates* that actually found real bugs this
# session — each gets built at both SMALL_REPS and LARGE_REPS for the
# scaling-ratio check. Single-character repeats are cheap enough everywhere
# they don't need the ratio treatment; kept at a fixed, generous size with
# just the absolute ceiling + alarm as a backstop.
_SEED_TEMPLATES = ["a.", "a%20", "><", "![", "<!--", "AAAA-", "a_1", "x-y-z-", "\n", "User: "]
_SINGLE_CHARS = ["a", ".", "%", "0", "A", "x", " ", "-", "[", "!", "#", "=", ":", "{", "_", "@", "$", "/", "\t"]
SINGLE_CHAR_REPS = 20_000


def _time_search(compiled, seed):
    signal.alarm(ALARM_TIMEOUT_S)
    start = time.time()
    try:
        compiled.search(seed)
        return time.time() - start
    except _TimeoutErr:
        return None
    except Exception:
        return time.time() - start
    finally:
        signal.alarm(0)


def test_extractor_finds_a_nontrivial_number_of_patterns():
    # If this ever drops to ~0, the AST extraction above has stopped
    # matching this codebase's actual re.compile() call shape — fail loudly
    # rather than silently testing nothing.
    patterns = _extract_patterns()
    assert len(patterns) > 100


def test_no_pattern_shows_quadratic_or_worse_scaling_on_adversarial_input():
    patterns = _extract_patterns()
    violations = []

    have_alarm = hasattr(signal, "SIGALRM")
    old_handler = signal.signal(signal.SIGALRM, _alarm_handler) if have_alarm else None

    try:
        for relpath, pattern_str, compiled in patterns:
            # Single-character-repeat seeds: absolute ceiling + alarm only.
            for ch in _SINGLE_CHARS:
                seed = ch * SINGLE_CHAR_REPS
                elapsed = _time_search(compiled, seed) if have_alarm else _time_search_no_alarm(compiled, seed)
                if elapsed is None:
                    violations.append(f"{relpath} :: {pattern_str[:80]} :: TIMEOUT(>{ALARM_TIMEOUT_S}s) char={ch!r} reps={SINGLE_CHAR_REPS}")
                elif elapsed * 1000 > ABS_CEILING_MS:
                    violations.append(f"{relpath} :: {pattern_str[:80]} :: {elapsed*1000:.0f}ms char={ch!r} reps={SINGLE_CHAR_REPS}")

            # Structural seeds: scaling-ratio check.
            for tmpl in _SEED_TEMPLATES:
                small_seed = tmpl * SMALL_REPS
                large_seed = tmpl * LARGE_REPS

                small_ms = _time_search(compiled, small_seed)
                if small_ms is None:
                    violations.append(f"{relpath} :: {pattern_str[:80]} :: TIMEOUT(>{ALARM_TIMEOUT_S}s) tmpl={tmpl!r} reps={SMALL_REPS}")
                    continue
                small_ms *= 1000

                large_ms = _time_search(compiled, large_seed)
                if large_ms is None:
                    violations.append(f"{relpath} :: {pattern_str[:80]} :: TIMEOUT(>{ALARM_TIMEOUT_S}s) tmpl={tmpl!r} reps={LARGE_REPS}")
                    continue
                large_ms *= 1000

                if large_ms > ABS_CEILING_MS:
                    violations.append(f"{relpath} :: {pattern_str[:80]} :: {large_ms:.0f}ms (over {ABS_CEILING_MS}ms ceiling) tmpl={tmpl!r} reps={LARGE_REPS}")
                elif small_ms >= MIN_SMALL_MS:
                    ratio = large_ms / small_ms
                    if ratio > RATIO_THRESHOLD:
                        violations.append(
                            f"{relpath} :: {pattern_str[:80]} :: {small_ms:.1f}ms@{SMALL_REPS} -> {large_ms:.1f}ms@{LARGE_REPS} "
                            f"(ratio {ratio:.1f}x for a 4x size step — quadratic-shaped) tmpl={tmpl!r}"
                        )
    finally:
        if have_alarm and old_handler is not None:
            signal.signal(signal.SIGALRM, old_handler)

    assert violations == [], "Slow / quadratic-shaped (possibly catastrophic-backtracking) patterns found:\n" + "\n".join(violations)


def _time_search_no_alarm(compiled, seed):
    start = time.time()
    try:
        compiled.search(seed)
    except Exception:
        pass
    return time.time() - start
