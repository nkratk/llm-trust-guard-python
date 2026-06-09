"""
TS<->Python parity gate.

`tests/parity-vectors.json` (identical to the file shipped in the npm package)
holds the canonical `allowed` verdict for each input, generated from the TS
InputSanitizer. This Python InputSanitizer must reproduce every verdict exactly;
a mismatch means the two hand-maintained ports have diverged.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.input_sanitizer import InputSanitizer

_DOC = json.load(
    open(os.path.join(os.path.dirname(__file__), "parity-vectors.json"))
)
_CFG = _DOC.get("config", {"threshold": 0.3, "detectPAP": True})


@pytest.mark.parametrize("vec", _DOC["vectors"], ids=lambda v: v["input"][:40])
def test_parity_with_typescript(vec):
    s = InputSanitizer(
        threshold=_CFG.get("threshold", 0.3),
        detect_pap=_CFG.get("detectPAP", True),
    )
    got = s.sanitize(vec["input"]).allowed
    assert got == vec["allowed"], (
        f"Parity drift vs TS: expected allowed={vec['allowed']}, got {got} "
        f":: {vec['input'][:70]}"
    )
