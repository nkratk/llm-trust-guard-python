"""
Full-guard TS<->Python parity gate.

Loads guard-parity-vectors.json (the same file locked by the npm repo's
guard-parity.test.ts) and runs each payload through the Python implementation,
asserting an identical block verdict. A mismatch means the two hand-maintained
ports have diverged.

Regenerate locked verdicts only with a RESULTS-v*.md justification.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

_VECTORS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "llm-trust-guard", "tests", "guard-parity-vectors.json"
)

with open(_VECTORS_PATH) as fh:
    _DOC = json.load(fh)


def _blocked(result) -> bool:
    """Return True if the guard result represents a violation."""
    if result is None:
        return False
    if isinstance(result, bool):
        return result
    if isinstance(result, dict):
        if result.get("violations"):
            return True
        if result.get("allowed") is False:
            return True
        if result.get("valid") is False:
            return True
        if result.get("threats"):
            return True
    # dataclass / object
    violations = getattr(result, "violations", None)
    if violations:
        return True
    if getattr(result, "allowed", True) is False:
        return True
    return False


def _run_guard(guard_name: str, payload: str) -> bool:
    if guard_name == "InputSanitizer":
        from llm_trust_guard.guards.input_sanitizer import InputSanitizer
        r = InputSanitizer(threshold=0.3, detect_pap=True).sanitize(payload)
        return _blocked(r)

    if guard_name == "EncodingDetector":
        from llm_trust_guard.guards.encoding_detector import EncodingDetector
        return _blocked(EncodingDetector().detect(payload))

    if guard_name == "MemoryGuard":
        from llm_trust_guard.guards.memory_guard import MemoryGuard
        return _blocked(MemoryGuard().check_write(payload, "user", "s1"))

    if guard_name == "OutputFilter":
        from llm_trust_guard.guards.output_filter import OutputFilter
        r = OutputFilter().filter(payload)
        return bool(getattr(r, "violations", None))

    if guard_name == "ToolResultGuard":
        from llm_trust_guard.guards.tool_result_guard import ToolResultGuard
        return _blocked(ToolResultGuard().validate_result("test_tool", payload))

    if guard_name == "MCPSecurityGuard":
        from llm_trust_guard.guards.mcp_security_guard import MCPSecurityGuard
        mcp = MCPSecurityGuard()
        result = mcp._detect_injection(payload)  # type: ignore[attr-defined]
        return result.get("detected", False)

    if guard_name == "ConversationGuard":
        from llm_trust_guard.guards.conversation_guard import ConversationGuard
        return _blocked(ConversationGuard().check("s1", payload))

    if guard_name == "MultiModalGuard":
        from llm_trust_guard.guards.multimodal_guard import MultiModalGuard, MultiModalContent
        content = MultiModalContent(
            type="document",
            content="",
            mime_type="text/plain",
            extracted_text=payload,
        )
        return _blocked(MultiModalGuard().check(content))

    if guard_name == "TenantBoundary":
        from llm_trust_guard.guards.tenant_boundary import TenantBoundary, TenantBoundaryConfig, SessionContext
        cfg = TenantBoundaryConfig(valid_tenants={"tenant-A"})
        tb = TenantBoundary(cfg)
        result = tb.validate_session(
            SessionContext(authenticated=True, role="user", tenant_id=payload, user_id="u1")
        )
        return result.get("valid") is False

    if guard_name == "ExternalDataGuard":
        from llm_trust_guard.guards.external_data_guard import ExternalDataGuard
        return _blocked(ExternalDataGuard().validate(payload))

    if guard_name == "PolicyGate":
        from llm_trust_guard.guards.policy_gate import PolicyGate, ToolDefinition, SessionContext as PGSession
        pg = PolicyGate()
        is_restricted = payload == "delete_all_users"
        result = pg.check_tool_access(
            ToolDefinition(name=payload, roles=["admin"] if is_restricted else []),
            PGSession(authenticated=True, role="user", tenant_id="t1", user_id="u1"),
        )
        return result.get("allowed") is False

    if guard_name == "RAGGuard":
        from llm_trust_guard.guards.rag_guard import RAGGuard, RAGDocument
        result = RAGGuard().validate([RAGDocument(id="c1", content=payload, source="test")])
        return bool(getattr(result, "violations", None))

    if guard_name == "PromptLeakageGuard":
        from llm_trust_guard.guards.prompt_leakage_guard import PromptLeakageGuard
        return _blocked(PromptLeakageGuard().check(payload))

    raise ValueError(f"Unknown guard in parity vectors: {guard_name}")


@pytest.mark.parametrize(
    "vec",
    _DOC["vectors"],
    ids=lambda v: f"{v['guard']}::{v['payload'][:50]}",
)
def test_guard_parity_with_typescript(vec):
    actual = _run_guard(vec["guard"], vec["payload"])
    assert actual == vec["should_block"], (
        f"Parity drift for {vec['guard']}: expected blocked={vec['should_block']}, "
        f"got {actual} :: {vec['payload'][:80]}"
    )
