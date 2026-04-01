"""Tests for ToolRegistry guard - ported from tool-registry.test.ts (13 tests)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.tool_registry import (
    ToolRegistry,
    ToolRegistryConfig,
    ToolDefinition,
)


@pytest.fixture
def tools():
    return [
        ToolDefinition(
            name="get_order",
            description="Get order details",
            parameters={"type": "object", "properties": {}, "required": []},
            roles=["customer", "admin"],
        ),
        ToolDefinition(
            name="manage_users",
            description="Manage user accounts",
            parameters={"type": "object", "properties": {}, "required": []},
            roles=["admin"],
        ),
        ToolDefinition(
            name="get_weather",
            description="Get weather info",
            parameters={"type": "object", "properties": {}, "required": []},
            roles=[],
        ),
    ]


@pytest.fixture
def registry(tools):
    return ToolRegistry(ToolRegistryConfig(tools=tools))


# ---------------------------------------------------------------------------
# Unregistered Tool Blocking
# ---------------------------------------------------------------------------

class TestUnregisteredToolBlocking:
    def test_should_block_tool_not_registered_hallucination(self, registry):
        result = registry.check("nonexistent_tool", "customer")
        assert result.allowed is False
        assert "UNREGISTERED_TOOL" in result.violations
        assert "not registered" in result.reason

    def test_should_block_completely_made_up_tool_name(self, registry):
        result = registry.check("fetch_secret_database_dump", "admin")
        assert result.allowed is False
        assert "UNREGISTERED_TOOL" in result.violations


# ---------------------------------------------------------------------------
# Role-Based Access
# ---------------------------------------------------------------------------

class TestRoleBasedAccess:
    def test_should_allow_customer_to_access_customer_tool(self, registry):
        result = registry.check("get_order", "customer")
        assert result.allowed is True
        assert result.tool is not None
        assert result.tool.name == "get_order"

    def test_should_block_customer_from_accessing_admin_only_tool(self, registry):
        result = registry.check("manage_users", "customer")
        assert result.allowed is False
        assert "UNAUTHORIZED_ROLE" in result.violations

    def test_should_allow_any_role_to_access_tool_with_no_role_restrictions(self, registry):
        result = registry.check("get_weather", "guest")
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Hallucination Pattern Detection
# ---------------------------------------------------------------------------

class TestHallucinationPatternDetection:
    def test_should_detect_hallucination_for_execute_prefixed_tools(self, registry):
        result = registry.check("execute_system_command", "admin")
        assert result.hallucination_detected is True

    def test_should_detect_hallucination_for_sudo_prefixed_tools(self, registry):
        result = registry.check("sudo_reset_all", "admin")
        assert result.hallucination_detected is True

    def test_should_detect_hallucination_for_bypass_prefixed_tools(self, registry):
        result = registry.check("bypass_security_check", "admin")
        assert result.hallucination_detected is True

    def test_should_detect_hallucination_for_tools_with_path_traversal_chars(self, registry):
        result = registry.check("tool/../../../etc/passwd", "admin")
        assert result.hallucination_detected is True

    def test_should_not_flag_hallucination_for_registered_tool(self, registry):
        result = registry.check("get_order", "admin")
        assert result.hallucination_detected is False


# ---------------------------------------------------------------------------
# Similar Tool Suggestion
# ---------------------------------------------------------------------------

class TestSimilarToolSuggestion:
    def test_should_suggest_similar_tools_when_close_match_exists(self, registry):
        result = registry.check("get_orders", "customer")
        assert result.allowed is False
        assert result.similar_tools is not None
        assert "get_order" in result.similar_tools

    def test_should_suggest_manage_users_for_manage_user_typo(self, registry):
        result = registry.check("manage_user", "admin")
        assert result.allowed is False
        assert result.similar_tools is not None
        assert "manage_users" in result.similar_tools


# ---------------------------------------------------------------------------
# False Positive - Legitimate Registered Tool
# ---------------------------------------------------------------------------

class TestFalsePositiveLegitimateRegisteredTool:
    def test_should_allow_admin_to_use_all_registered_tools_without_false_flags(self, registry):
        order_result = registry.check("get_order", "admin")
        assert order_result.allowed is True
        assert order_result.hallucination_detected is False

        manage_result = registry.check("manage_users", "admin")
        assert manage_result.allowed is True
        assert manage_result.hallucination_detected is False
