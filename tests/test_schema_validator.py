"""Tests for SchemaValidator guard - ported from schema-validator.test.ts (16 tests)."""

import math
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest
from llm_trust_guard.guards.schema_validator import (
    SchemaValidator,
    SchemaValidatorConfig,
    ToolDefinition,
)


@pytest.fixture
def tool():
    return ToolDefinition(
        name="search",
        description="Search products",
        parameters={
            "type": "object",
            "properties": {
                "query": {"type": "string", "maxLength": 200},
                "limit": {"type": "number", "min": 1, "max": 100},
            },
            "required": ["query"],
        },
    )


@pytest.fixture
def validator():
    return SchemaValidator(SchemaValidatorConfig(strict_types=True, detect_injection=True))


# ---------------------------------------------------------------------------
# Basic Validation
# ---------------------------------------------------------------------------

class TestBasicValidation:
    def test_should_allow_valid_parameters(self, validator, tool):
        result = validator.validate(tool, {"query": "blue shoes", "limit": 10})
        assert result.allowed is True

    def test_should_reject_missing_required_fields(self, validator, tool):
        result = validator.validate(tool, {"limit": 10})
        assert result.allowed is False
        assert "Missing required field: query" in result.errors

    def test_should_reject_type_mismatches(self, validator, tool):
        result = validator.validate(tool, {"query": "test", "limit": "all"})
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Injection Detection
# ---------------------------------------------------------------------------

class TestInjectionDetection:
    def test_should_detect_sql_injection_with_keywords(self, validator, tool):
        result = validator.validate(tool, {"query": "'; DROP TABLE products; --"})
        assert result.allowed is False
        assert any("SQL" in a for a in result.blocked_attacks)

    def test_should_detect_nosql_injection(self, validator, tool):
        result = validator.validate(tool, {"query": '{"$gt": ""}'})
        assert result.allowed is False

    def test_should_detect_path_traversal(self, validator, tool):
        result = validator.validate(tool, {"query": "../../../etc/passwd"})
        assert result.allowed is False

    def test_should_detect_xss(self, validator, tool):
        result = validator.validate(tool, {"query": '<script>alert("xss")</script>'})
        assert result.allowed is False

    def test_should_detect_command_injection_with_piped_commands(self, validator, tool):
        result = validator.validate(tool, {"query": "test; rm -rf /"})
        assert result.allowed is False


# ---------------------------------------------------------------------------
# Prototype Pollution
# ---------------------------------------------------------------------------

class TestPrototypePollution:
    def test_should_detect_proto_keys(self, validator, tool):
        params = {"query": "test", "__proto__": {"admin": True}}
        result = validator.validate(tool, params)
        assert result.allowed is False
        assert "PROTOTYPE_POLLUTION" in result.blocked_attacks

    def test_should_detect_constructor_keys(self, validator, tool):
        params = {"query": "test", "constructor": {}}
        result = validator.validate(tool, params)
        assert result.allowed is False


# ---------------------------------------------------------------------------
# False Positives
# ---------------------------------------------------------------------------

class TestFalsePositives:
    def test_should_allow_normal_text_with_apostrophes(self, tool):
        v = SchemaValidator(SchemaValidatorConfig(strict_types=True, detect_injection=True))
        result = v.validate(tool, {"query": "it's a beautiful day"})
        assert result.allowed is True

    def test_should_allow_normal_product_searches(self, validator, tool):
        result = validator.validate(tool, {"query": "men's blue running shoes size 10"})
        assert result.allowed is True

    def test_should_allow_urls_in_string_fields(self, validator):
        url_tool = ToolDefinition(
            name="fetch",
            description="Fetch URL",
            parameters={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        )
        result = validator.validate(url_tool, {"url": "https://example.com/api?q=test&limit=10"})
        assert result.allowed is True


# ---------------------------------------------------------------------------
# Number Validation
# ---------------------------------------------------------------------------

class TestNumberValidation:
    def test_should_reject_values_outside_range(self, validator, tool):
        result = validator.validate(tool, {"query": "test", "limit": 500})
        assert result.allowed is False

    def test_should_reject_nan(self, validator, tool):
        result = validator.validate(tool, {"query": "test", "limit": float("nan")})
        assert result.allowed is False

    def test_should_reject_infinity(self, validator, tool):
        result = validator.validate(tool, {"query": "test", "limit": float("inf")})
        assert result.allowed is False
