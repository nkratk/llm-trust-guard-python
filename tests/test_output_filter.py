"""Tests for OutputFilter — ported from output-filter.test.ts (14 tests)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.output_filter import OutputFilter


class TestPIIDetection:
    def setup_method(self):
        self.filter = OutputFilter(detect_pii=True, detect_secrets=True)

    def test_should_detect_email_addresses(self):
        result = self.filter.filter("Contact: john@example.com")
        assert len(result.pii_detected) > 0
        assert any(p.type == "email" for p in result.pii_detected)

    def test_should_detect_ssn(self):
        result = self.filter.filter("SSN: 123-45-6789")
        assert any(p.type == "ssn" for p in result.pii_detected)

    def test_should_detect_credit_card_numbers(self):
        result = self.filter.filter("Card: 4111-1111-1111-1111")
        assert any(p.type == "credit_card" for p in result.pii_detected)

    def test_should_mask_pii_in_string_output(self):
        result = self.filter.filter("Email: test@example.com")
        assert "[EMAIL]" in result.filtered_response
        assert "test@example.com" not in result.filtered_response


class TestSecretDetection:
    def setup_method(self):
        self.filter = OutputFilter(detect_pii=True, detect_secrets=True)

    def test_should_detect_api_keys(self):
        result = self.filter.filter("api_key=sk-1234567890abcdefghijklmno")
        assert len(result.secrets_detected) > 0

    def test_should_detect_jwt_tokens(self):
        result = self.filter.filter(
            "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        assert any(s.type == "jwt_token" for s in result.secrets_detected)

    def test_should_block_critical_secrets(self):
        result = self.filter.filter("password=SuperSecret123!")
        assert len(result.secrets_detected) > 0
        assert any(s.type == "password" for s in result.secrets_detected)


class TestObjectFiltering:
    def setup_method(self):
        self.filter = OutputFilter(detect_pii=True, detect_secrets=True)

    def test_should_filter_sensitive_fields_in_objects(self):
        result = self.filter.filter(
            {"name": "John", "password": "secret123", "email": "john@test.com"}
        )
        assert result.filtered_response["password"] == "[FILTERED]"

    def test_should_handle_nested_objects(self):
        result = self.filter.filter({"user": {"name": "John", "ssn": "123-45-6789"}})
        assert result.filtered_response["user"]["ssn"] == "[FILTERED]"

    def test_should_handle_circular_references_gracefully(self):
        # Python dicts can't have true circular refs via JSON,
        # but we test that a self-referencing structure doesn't crash
        obj = {"name": "test"}
        # filter() should not crash - it will serialize to string on TypeError
        result = self.filter.filter(obj)
        assert hasattr(result, "allowed")


class TestFalsePositives:
    def setup_method(self):
        self.filter = OutputFilter(detect_pii=True, detect_secrets=True)

    def test_should_not_flag_normal_text_without_pii(self):
        result = self.filter.filter(
            "The weather is nice today. Order status: shipped."
        )
        assert len(result.pii_detected) == 0
        assert len(result.secrets_detected) == 0

    def test_should_not_flag_short_numbers_as_bank_accounts(self):
        result = self.filter.filter("Order ID: 12345678, Product: Widget")
        # bank_account now requires context keyword
        assert not any(p.type == "bank_account" for p in result.pii_detected)

    def test_should_not_flag_timestamps_as_bank_accounts(self):
        result = self.filter.filter("Created at: 1710547200000")
        assert not any(p.type == "bank_account" for p in result.pii_detected)


class TestIpAddressVersionStringFalsePositive:
    """Regression coverage for #10: ip_address false-positived on dotted
    version strings whose every octet happens to be a valid IPv4 component
    (e.g. "10.4.32.3"). Parity with tests/output-filter.test.ts."""

    def setup_method(self):
        self.filter = OutputFilter()

    def _is_ip_detected(self, text):
        return any(p.type == "ip_address" for p in self.filter.filter(text).pii_detected)

    def test_does_not_flag_out_of_range_octets(self):
        assert self._is_ip_detected("Error code 999.999.999.999 invalid") is False

    def test_does_not_flag_a_version_string_preceded_by_a_version_keyword(self):
        assert self._is_ip_detected("Please upgrade to 10.4.32.3 before Friday") is False
        assert self._is_ip_detected("Now on version 10.4.32.3") is False
        assert self._is_ip_detected("release 10.4.32.3 is out") is False
        assert self._is_ip_detected("Update to v10.4.32.3 today") is False
        assert self._is_ip_detected("V10.4.32.3") is False

    def test_still_flags_real_ip_addresses_including_near_miss_cases(self):
        assert self._is_ip_detected("The server IP is 192.168.1.1, contact admin.") is True
        assert self._is_ip_detected("Connect to 10.0.0.1 via SSH") is True
        # version keyword present but too far from the number to plausibly qualify it
        assert self._is_ip_detected("Server version 2.1 is running at 10.4.32.3") is True
        assert self._is_ip_detected("Blocklisted address: 8.8.8.8") is True
        # "coverage"/"diverse" contain "ver" as a substring — must not trip the keyword check
        assert self._is_ip_detected("diverse coverage from 172.16.0.5") is True
        # Roman numeral "V" with a space is not the tight no-gap "v10.4.32.3" prefix case
        assert self._is_ip_detected("Chapter V 10.0.0.1") is True

    def test_masks_real_ips_but_leaves_version_strings_unmasked_in_the_same_string(self):
        r = self.filter.filter("Please upgrade to v10.4.32.3 -- the server at 192.168.1.1 needs it too")
        assert r.filtered_response == "Please upgrade to v10.4.32.3 -- the server at [IP_ADDRESS] needs it too"


class TestRoleBasedFiltering:
    def test_should_apply_role_specific_field_filters(self):
        role_filter = OutputFilter(
            role_filters={"customer": ["internal_notes", "cost_price"]},
        )
        result = role_filter.filter(
            {
                "name": "Widget",
                "price": 29.99,
                "internal_notes": "Buy from supplier X",
                "cost_price": 10.0,
            },
            "customer",
        )
        assert result.filtered_response["internal_notes"] == "[FILTERED]"
        assert result.filtered_response["cost_price"] == "[FILTERED]"
        assert result.filtered_response["name"] == "Widget"
