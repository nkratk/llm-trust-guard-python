"""
CodeExecutionGuard (L11)

Validates and sandboxes agent-generated code before execution.
Prevents RCE (Remote Code Execution) attacks via malicious code generation.

Threat Model:
- ASI05: Unexpected Code Execution (RCE)
- Code injection via LLM outputs
- Sandbox escape attempts

Protection Capabilities:
- Static code analysis for dangerous patterns
- Import/require blocklist enforcement
- System call detection
- Resource limit enforcement
- Language-specific security rules
"""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SandboxConfig:
    timeout: int
    memory_limit: int
    allowed_syscalls: List[str]
    network_policy: str  # "none" | "localhost" | "allowlist"
    filesystem_policy: str  # "none" | "readonly" | "temponly"
    env_vars: Dict[str, str]


@dataclass
class CodeAnalysisInfo:
    language: str
    length: int
    dangerous_imports: List[str]
    dangerous_functions: List[str]
    system_calls: List[str]
    network_access: bool
    file_access: bool
    shell_access: bool
    env_access: bool
    risk_score: int
    complexity_score: int


@dataclass
class CodeAnalysisResult:
    allowed: bool
    reason: str
    violations: List[str]
    request_id: str
    code_analysis: CodeAnalysisInfo
    recommendations: List[str]
    sanitized_code: Optional[str] = None
    sandbox_config: Optional[SandboxConfig] = None


@dataclass
class CodeExecutionGuardConfig:
    allowed_languages: List[str] = field(default_factory=lambda: ["javascript", "python", "sql"])
    blocked_imports: List[str] = field(default_factory=list)
    blocked_functions: Optional[List[str]] = None
    max_code_length: int = 10_000
    max_execution_time: int = 5_000
    allow_network: bool = False
    allow_file_system: bool = False
    allow_shell: bool = False
    allow_env_access: bool = False
    custom_patterns: List[Dict[str, Any]] = field(default_factory=list)
    risk_threshold: int = 50


@dataclass
class _DangerousPattern:
    name: str
    pattern: re.Pattern[str]
    severity: int


_DEFAULT_BLOCKED_FUNCTIONS = [
    "eval", "exec", "system", "popen", "spawn",
    "fork", "execv", "execve", "dlopen", "compile",
]

# fmt: off
_DANGEROUS_PATTERNS: Dict[str, List[_DangerousPattern]] = {
    "javascript": [
        _DangerousPattern("eval", re.compile(r"\beval\s*\("), 50),
        _DangerousPattern("function_constructor", re.compile(r"new\s+Function\s*\("), 50),
        _DangerousPattern("child_process", re.compile(r"require\s*\(\s*['\"]child_process['\"]\s*\)"), 60),
        _DangerousPattern("exec", re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\("), 60),
        _DangerousPattern("fs_write", re.compile(r"\b(writeFile|writeFileSync|appendFile|unlink|rmdir)\s*\("), 45),
        _DangerousPattern("process_env", re.compile(r"process\.env"), 30),
        _DangerousPattern("require_dynamic", re.compile(r"require\s*\(\s*[^'\"]"), 40),
        _DangerousPattern("vm_module", re.compile(r"require\s*\(\s*['\"]vm['\"]\s*\)"), 55),
        _DangerousPattern("fetch_external", re.compile(r"fetch\s*\(\s*['\"]https?://(?!localhost)"), 35),
        _DangerousPattern("websocket", re.compile(r"new\s+WebSocket\s*\("), 35),
        _DangerousPattern("prototype_pollution", re.compile(r"__proto__|constructor\s*\[|Object\.setPrototypeOf"), 50),
        _DangerousPattern("global_access", re.compile(r"\bglobal\b|\bglobalThis\b"), 35),
    ],
    "python": [
        _DangerousPattern("eval", re.compile(r"\beval\s*\("), 50),
        _DangerousPattern("exec", re.compile(r"\bexec\s*\("), 50),
        _DangerousPattern("compile", re.compile(r"\bcompile\s*\("), 45),
        _DangerousPattern("subprocess", re.compile(r"import\s+subprocess|from\s+subprocess"), 60),
        _DangerousPattern("os_system", re.compile(r"os\.(system|popen|exec)"), 60),
        _DangerousPattern("os_module", re.compile(r"import\s+os|from\s+os\s+import"), 40),
        _DangerousPattern("socket", re.compile(r"import\s+socket|from\s+socket"), 40),
        _DangerousPattern("pickle", re.compile(r"import\s+pickle|pickle\.loads?"), 55),
        _DangerousPattern("ctypes", re.compile(r"import\s+ctypes|from\s+ctypes"), 55),
        _DangerousPattern("builtins", re.compile(r"__builtins__|__import__"), 50),
        _DangerousPattern("file_write", re.compile(r"open\s*\([^)]*['\"]w['\"]"), 40),
        _DangerousPattern("requests", re.compile(r"requests\.(get|post|put|delete)\s*\("), 35),
        _DangerousPattern("getattr_dynamic", re.compile(r"getattr\s*\(\s*\w+\s*,\s*[^'\"]"), 40),
    ],
    "bash": [
        _DangerousPattern("rm_rf", re.compile(r"rm\s+(-rf?|--recursive)", re.I), 70),
        _DangerousPattern("sudo", re.compile(r"\bsudo\b", re.I), 60),
        _DangerousPattern("curl_pipe", re.compile(r"curl\s+.*\|\s*(ba)?sh", re.I), 70),
        _DangerousPattern("wget_execute", re.compile(r"wget\s+.*&&\s*(ba)?sh", re.I), 70),
        _DangerousPattern("eval", re.compile(r"\beval\b", re.I), 50),
        _DangerousPattern("env_dump", re.compile(r"\benv\b|\bprintenv\b", re.I), 35),
        _DangerousPattern("chmod", re.compile(r"chmod\s+(\+x|777|755)", re.I), 40),
        _DangerousPattern("chown", re.compile(r"\bchown\b", re.I), 45),
        _DangerousPattern("dd", re.compile(r"\bdd\s+if=", re.I), 55),
        _DangerousPattern("nc_reverse", re.compile(r"\bnc\b.*-e", re.I), 70),
        _DangerousPattern("base64_decode", re.compile(r"base64\s+(-d|--decode)", re.I), 40),
        _DangerousPattern("cron", re.compile(r"crontab|/etc/cron", re.I), 50),
    ],
    "sql": [
        _DangerousPattern("drop_table", re.compile(r"DROP\s+(TABLE|DATABASE)", re.I), 70),
        _DangerousPattern("delete_all", re.compile(r"DELETE\s+FROM\s+\w+\s*(;|$)", re.I), 60),
        _DangerousPattern("truncate", re.compile(r"TRUNCATE\s+TABLE", re.I), 65),
        _DangerousPattern("union_injection", re.compile(r"UNION\s+(ALL\s+)?SELECT", re.I), 55),
        _DangerousPattern("comment_injection", re.compile(r"--\s*$", re.M), 30),
        _DangerousPattern("xp_cmdshell", re.compile(r"xp_cmdshell", re.I), 70),
        _DangerousPattern("into_outfile", re.compile(r"INTO\s+(OUT|DUMP)FILE", re.I), 60),
        _DangerousPattern("load_file", re.compile(r"LOAD_FILE\s*\(", re.I), 55),
    ],
}
# fmt: on

_DEFAULT_BLOCKED_IMPORTS: Dict[str, List[str]] = {
    "javascript": [
        "child_process", "cluster", "dgram", "dns", "net",
        "tls", "vm", "worker_threads", "v8", "perf_hooks",
    ],
    "python": [
        "subprocess", "os", "sys", "socket", "ctypes",
        "pickle", "marshal", "multiprocessing", "threading", "_thread",
    ],
}

# AST-based detection (Python only). Catches sandbox-escape gadget chains and
# dynamic imports that regex provably cannot, e.g.
#   ().__class__.__bases__[0].__subclasses__()      # CPython jailbreak gadget
#   __import__("os").system("id")                   # dynamic import + exec
# These dunders are high-signal and rarely appear in benign code, so the pass is
# layered ON TOP of the regex pass (strictly additive — it can only add findings,
# never remove them; no false-positive regression, existing behavior preserved).
# Python's stdlib `ast` keeps this zero-dependency; the npm port can't use a
# stdlib parser, so it takes a pluggable parser-adapter route instead.
_AST_ESCAPE_DUNDERS = frozenset({
    "__subclasses__", "__bases__", "__mro__", "__base__",
    "__globals__", "__getattribute__", "__reduce_ex__", "__reduce__",
    "__code__", "__closure__",
})
# __builtins__/__import__ dropped from this set (mirrors the npm port's
# PYTHON_GADGET_TOKENS list) — __import__ used as a bare Call already has its
# own always-on check below (calling it dynamically is inherently suspicious
# regardless of context); a bare, uncalled reference to either isn't.

_GADGET_PROXIMITY_WINDOW = 50  # chars; mirrors code-execution-guard.ts


def _line_offset_lookup(code: str):
    """Return fn(lineno, col_offset) -> absolute char offset into `code`."""
    starts = [0]
    for line in code.splitlines(keepends=True):
        starts.append(starts[-1] + len(line))

    def to_offset(lineno: int, col_offset: int) -> int:
        return starts[lineno - 1] + col_offset

    return to_offset


def _ast_escape_findings(code: str):
    """Return [(name, severity), ...] for Python sandbox-escape gadgets, or None
    if the code does not parse (caller keeps the regex-only result).

    Gadget-chain dunders (__subclasses__, __globals__, .mro(), etc.) only fire
    when 2+ DISTINCT tokens co-occur within a small proximity window (50 chars)
    of each other — mirrors the npm port's identical, independently-adversarial-
    reviewed fix (code-execution-guard.ts's hasPythonGadgetChain). A single
    token alone (e.g. bare __reduce__ for pickling support, __subclasses__()
    for plugin discovery) is common in legitimate code and isn't itself a
    chain; real gadget chains are tightly-chained attribute accesses reaching
    from an arbitrary object to os/subprocess without importing them directly.
    Uses AST node positions (not npm's raw substring search) so a dunder
    appearing only inside a string literal or comment, or as a `def __reduce__`
    *definition* rather than a use, is never visited as an ast.Attribute/Name
    and so never counted — a precision advantage over pure text scanning.
    """
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError):
        return None
    out: List = []
    seen: set = set()
    positions: List[tuple] = []  # (token, absolute_offset)
    to_offset = _line_offset_lookup(code)

    def add(name: str, severity: int) -> None:
        if name not in seen:
            seen.add(name)
            out.append((name, severity))

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in _AST_ESCAPE_DUNDERS:
            # An Attribute node's lineno/col_offset is the START of the WHOLE
            # chain expression it's part of (e.g. for `a.b.__subclasses__`,
            # col_offset points at `a`, not at `__subclasses__`) — using it
            # inflates the measured distance between two separate references
            # by the length of the first one's prefix, letting genuinely
            # adjacent gadget pairs slip past the window undetected. Use
            # end_lineno/end_col_offset instead, which lands right after the
            # attribute name itself.
            positions.append((node.attr, to_offset(node.end_lineno, node.end_col_offset)))
        elif isinstance(node, ast.Name) and node.id in _AST_ESCAPE_DUNDERS:
            # A bare Name has no wrapping expression, so its own
            # lineno/col_offset already points at the token itself.
            positions.append((node.id, to_offset(node.lineno, node.col_offset)))
        elif (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "mro"
        ):
            # .mro() method-call form, distinct from the __mro__ attribute.
            # Same end-offset reasoning as the Attribute case above.
            positions.append(("__mro_call__", to_offset(node.func.end_lineno, node.func.end_col_offset)))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "__import__"
        ):
            add("ast_dynamic_import", 55)

    positions.sort(key=lambda p: p[1])
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            if positions[j][1] - positions[i][1] > _GADGET_PROXIMITY_WINDOW:
                break  # positions sorted by offset; nothing further can be in-window
            if positions[j][0] != positions[i][0]:
                add("ast_sandbox_escape_gadget_chain", 60)
                break
    return out


class CodeExecutionGuard:
    """Validates and sandboxes agent-generated code before execution."""

    def __init__(self, config: Optional[CodeExecutionGuardConfig] = None) -> None:
        cfg = config or CodeExecutionGuardConfig()
        self._config = cfg
        if cfg.blocked_functions is None:
            self._config.blocked_functions = list(_DEFAULT_BLOCKED_FUNCTIONS)
        # Mutable copy of dangerous patterns so users can add more
        self._dangerous_patterns: Dict[str, List[_DangerousPattern]] = {
            k: list(v) for k, v in _DANGEROUS_PATTERNS.items()
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(
        self,
        code: str,
        language: str,
        request_id: Optional[str] = None,
    ) -> CodeAnalysisResult:
        """Analyze code for dangerous patterns before execution."""
        req_id = request_id or f"code-{int(time.time() * 1000)}"
        normalized_lang = language.lower()
        violations: List[str] = []
        risk_score = 0

        # Check language allowlist
        if normalized_lang not in self._config.allowed_languages:
            return CodeAnalysisResult(
                allowed=False,
                reason=f"Language '{language}' is not allowed",
                violations=["disallowed_language"],
                request_id=req_id,
                code_analysis=CodeAnalysisInfo(
                    language=normalized_lang, length=len(code),
                    dangerous_imports=[], dangerous_functions=[],
                    system_calls=[], network_access=False,
                    file_access=False, shell_access=False,
                    env_access=False, risk_score=100, complexity_score=0,
                ),
                recommendations=[f"Use one of: {', '.join(self._config.allowed_languages)}"],
            )

        # Code length
        if len(code) > self._config.max_code_length:
            violations.append("code_too_long")
            risk_score += 20

        # Gather patterns
        patterns = list(self._dangerous_patterns.get(normalized_lang, []))
        for cp in self._config.custom_patterns:
            patterns.append(_DangerousPattern(
                name=cp["name"],
                pattern=re.compile(cp["pattern"]) if isinstance(cp["pattern"], str) else cp["pattern"],
                severity=cp.get("severity", 30),
            ))

        dangerous_imports: List[str] = []
        dangerous_functions: List[str] = []
        system_calls: List[str] = []
        network_access = False
        file_access = False
        shell_access = False
        env_access = False

        for dp in patterns:
            if dp.pattern.search(code):
                violations.append(f"dangerous_pattern_{dp.name}")
                risk_score += dp.severity

                if any(k in dp.name for k in ("exec", "spawn", "system", "subprocess")):
                    shell_access = True
                    system_calls.append(dp.name)
                if any(k in dp.name for k in ("fs", "file", "write")):
                    file_access = True
                if any(k in dp.name for k in ("fetch", "socket", "request", "websocket")):
                    network_access = True
                if "env" in dp.name:
                    env_access = True
                if any(k in dp.name for k in ("import", "require")):
                    dangerous_imports.append(dp.name)
                if any(k in dp.name for k in ("eval", "exec", "compile")):
                    dangerous_functions.append(dp.name)

        # AST pass (Python only): sandbox-escape gadgets regex cannot see. Strictly
        # additive — only adds findings the regex missed.
        if normalized_lang == "python":
            ast_findings = _ast_escape_findings(code)
            if ast_findings:
                for name, sev in ast_findings:
                    violation = f"dangerous_pattern_{name}"
                    if violation not in violations:
                        violations.append(violation)
                        risk_score += sev
                        dangerous_functions.append(name)

        # Check blocked imports
        all_blocked = list(self._config.blocked_imports) + list(_DEFAULT_BLOCKED_IMPORTS.get(normalized_lang, []))
        for blocked in all_blocked:
            import_patterns = [
                re.compile(rf"require\s*\(\s*['\"]{ re.escape(blocked) }['\"]\s*\)"),
                re.compile(rf"import\s+.*from\s+['\"]{ re.escape(blocked) }['\"]"),
                re.compile(rf"import\s+{ re.escape(blocked) }"),
                re.compile(rf"from\s+{ re.escape(blocked) }\s+import"),
            ]
            for ip in import_patterns:
                if ip.search(code):
                    violations.append(f"blocked_import_{blocked}")
                    dangerous_imports.append(blocked)
                    risk_score += 40

        # Check blocked functions
        for func in (self._config.blocked_functions or []):
            fp = re.compile(rf"\b{ re.escape(func) }\s*\(")
            if fp.search(code):
                violations.append(f"blocked_function_{func}")
                dangerous_functions.append(func)
                risk_score += 35

        # Policy checks
        if network_access and not self._config.allow_network:
            violations.append("network_access_denied")
            risk_score += 30
        if file_access and not self._config.allow_file_system:
            violations.append("filesystem_access_denied")
            risk_score += 30
        if shell_access and not self._config.allow_shell:
            violations.append("shell_access_denied")
            risk_score += 40
        if env_access and not self._config.allow_env_access:
            violations.append("env_access_denied")
            risk_score += 25

        complexity_score = self._calculate_complexity(code, normalized_lang)
        risk_score = min(100, risk_score)
        blocked = risk_score >= self._config.risk_threshold

        result = CodeAnalysisResult(
            allowed=not blocked,
            reason=f"Code blocked: {', '.join(violations[:3])}" if blocked else "Code analysis passed",
            violations=violations,
            request_id=req_id,
            code_analysis=CodeAnalysisInfo(
                language=normalized_lang,
                length=len(code),
                dangerous_imports=list(set(dangerous_imports)),
                dangerous_functions=list(set(dangerous_functions)),
                system_calls=list(set(system_calls)),
                network_access=network_access,
                file_access=file_access,
                shell_access=shell_access,
                env_access=env_access,
                risk_score=risk_score,
                complexity_score=complexity_score,
            ),
            recommendations=self._generate_recommendations(violations, risk_score),
        )

        if not blocked:
            result.sandbox_config = self.generate_sandbox_config(
                network_access, file_access, shell_access, env_access
            )
            if violations:
                result.sanitized_code = self.sanitize_code(code, normalized_lang)

        return result

    def validate_syntax(self, code: str, language: str) -> Dict[str, Any]:
        """Validate code structure (simplified syntax check)."""
        errors: List[str] = []
        lang = language.lower()

        if lang == "javascript":
            if code.count("{") != code.count("}"):
                errors.append("Unbalanced curly braces")
            if code.count("(") != code.count(")"):
                errors.append("Unbalanced parentheses")
        elif lang == "python":
            single = code.count("'")
            double = code.count('"')
            triple = len(re.findall(r"'''|\"\"\"", code))
            if (single - triple * 3) % 2 != 0:
                errors.append("Unclosed single quotes")
            if (double - triple * 3) % 2 != 0:
                errors.append("Unclosed double quotes")
        elif lang == "sql":
            if code.count("'") % 2 != 0:
                errors.append("Unclosed single quotes in SQL")

        return {"valid": len(errors) == 0, "errors": errors}

    def generate_sandbox_config(
        self,
        needs_network: bool,
        needs_file_system: bool,
        needs_shell: bool,
        needs_env: bool,
    ) -> SandboxConfig:
        """Generate secure sandbox configuration."""
        return SandboxConfig(
            timeout=self._config.max_execution_time,
            memory_limit=128 * 1024 * 1024,  # 128MB
            allowed_syscalls=self._get_allowed_syscalls(needs_network, needs_file_system, needs_shell),
            network_policy="localhost" if (needs_network and self._config.allow_network) else "none",
            filesystem_policy="temponly" if (needs_file_system and self._config.allow_file_system) else "none",
            env_vars={"NODE_ENV": "sandbox", "SANDBOX": "true"} if (needs_env and self._config.allow_env_access) else {},
        )

    def sanitize_code(self, code: str, language: str) -> str:
        """Sanitize code by removing dangerous patterns."""
        sanitized = code
        patterns = self._dangerous_patterns.get(language, [])

        for dp in patterns:
            if dp.severity >= 50:
                sanitized = dp.pattern.sub("/* BLOCKED */", sanitized)

        all_blocked = list(self._config.blocked_imports) + list(_DEFAULT_BLOCKED_IMPORTS.get(language, []))
        for blocked in all_blocked:
            import_pats = [
                re.compile(rf"require\s*\(\s*['\"]{ re.escape(blocked) }['\"]\s*\)"),
                re.compile(rf"import\s+.*from\s+['\"]{ re.escape(blocked) }['\"].*", re.M),
                re.compile(rf"import\s+{ re.escape(blocked) }.*", re.M),
                re.compile(rf"from\s+{ re.escape(blocked) }\s+import.*", re.M),
            ]
            for ip in import_pats:
                sanitized = ip.sub("/* BLOCKED_IMPORT */", sanitized)

        return sanitized

    def get_allowed_languages(self) -> List[str]:
        """Get allowed languages."""
        return list(self._config.allowed_languages)

    def add_dangerous_pattern(
        self, language: str, name: str, pattern: re.Pattern[str], severity: int
    ) -> None:
        """Add custom dangerous pattern."""
        if language not in self._dangerous_patterns:
            self._dangerous_patterns[language] = []
        self._dangerous_patterns[language].append(_DangerousPattern(name, pattern, severity))

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _calculate_complexity(self, code: str, language: str) -> int:
        complexity = 0

        control_patterns: Dict[str, re.Pattern[str]] = {
            "javascript": re.compile(r"\b(if|else|for|while|switch|try|catch)\b"),
            "python": re.compile(r"\b(if|elif|else|for|while|try|except|with)\b"),
            "sql": re.compile(r"\b(CASE|WHEN|IF|WHILE|LOOP)\b", re.I),
        }
        cp = control_patterns.get(language)
        if cp:
            complexity += len(cp.findall(code)) * 5

        func_patterns: Dict[str, re.Pattern[str]] = {
            "javascript": re.compile(r"\b(function|=>|\basync\b)"),
            "python": re.compile(r"\bdef\b|\blambda\b"),
            "sql": re.compile(r"\bCREATE\s+(FUNCTION|PROCEDURE)\b", re.I),
        }
        fp = func_patterns.get(language)
        if fp:
            complexity += len(fp.findall(code)) * 10

        lines = code.count("\n") + 1
        complexity += min(lines, 100)

        return min(100, complexity)

    def _get_allowed_syscalls(
        self, needs_network: bool, needs_file_system: bool, needs_shell: bool
    ) -> List[str]:
        base = ["read", "write", "exit", "brk", "mmap", "munmap", "close"]
        if needs_network and self._config.allow_network:
            base.extend(["socket", "connect", "bind", "listen", "accept"])
        if needs_file_system and self._config.allow_file_system:
            base.extend(["open", "stat", "fstat", "lstat", "access"])
        return base

    @staticmethod
    def _generate_recommendations(violations: List[str], risk_score: int) -> List[str]:
        recommendations: List[str] = []
        if any("import" in v for v in violations):
            recommendations.append("Remove or replace blocked imports with safe alternatives")
        if any("eval" in v or "exec" in v for v in violations):
            recommendations.append("Avoid dynamic code execution - use static alternatives")
        if any("network" in v for v in violations):
            recommendations.append("Remove network access or use approved endpoints only")
        if any("filesystem" in v for v in violations):
            recommendations.append("Use temporary directories or remove file operations")
        if any("shell" in v for v in violations):
            recommendations.append("Shell access is not permitted - use language-native alternatives")
        if risk_score >= 70:
            recommendations.append("Code requires significant review before execution")
        if not recommendations:
            recommendations.append("Code passed security analysis")
        return recommendations
