"""
Security Scanner agent — single module.

Two layers, run in order:
  1. Static rules   — regex + AST, no network/API key required.
  2. LLM review     — optional Claude pass that confirms/prunes static
                       findings and adds reasoning-based ones.

Accuracy choices made in this refactor (vs. the Day-1 first draft):
  - SQL injection is detected via AST at the call site (e.g. cursor.execute(...))
    instead of "any line that looks like SQL text", cutting false positives on
    strings that are built but never executed.
  - Hardcoded-secret matching excludes common placeholders (changeme, xxx,
    <your-key>, etc.) so dummy/example values stop triggering noise.
  - The Day-1 "missing input validation" heuristic was dropped. It flagged any
    route handler calling a sink regardless of whether validation actually
    happened elsewhere — no reliable signal, just noise. Better to under-report
    than cry wolf.
"""
import ast
import json
import re

from anthropic import Anthropic

from app.config.settings import get_settings
from app.logger.json_logger import get_logger
from app.models.schemas import (
    FileScanResult, Finding, FindingSource, ScanReport, ScanRequest, Severity,
)
from app.utils.ast_helpers import dotted_name, parse_or_none

logger = get_logger(__name__)

# --------------------------------------------------------------------------
# Static rules
# --------------------------------------------------------------------------

_PLACEHOLDER_RE = re.compile(
    r"(?i)^(changeme|xxx+|todo|your[-_]?|example|dummy|test|placeholder|"
    r"<.*>|\$\{.*\}|%\(.*\)s|none|null)"
)

_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*=\s*['\"]([^'\"]{6,})['\"]"
)
_AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")

_SINK_CALL_NAMES = {"execute", "executemany", "raw"}
_DESERIALIZE_UNSAFE = {"pickle.loads", "yaml.load"}
_WEAK_HASH = {"hashlib.md5", "hashlib.sha1"}
_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True")
_VERIFY_FALSE_RE = re.compile(r"verify\s*=\s*False")


def _is_sql_like(text: str) -> bool:
    return bool(re.search(r"(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)\b", text))


def _arg_is_dynamically_built(arg: ast.AST) -> bool:
    """True if a SQL-string-building node is an f-string, concatenation, or .format() call."""
    if isinstance(arg, ast.JoinedStr):  # f-string
        return True
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):  # "..." + var
        return True
    if isinstance(arg, ast.Call):
        called = dotted_name(arg.func)
        if called and called.endswith(".format"):
            return True
    return False


def scan_hardcoded_secrets(file_path: str, lines: list[str]) -> list[Finding]:
    """Flag likely hardcoded API keys, tokens, passwords, or private key material."""
    findings = []
    for i, line in enumerate(lines, start=1):
        match = _SECRET_ASSIGNMENT_RE.search(line)
        if match and not _PLACEHOLDER_RE.match(match.group(2)):
            findings.append(Finding(
                rule_id="SEC-HARDCODED-SECRET", category="hardcoded_secret",
                severity=Severity.CRITICAL, file_path=file_path, line_number=i,
                message="Possible hardcoded credential assigned directly in source.",
                snippet=line.strip()[:200],
            ))
        if _AWS_KEY_RE.search(line):
            findings.append(Finding(
                rule_id="SEC-AWS-KEY", category="hardcoded_secret",
                severity=Severity.CRITICAL, file_path=file_path, line_number=i,
                message="String matches AWS access key ID pattern.",
                snippet=line.strip()[:200],
            ))
        if _PRIVATE_KEY_RE.search(line):
            findings.append(Finding(
                rule_id="SEC-PRIVATE-KEY", category="hardcoded_secret",
                severity=Severity.CRITICAL, file_path=file_path, line_number=i,
                message="Embedded private key material detected.",
                snippet=line.strip()[:200],
            ))
    return findings


def scan_dangerous_calls_non_python(file_path: str, lines: list[str]) -> list[Finding]:
    """Line-level fallback for non-Python files (JS/TS/etc.) where we have no AST parser.

    Only used for non-.py files. For Python, scan_python_ast above does the
    equivalent checks at the actual call site, which avoids matching these
    same keywords when they appear inside a string literal, docstring, or
    comment (a real false positive this tool found by scanning its own code).
    """
    findings = []
    for i, line in enumerate(lines, start=1):
        if re.search(r"\beval\s*\(", line):
            findings.append(Finding(
                rule_id="SEC-EVAL", category="dangerous_eval", severity=Severity.CRITICAL,
                file_path=file_path, line_number=i,
                message="Use of eval() on data that may be externally influenced.",
                snippet=line.strip()[:200],
            ))
        if re.search(r"\bexec\s*\(", line):
            findings.append(Finding(
                rule_id="SEC-EXEC", category="dangerous_exec", severity=Severity.CRITICAL,
                file_path=file_path, line_number=i,
                message="Use of exec() on data that may be externally influenced.",
                snippet=line.strip()[:200],
            ))
        if _SHELL_TRUE_RE.search(line) and re.search(r"(subprocess\.\w+|os\.system)\s*\(", line):
            findings.append(Finding(
                rule_id="SEC-SHELL-INJECTION", category="shell_injection", severity=Severity.HIGH,
                file_path=file_path, line_number=i,
                message="Subprocess call with shell=True risks shell injection on dynamic input.",
                snippet=line.strip()[:200],
            ))
        if _VERIFY_FALSE_RE.search(line):
            findings.append(Finding(
                rule_id="SEC-TLS-VERIFY-DISABLED", category="insecure_transport",
                severity=Severity.HIGH, file_path=file_path, line_number=i,
                message="TLS certificate verification is disabled (verify=False).",
                snippet=line.strip()[:200],
            ))
    return findings


def scan_python_ast(file_path: str, source: str) -> list[Finding]:
    """AST-based checks: tie findings to the actual dangerous call site, not a nearby string."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        called = dotted_name(node.func)
        if not called:
            continue
        short_name = called.rsplit(".", maxsplit=1)[-1]

        # eval/exec: only a real call site counts, never a mention in a string/docstring
        if short_name == "eval" and called == "eval":
            findings.append(Finding(
                rule_id="SEC-EVAL", category="dangerous_eval", severity=Severity.CRITICAL,
                file_path=file_path, line_number=node.lineno,
                message="Use of eval() on data that may be externally influenced.",
            ))
        if short_name == "exec" and called == "exec":
            findings.append(Finding(
                rule_id="SEC-EXEC", category="dangerous_exec", severity=Severity.CRITICAL,
                file_path=file_path, line_number=node.lineno,
                message="Use of exec() on data that may be externally influenced.",
            ))

        # shell=True on an actual subprocess/os.system call site
        if short_name in {"Popen", "call", "run", "check_call", "check_output", "system"}:
            has_shell_true = any(
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                for kw in node.keywords
            )
            if has_shell_true:
                findings.append(Finding(
                    rule_id="SEC-SHELL-INJECTION", category="shell_injection", severity=Severity.HIGH,
                    file_path=file_path, line_number=node.lineno,
                    message="Subprocess call with shell=True risks shell injection on dynamic input.",
                ))

        # verify=False on an actual call's keyword argument, not text mentioning it
        has_verify_false = any(
            kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False
            for kw in node.keywords
        )
        if has_verify_false:
            findings.append(Finding(
                rule_id="SEC-TLS-VERIFY-DISABLED", category="insecure_transport",
                severity=Severity.HIGH, file_path=file_path, line_number=node.lineno,
                message="TLS certificate verification is disabled (verify=False).",
            ))

        # SQL injection: sink call whose first arg is dynamically built AND sql-like
        if short_name in _SINK_CALL_NAMES and node.args and hasattr(ast, "unparse"):
            first_arg = node.args[0]
            if _is_sql_like(ast.unparse(first_arg)) and _arg_is_dynamically_built(first_arg):
                findings.append(Finding(
                    rule_id="SEC-SQL-INJECTION", category="sql_injection",
                    severity=Severity.CRITICAL, file_path=file_path, line_number=node.lineno,
                    message=f"'{short_name}()' called with a dynamically-built SQL string "
                            "(f-string/concat/.format()) instead of a parameterized query.",
                ))

        # Insecure deserialization (yaml.load with an explicit SafeLoader is fine)
        if called in _DESERIALIZE_UNSAFE:
            if called == "yaml.load" and hasattr(ast, "unparse") and any(
                kw.arg == "Loader" and "Safe" in ast.unparse(kw.value) for kw in node.keywords
            ):
                continue
            findings.append(Finding(
                rule_id="SEC-INSECURE-DESERIALIZATION", category="insecure_deserialization",
                severity=Severity.HIGH, file_path=file_path, line_number=node.lineno,
                message=f"{called}() on untrusted input can lead to code execution.",
            ))

        # Weak crypto
        if called in _WEAK_HASH:
            findings.append(Finding(
                rule_id="SEC-WEAK-CRYPTO", category="weak_crypto", severity=Severity.MEDIUM,
                file_path=file_path, line_number=node.lineno,
                message=f"{called}() is not suitable for password hashing or integrity checks.",
            ))

    return findings


def run_all_static_rules(file_path: str, content: str) -> list[Finding]:
    """Run every static rule against a file and return the combined findings."""
    lines = content.splitlines()
    findings = scan_hardcoded_secrets(file_path, lines)
    if file_path.endswith(".py"):
        findings += scan_python_ast(file_path, content)
    else:
        findings += scan_dangerous_calls_non_python(file_path, lines)
    return findings


# --------------------------------------------------------------------------
# LLM review (optional second pass)
# --------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a precise security code reviewer. You are given a \
source file and findings already flagged by static analysis. Your job:
1. For each static finding, decide TRUE_POSITIVE or FALSE_POSITIVE given full \
context, with a one-line reason. Be conservative: only mark FALSE_POSITIVE if \
you are confident the flagged code is actually safe (e.g. the query is fully \
parameterized despite superficial string building).
2. List any ADDITIONAL security issues the static rules likely missed, each \
with a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO). Only include issues you \
have reasonable confidence in; do not pad the list.

Respond ONLY with JSON, no prose, no markdown fences:
{
  "reviewed_static_findings": [
    {"rule_id": "...", "verdict": "TRUE_POSITIVE|FALSE_POSITIVE", "reason": "..."}
  ],
  "additional_findings": [
    {"category": "...", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
     "line_number": null, "message": "..."}
  ]
}
"""


def review_with_llm(file_path: str, content: str, static_findings: list[Finding]) -> list[Finding]:
    """Confirm/prune static findings and add reasoning-based findings via Claude. Fails open."""
    settings = get_settings()
    if not settings.enable_llm_review or not settings.anthropic_api_key or not static_findings:
        return static_findings

    static_summary = [
        {"rule_id": f.rule_id, "category": f.category, "line_number": f.line_number,
         "message": f.message, "snippet": f.snippet}
        for f in static_findings
    ]
    user_content = (
        f"FILE: {file_path}\n\nSOURCE:\n{content[:8000]}\n\n"
        f"STATIC_FINDINGS:\n{json.dumps(static_summary, indent=2)}"
    )

    try:
        client = Anthropic(api_key=settings.anthropic_api_key)
        response = client.messages.create(
            model=settings.claude_model,
            max_tokens=settings.claude_max_tokens,
            system=_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_content}],
        )
        text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text")
        parsed = json.loads(text)
    except Exception as exc:  # noqa: BLE001 - best-effort second pass, never fail the scan
        logger.warning("LLM review failed for %s, keeping static findings only: %s", file_path, exc)
        return static_findings

    verdicts = {v["rule_id"]: v.get("verdict") for v in parsed.get("reviewed_static_findings", [])}
    confirmed = [f for f in static_findings if verdicts.get(f.rule_id) != "FALSE_POSITIVE"]

    for extra in parsed.get("additional_findings", []):
        try:
            severity = Severity(extra.get("severity", "MEDIUM"))
        except ValueError:
            severity = Severity.MEDIUM
        confirmed.append(Finding(
            rule_id="SEC-LLM-REVIEW", category=extra.get("category", "other"), severity=severity,
            file_path=file_path, line_number=extra.get("line_number"),
            message=extra.get("message", ""), source=FindingSource.LLM_REVIEW,
        ))
    return confirmed


# --------------------------------------------------------------------------
# Agent
# --------------------------------------------------------------------------

class SecurityScannerAgent:
    """Scans source files for OWASP-style security issues."""

    name = "security_scanner"

    def __init__(self, enable_llm_review: bool | None = None):
        settings = get_settings()
        self.enable_llm_review = (
            settings.enable_llm_review if enable_llm_review is None else enable_llm_review
        )
        self.max_file_size_bytes = settings.max_file_size_bytes

    def scan_file(self, file_path: str, content: str) -> FileScanResult:
        """Run static rules, then the optional LLM pass, for one file's content."""
        if len(content.encode("utf-8", errors="ignore")) > self.max_file_size_bytes:
            logger.warning("Skipping %s: exceeds max_file_size_bytes", file_path)
            return FileScanResult(file_path=file_path, findings=[], lines_scanned=0)

        findings = run_all_static_rules(file_path, content)
        if self.enable_llm_review and findings:
            findings = review_with_llm(file_path, content, findings)

        logger.info("Scanned %s: %d finding(s)", file_path, len(findings))
        return FileScanResult(
            file_path=file_path, findings=findings, lines_scanned=len(content.splitlines()),
        )

    def scan(self, request: ScanRequest) -> ScanReport:
        """Scan every file in the request and return the aggregate report."""
        results = [self.scan_file(path, content) for path, content in request.files.items()]
        return ScanReport(results=results)
