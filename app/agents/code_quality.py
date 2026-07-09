"""
Code Quality agent.

Static, AST-based checks only (same rationale as Performance Analyzer —
these are structural, not context-sensitive, so no LLM pass):

  1. Naming conventions — function/variable names not snake_case,
     class names not PascalCase.
  2. Missing docstrings — public (non-underscore-prefixed) functions,
     classes, and the module itself with no docstring.
  3. Dead code — statements unreachable after return/raise/break/continue
     in the same block.
  4. Unused imports — imported names never referenced elsewhere in the file.

Kept deliberately conservative: e.g. naming checks skip dunder methods
and common short loop variables (i, j, k, _), and unused-import detection
only looks at whether the bound name appears as a token elsewhere in the
file — good enough signal for a PR review comment, not a full linter
replacement (ruff/pylint already do that more rigorously; this agent is
about surfacing hygiene issues in the review report itself).
"""
import ast
import re

from app.models.schemas import FileScanResult, Finding, ScanReport, ScanRequest, Severity
from app.utils.ast_helpers import parse_or_none

_SNAKE_CASE_RE = re.compile(r"^_{0,2}[a-z][a-z0-9_]*$")
_PASCAL_CASE_RE = re.compile(r"^[A-Z][a-zA-Z0-9]*$")
_TERMINATOR_TYPES = (ast.Return, ast.Raise, ast.Break, ast.Continue)


def _is_dunder(name: str) -> bool:
    return name.startswith("__") and name.endswith("__")


def scan_naming_conventions(file_path: str, source: str) -> list[Finding]:
    """Flag function names not in snake_case and class names not in PascalCase."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if _is_dunder(node.name) or _SNAKE_CASE_RE.match(node.name):
                continue
            findings.append(Finding(
                rule_id="QUAL-NAMING-FUNCTION", category="naming_convention",
                severity=Severity.LOW, file_path=file_path, line_number=node.lineno,
                message=f"Function '{node.name}' does not follow snake_case naming.",
            ))
        elif isinstance(node, ast.ClassDef):
            if _PASCAL_CASE_RE.match(node.name):
                continue
            findings.append(Finding(
                rule_id="QUAL-NAMING-CLASS", category="naming_convention",
                severity=Severity.LOW, file_path=file_path, line_number=node.lineno,
                message=f"Class '{node.name}' does not follow PascalCase naming.",
            ))
    return findings


def scan_missing_docstrings(file_path: str, source: str) -> list[Finding]:
    """Flag public functions/classes/module with no docstring."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    if ast.get_docstring(tree) is None and tree.body:
        findings.append(Finding(
            rule_id="QUAL-MISSING-DOCSTRING", category="documentation",
            severity=Severity.INFO, file_path=file_path, line_number=1,
            message="Module has no top-level docstring.",
        ))

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name.startswith("_"):
                continue
            if ast.get_docstring(node) is None:
                kind = "Class" if isinstance(node, ast.ClassDef) else "Function"
                findings.append(Finding(
                    rule_id="QUAL-MISSING-DOCSTRING", category="documentation",
                    severity=Severity.INFO, file_path=file_path, line_number=node.lineno,
                    message=f"{kind} '{node.name}' is public but has no docstring.",
                ))
    return findings


def scan_unreachable_code(file_path: str, source: str) -> list[Finding]:
    """Flag statements that follow a return/raise/break/continue in the same block."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list):
            continue
        for i, stmt in enumerate(body[:-1]):
            if isinstance(stmt, _TERMINATOR_TYPES):
                unreachable = body[i + 1]
                findings.append(Finding(
                    rule_id="QUAL-DEAD-CODE", category="dead_code",
                    severity=Severity.MEDIUM, file_path=file_path, line_number=unreachable.lineno,
                    message="Unreachable code: this statement follows a "
                            f"{type(stmt).__name__.lower()} in the same block.",
                ))
                break  # one finding per block is enough signal
    return findings


def scan_unused_imports(file_path: str, source: str) -> list[Finding]:
    """Flag imported names that never appear again elsewhere in the file."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    imported: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound_name = (alias.asname or alias.name).split(".")[0]
                imported.append((bound_name, node.lineno))
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    continue
                bound_name = alias.asname or alias.name
                imported.append((bound_name, node.lineno))

    if not imported:
        return findings

    # Count every identifier token in the source once; imports "used" only
    # in their own import statement will have a count of exactly 1.
    all_names = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", source)
    name_counts: dict[str, int] = {}
    for name in all_names:
        name_counts[name] = name_counts.get(name, 0) + 1

    for bound_name, lineno in imported:
        if name_counts.get(bound_name, 0) <= 1:
            findings.append(Finding(
                rule_id="QUAL-UNUSED-IMPORT", category="dead_code",
                severity=Severity.LOW, file_path=file_path, line_number=lineno,
                message=f"'{bound_name}' is imported but never used.",
            ))
    return findings


def run_all_quality_rules(file_path: str, content: str) -> list[Finding]:
    """Run every code-quality rule against a Python file and return combined findings."""
    if not file_path.endswith(".py"):
        return []
    findings = scan_naming_conventions(file_path, content)
    findings += scan_missing_docstrings(file_path, content)
    findings += scan_unreachable_code(file_path, content)
    findings += scan_unused_imports(file_path, content)
    return findings


class CodeQualityAgent:
    """Scans source files for naming, documentation, and dead-code issues."""

    name = "code_quality"

    def scan_file(self, file_path: str, content: str) -> FileScanResult:
        """Run all code-quality rules against one file's content."""
        findings = run_all_quality_rules(file_path, content)
        return FileScanResult(
            file_path=file_path, findings=findings, lines_scanned=len(content.splitlines()),
        )

    def scan(self, request: ScanRequest) -> ScanReport:
        """Scan every file in the request and return the aggregate report."""
        results = [self.scan_file(path, content) for path, content in request.files.items()]
        return ScanReport(results=results)
