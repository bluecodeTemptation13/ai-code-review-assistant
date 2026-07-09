"""
Performance Analyzer agent.

Static, AST-based checks only — no LLM pass, since these are structural
patterns (loop shapes, call sites, cyclomatic paths) that don't benefit
much from an LLM second opinion the way security context-sensitivity does.

Checks:
  1. N+1 queries      — a DB-call-shaped function invoked inside a loop body.
  2. Cyclomatic complexity — McCabe complexity per function, flagged above threshold.
  3. Blocking I/O in async — sync-blocking calls (time.sleep, requests.*, open in
     read/write mode via urllib) made inside an `async def`.
  4. Inefficient loops — string built via `+=` inside a loop (O(n^2) instead of
     join/list-accumulate).
"""
import ast

from app.models.schemas import FileScanResult, Finding, ScanReport, ScanRequest, Severity
from app.utils.ast_helpers import dotted_name, parse_or_none

_DB_CALL_NAMES = {
    "execute", "executemany", "query", "filter", "get", "find", "find_one",
    "fetchone", "fetchall", "select", "objects",
}

_COMPLEXITY_THRESHOLD = 10


def _loop_body_calls(loop_node: ast.AST):
    for child in ast.walk(loop_node):
        if isinstance(child, ast.Call):
            yield child


def scan_n_plus_one(file_path: str, source: str) -> list[Finding]:
    """Flag DB-call-shaped calls made inside a for/while loop body (classic N+1)."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            continue
        for call in _loop_body_calls(node):
            called = dotted_name(call.func)
            if not called:
                continue
            short_name = called.rsplit(".", maxsplit=1)[-1]
            if short_name in _DB_CALL_NAMES:
                findings.append(Finding(
                    rule_id="PERF-N-PLUS-ONE", category="n_plus_one_query",
                    severity=Severity.HIGH, file_path=file_path, line_number=call.lineno,
                    message=f"'{short_name}()' called inside a loop — likely N+1 query pattern. "
                            "Consider batching (e.g. a single IN-clause query or bulk fetch).",
                ))
                break  # one finding per loop is enough signal
    return findings


class _ComplexityVisitor(ast.NodeVisitor):
    """Counts McCabe-style decision points within a single function body."""

    # visit_* method names are dictated by ast.NodeVisitor's dispatch protocol
    # and must match the AST node class names exactly (not snake_case).
    # pylint: disable=invalid-name

    def __init__(self):
        self.complexity = 1  # base path

    def visit_If(self, node):  # noqa: N802 - ast visitor naming convention
        self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node):  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_AsyncFor(self, node):  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node):  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node):  # noqa: N802
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node):  # noqa: N802
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_With(self, node):  # noqa: N802
        self.generic_visit(node)  # not a branch point, don't count


def scan_cyclomatic_complexity(file_path: str, source: str) -> list[Finding]:
    """Flag functions whose McCabe complexity exceeds the configured threshold."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        visitor = _ComplexityVisitor()
        for child in ast.iter_child_nodes(node):
            visitor.visit(child)
        if visitor.complexity > _COMPLEXITY_THRESHOLD:
            findings.append(Finding(
                rule_id="PERF-HIGH-COMPLEXITY", category="cyclomatic_complexity",
                severity=Severity.MEDIUM, file_path=file_path, line_number=node.lineno,
                message=f"Function '{node.name}' has cyclomatic complexity "
                        f"{visitor.complexity} (threshold {_COMPLEXITY_THRESHOLD}). "
                        "Consider splitting into smaller functions.",
            ))
    return findings


def scan_blocking_io_in_async(file_path: str, source: str) -> list[Finding]:
    """Flag synchronous-blocking calls made inside an async def (blocks the event loop)."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            called = dotted_name(call.func)
            if not called:
                continue
            is_blocking = (
                called == "time.sleep"
                or called.endswith("urlopen")
                or (called.startswith("requests.") and called.rsplit(".", maxsplit=1)[-1]
                    in {"get", "post", "put", "delete", "patch"})
            )
            if is_blocking:
                findings.append(Finding(
                    rule_id="PERF-BLOCKING-IO-IN-ASYNC", category="blocking_io",
                    severity=Severity.MEDIUM, file_path=file_path, line_number=call.lineno,
                    message=f"'{called}()' is a blocking call inside async def '{node.name}' — "
                            "it will block the event loop. Use an async equivalent "
                            "(httpx.AsyncClient, asyncio.sleep, etc.).",
                ))
    return findings


def scan_inefficient_string_concat(file_path: str, source: str) -> list[Finding]:
    """Flag `result += ...` string accumulation inside a loop (O(n^2) instead of join())."""
    findings: list[Finding] = []
    tree = parse_or_none(source)
    if tree is None:
        return findings

    for node in ast.walk(tree):
        if not isinstance(node, (ast.For, ast.AsyncFor, ast.While)):
            continue
        for child in ast.walk(node):
            if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                if isinstance(child.target, ast.Name):
                    findings.append(Finding(
                        rule_id="PERF-STRING-CONCAT-IN-LOOP", category="inefficient_loop",
                        severity=Severity.LOW, file_path=file_path, line_number=child.lineno,
                        message=f"'{child.target.id} += ...' inside a loop rebuilds the "
                                "string each iteration (O(n^2)). Prefer collecting into a "
                                "list and ''.join(...) once.",
                    ))
    return findings


def run_all_performance_rules(file_path: str, content: str) -> list[Finding]:
    """Run every performance rule against a Python file and return combined findings."""
    if not file_path.endswith(".py"):
        return []
    findings = scan_n_plus_one(file_path, content)
    findings += scan_cyclomatic_complexity(file_path, content)
    findings += scan_blocking_io_in_async(file_path, content)
    findings += scan_inefficient_string_concat(file_path, content)
    return findings


class PerformanceAnalyzerAgent:
    """Scans source files for common performance anti-patterns."""

    name = "performance_analyzer"

    def scan_file(self, file_path: str, content: str) -> FileScanResult:
        """Run all performance rules against one file's content."""
        findings = run_all_performance_rules(file_path, content)
        return FileScanResult(
            file_path=file_path, findings=findings, lines_scanned=len(content.splitlines()),
        )

    def scan(self, request: ScanRequest) -> ScanReport:
        """Scan every file in the request and return the aggregate report."""
        results = [self.scan_file(path, content) for path, content in request.files.items()]
        return ScanReport(results=results)
