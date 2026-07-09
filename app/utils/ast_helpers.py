"""Shared AST helpers used by both the Security Scanner and Performance Analyzer agents."""
import ast


def dotted_name(node: ast.AST) -> str | None:
    """Resolve a Name/Attribute/Call chain to a dotted string, e.g. 'hashlib.md5'."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return None


def parse_or_none(source: str) -> ast.AST | None:
    """Parse Python source, returning None on SyntaxError instead of raising."""
    try:
        return ast.parse(source)
    except SyntaxError:
        return None
