"""Tests for the Code Quality agent (all static/AST-based, no API key needed)."""
from app.agents.code_quality import CodeQualityAgent


def _categories(result):
    return {f.category for f in result.findings}


def make_agent():
    return CodeQualityAgent()


# --- naming conventions --------------------------------------------------------

def test_flags_non_snake_case_function():
    code = "def MyFunction():\n    return 1\n"
    result = make_agent().scan_file("mod.py", code)
    assert "naming_convention" in _categories(result)


def test_snake_case_function_not_flagged():
    code = '"""Module docstring."""\ndef my_function():\n    """Docstring."""\n    return 1\n'
    result = make_agent().scan_file("mod.py", code)
    assert "naming_convention" not in _categories(result)


def test_flags_non_pascal_case_class():
    code = "class my_class:\n    pass\n"
    result = make_agent().scan_file("mod.py", code)
    assert "naming_convention" in _categories(result)


def test_pascal_case_class_not_flagged():
    code = '"""Module docstring."""\nclass MyClass:\n    """Docstring."""\n'
    result = make_agent().scan_file("mod.py", code)
    assert "naming_convention" not in _categories(result)


def test_dunder_methods_not_flagged():
    code = (
        '"""Module docstring."""\n'
        "class Thing:\n"
        '    """Docstring."""\n'
        "    def __init__(self):\n"
        "        pass\n"
    )
    result = make_agent().scan_file("mod.py", code)
    assert "naming_convention" not in _categories(result)


def test_ast_visitor_dispatch_methods_not_flagged():
    """Real false positive found scanning this project's own source: ast.NodeVisitor
    requires exact visit_<NodeClassName> method names to dispatch correctly -
    that's not a naming violation, it's the base class's protocol."""
    code = (
        '"""Module docstring."""\n'
        "import ast\n\n\n"
        "class ComplexityVisitor(ast.NodeVisitor):\n"
        '    """Docstring."""\n'
        "    def visit_If(self, node):\n"
        "        self.generic_visit(node)\n"
        "    def visit_BoolOp(self, node):\n"
        "        self.generic_visit(node)\n"
    )
    result = make_agent().scan_file("mod.py", code)
    assert "naming_convention" not in _categories(result)


def test_private_pascal_case_class_not_flagged():
    """A single leading underscore for a private/internal class is standard
    PEP 8 style, not a naming violation."""
    code = (
        '"""Module docstring."""\n'
        "class _InternalHelper:\n"
        '    """Docstring."""\n'
    )
    result = make_agent().scan_file("mod.py", code)
    assert "naming_convention" not in _categories(result)
    

# --- missing docstrings ---------------------------------------------------------

def test_flags_public_function_missing_docstring():
    code = '"""Module docstring."""\ndef do_thing():\n    return 1\n'
    result = make_agent().scan_file("mod.py", code)
    assert "documentation" in _categories(result)


def test_private_function_missing_docstring_not_flagged():
    code = '"""Module docstring."""\ndef _helper():\n    return 1\n'
    result = make_agent().scan_file("mod.py", code)
    assert "documentation" not in _categories(result)


def test_module_missing_docstring_flagged():
    code = "def do_thing():\n    '''Has one.'''\n    return 1\n"
    result = make_agent().scan_file("mod.py", code)
    messages = " ".join(f.message for f in result.findings)
    assert "Module has no top-level docstring" in messages


# --- unreachable code ------------------------------------------------------------

def test_flags_code_after_return():
    code = (
        '"""Module docstring."""\n'
        "def do_thing():\n"
        "    '''Docstring.'''\n"
        "    return 1\n"
        "    print('never runs')\n"
    )
    result = make_agent().scan_file("mod.py", code)
    assert "dead_code" in _categories(result)


def test_code_in_if_branch_after_loop_return_not_flagged():
    code = (
        '"""Module docstring."""\n'
        "def do_thing(x):\n"
        "    '''Docstring.'''\n"
        "    if x:\n"
        "        return 1\n"
        "    return 2\n"
    )
    result = make_agent().scan_file("mod.py", code)
    assert "dead_code" not in _categories(result)


# --- unused imports ---------------------------------------------------------------

def test_flags_unused_import():
    code = '"""Module docstring."""\nimport os\n\ndef do_thing():\n    """Docstring."""\n    return 1\n'
    result = make_agent().scan_file("mod.py", code)
    assert "dead_code" in _categories(result)
    messages = " ".join(f.message for f in result.findings)
    assert "'os' is imported but never used" in messages


def test_used_import_not_flagged():
    code = (
        '"""Module docstring."""\n'
        "import os\n\n"
        "def do_thing():\n"
        "    '''Docstring.'''\n"
        "    return os.getcwd()\n"
    )
    result = make_agent().scan_file("mod.py", code)
    unused_import_msgs = [f for f in result.findings if f.rule_id == "QUAL-UNUSED-IMPORT"]
    assert unused_import_msgs == []


def test_non_python_file_returns_no_findings():
    result = make_agent().scan_file("script.js", "function MyFunc() { return 1; }")
    assert result.findings == []
