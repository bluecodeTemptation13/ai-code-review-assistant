"""Tests for the Performance Analyzer agent (all static/AST-based, no API key needed)."""
from app.agents.performance_analyzer import PerformanceAnalyzerAgent


def _categories(result):
    return {f.category for f in result.findings}


def make_agent():
    return PerformanceAnalyzerAgent()


# --- N+1 queries --------------------------------------------------------------

def test_detects_n_plus_one_query_in_for_loop():
    code = (
        "def load_claims(claim_ids, db):\n"
        "    claims = []\n"
        "    for claim_id in claim_ids:\n"
        "        claims.append(db.execute('SELECT * FROM claims WHERE id = ?', claim_id))\n"
        "    return claims\n"
    )
    result = make_agent().scan_file("service.py", code)
    assert "n_plus_one_query" in _categories(result)


def test_single_query_outside_loop_not_flagged():
    code = (
        "def load_claims(claim_ids, db):\n"
        "    return db.execute('SELECT * FROM claims WHERE id IN (?)', claim_ids)\n"
    )
    result = make_agent().scan_file("service.py", code)
    assert "n_plus_one_query" not in _categories(result)


def test_dict_get_in_loop_not_flagged_as_n_plus_one():
    """Real false positive found by running this tool on its own codebase:
    file_meta.get("status") in a loop is a plain dict lookup, not a DB call."""
    code = (
        "def process(items):\n"
        "    out = []\n"
        "    for item in items:\n"
        "        out.append(item.get('status'))\n"
        "    return out\n"
    )
    result = make_agent().scan_file("service.py", code)
    assert "n_plus_one_query" not in _categories(result)


def test_http_client_get_in_loop_not_flagged_as_n_plus_one():
    code = (
        "def fetch_all(urls, client):\n"
        "    out = []\n"
        "    for url in urls:\n"
        "        out.append(client.get(url))\n"
        "    return out\n"
    )
    result = make_agent().scan_file("service.py", code)
    assert "n_plus_one_query" not in _categories(result)


def test_str_find_in_loop_not_flagged_as_n_plus_one():
    code = (
        "def count_matches(lines, needle):\n"
        "    hits = []\n"
        "    for line in lines:\n"
        "        hits.append(line.find(needle))\n"
        "    return hits\n"
    )
    result = make_agent().scan_file("service.py", code)
    assert "n_plus_one_query" not in _categories(result)


# --- cyclomatic complexity ------------------------------------------------------

def test_flags_high_complexity_function():
    branches = "\n".join(f"    if x == {i}:\n        y += 1" for i in range(15))
    code = f"def handler(x):\n    y = 0\n{branches}\n    return y\n"
    result = make_agent().scan_file("handler.py", code)
    assert "cyclomatic_complexity" in _categories(result)


def test_simple_function_not_flagged_for_complexity():
    code = "def add(a, b):\n    return a + b\n"
    result = make_agent().scan_file("utils.py", code)
    assert "cyclomatic_complexity" not in _categories(result)


# --- blocking I/O in async ------------------------------------------------------

def test_detects_time_sleep_in_async_def():
    code = "import time\nasync def handler():\n    time.sleep(2)\n"
    result = make_agent().scan_file("handler.py", code)
    assert "blocking_io" in _categories(result)


def test_detects_requests_get_in_async_def():
    code = "import requests\nasync def handler():\n    requests.get('http://example.com')\n"
    result = make_agent().scan_file("handler.py", code)
    assert "blocking_io" in _categories(result)


def test_asyncio_sleep_in_async_def_not_flagged():
    code = "import asyncio\nasync def handler():\n    await asyncio.sleep(2)\n"
    result = make_agent().scan_file("handler.py", code)
    assert "blocking_io" not in _categories(result)


def test_time_sleep_in_sync_def_not_flagged():
    code = "import time\ndef handler():\n    time.sleep(2)\n"
    result = make_agent().scan_file("handler.py", code)
    assert "blocking_io" not in _categories(result)


# --- inefficient loops -----------------------------------------------------------

def test_detects_string_concat_in_loop():
    code = (
        "def build_report(rows):\n"
        "    result = ''\n"
        "    for row in rows:\n"
        "        result += str(row)\n"
        "    return result\n"
    )
    result = make_agent().scan_file("report.py", code)
    assert "inefficient_loop" in _categories(result)


def test_join_not_flagged():
    code = (
        "def build_report(rows):\n"
        "    return ''.join(str(row) for row in rows)\n"
    )
    result = make_agent().scan_file("report.py", code)
    assert "inefficient_loop" not in _categories(result)


def test_non_python_file_returns_no_findings():
    result = make_agent().scan_file("script.js", "for (let i=0;i<10;i++) { db.get(i); }")
    assert result.findings == []
