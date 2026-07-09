"""Tests for the LangGraph review graph (Day 3). LLM review disabled, no API key needed."""
from graph import run_review


def test_graph_runs_end_to_end_and_produces_markdown():
    files = {
        "config.py": 'api_key = "sk-ant-1234567890abcdef"\n',
        "service.py": (
            "def load(ids, db):\n"
            "    out = []\n"
            "    for i in ids:\n"
            "        out.append(db.execute('SELECT * FROM t WHERE id=?', i))\n"
            "    return out\n"
        ),
    }
    final_state = run_review(files, enable_llm_review=False)

    assert final_state["security_report"] is not None
    assert final_state["performance_report"] is not None
    assert final_state["markdown_report"] is not None
    assert "config.py" in final_state["markdown_report"]
    assert "service.py" in final_state["markdown_report"]
    assert "hardcoded_secret" in {
        f.category for r in final_state["security_report"].results for f in r.findings
    }
    assert "n_plus_one_query" in {
        f.category for r in final_state["performance_report"].results for f in r.findings
    }


def test_graph_runs_clean_on_safe_files():
    files = {"utils.py": "def add(a, b):\n    return a + b\n"}
    final_state = run_review(files, enable_llm_review=False)
    assert "No issues found" in final_state["markdown_report"]
