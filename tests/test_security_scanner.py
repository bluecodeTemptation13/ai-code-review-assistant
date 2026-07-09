"""
Tests for the Security Scanner agent — static rule layer only.
Runs with no network access and no ANTHROPIC_API_KEY (enable_llm_review=False).
"""
from app.agents.security_scanner import SecurityScannerAgent
from app.models.schemas import ScanRequest


def _categories(result):
    return {f.category for f in result.findings}


def make_agent():
    return SecurityScannerAgent(enable_llm_review=False)


# --- hardcoded secrets -------------------------------------------------------

def test_detects_hardcoded_api_key():
    code = 'api_key = "sk-ant-1234567890abcdef"\n'
    result = make_agent().scan_file("config.py", code)
    assert "hardcoded_secret" in _categories(result)


def test_detects_aws_access_key():
    code = 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n'
    result = make_agent().scan_file("config.py", code)
    assert "hardcoded_secret" in _categories(result)


def test_ignores_short_non_secret_assignment():
    code = 'status = "ok"\ncount = 5\n'
    result = make_agent().scan_file("app.py", code)
    assert result.findings == []


def test_ignores_placeholder_secret_values():
    code = (
        'api_key = "changeme"\n'
        'password = "your_password_here"\n'
        'token = "<REPLACE_ME>"\n'
    )
    result = make_agent().scan_file("config.py", code)
    assert "hardcoded_secret" not in _categories(result)


def test_ignores_env_var_lookup():
    code = 'api_key = os.getenv("API_KEY")\n'
    result = make_agent().scan_file("config.py", code)
    assert result.findings == []


# --- SQL injection (AST call-site based) -------------------------------------

def test_detects_sql_injection_fstring_at_call_site():
    code = (
        "def get_user(cursor, user_id):\n"
        '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    )
    result = make_agent().scan_file("db.py", code)
    assert "sql_injection" in _categories(result)


def test_detects_sql_injection_concatenation_at_call_site():
    code = (
        "def get_user(cursor, name):\n"
        '    cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")\n'
    )
    result = make_agent().scan_file("db.py", code)
    assert "sql_injection" in _categories(result)


def test_parameterized_query_not_flagged():
    code = (
        "def get_user(cursor, user_id):\n"
        '    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n'
    )
    result = make_agent().scan_file("db.py", code)
    assert "sql_injection" not in _categories(result)


def test_fstring_sql_not_executed_is_not_flagged():
    """A SQL-looking f-string that is only logged, never executed, should not fire."""
    code = (
        "def log_query(user_id):\n"
        '    message = f"SELECT * FROM users WHERE id = {user_id}"\n'
        "    logger.info(message)\n"
    )
    result = make_agent().scan_file("db.py", code)
    assert "sql_injection" not in _categories(result)


# --- dangerous calls ----------------------------------------------------------

def test_detects_eval_usage():
    code = "result = eval(user_input)\n"
    result = make_agent().scan_file("handler.py", code)
    assert "dangerous_eval" in _categories(result)


def test_eval_mentioned_in_string_not_flagged():
    """Real false positive found scanning this project's own source: a docstring or
    message describing the eval() rule was itself matched as a violation."""
    code = 'message = "Use of eval() on data that may be externally influenced."\n'
    result = make_agent().scan_file("rules.py", code)
    assert "dangerous_eval" not in _categories(result)


def test_verify_false_mentioned_in_string_not_flagged():
    code = 'message = "TLS certificate verification is disabled (verify=False)."\n'
    result = make_agent().scan_file("rules.py", code)
    assert "insecure_transport" not in _categories(result)


def test_detects_pickle_loads():
    code = "import pickle\ndata = pickle.loads(payload)\n"
    result = make_agent().scan_file("handler.py", code)
    assert "insecure_deserialization" in _categories(result)


def test_detects_yaml_load_unsafe():
    code = "import yaml\nconfig = yaml.load(stream)\n"
    result = make_agent().scan_file("handler.py", code)
    assert "insecure_deserialization" in _categories(result)


def test_yaml_safe_loader_not_flagged():
    code = "import yaml\nconfig = yaml.load(stream, Loader=yaml.SafeLoader)\n"
    result = make_agent().scan_file("handler.py", code)
    assert "insecure_deserialization" not in _categories(result)


def test_detects_weak_hash_md5():
    code = "import hashlib\nh = hashlib.md5(password.encode())\n"
    result = make_agent().scan_file("auth.py", code)
    assert "weak_crypto" in _categories(result)


def test_detects_tls_verify_disabled():
    code = "requests.get(url, verify=False)\n"
    result = make_agent().scan_file("client.py", code)
    assert "insecure_transport" in _categories(result)


def test_detects_shell_true_subprocess():
    code = "subprocess.Popen(cmd, shell=True)\n"
    result = make_agent().scan_file("runner.py", code)
    assert "shell_injection" in _categories(result)


def test_subprocess_without_shell_true_not_flagged():
    code = "subprocess.Popen(['ls', '-la'])\n"
    result = make_agent().scan_file("runner.py", code)
    assert "shell_injection" not in _categories(result)


# --- aggregate report ---------------------------------------------------------

def test_scan_report_aggregates_multiple_files():
    request = ScanRequest(
        files={
            "a.py": 'api_key = "sk-ant-1234567890abcdef"\n',
            "b.py": "x = 1\n",
        }
    )
    report = make_agent().scan(request)
    assert len(report.results) == 2
    assert report.total_findings == 1
    assert report.findings_by_severity.get("CRITICAL") == 1
