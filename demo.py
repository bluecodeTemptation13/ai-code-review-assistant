"""
Local demo: runs the full review pipeline (Security Scanner + Performance
Analyzer + Code Quality + Report Generator, via the LangGraph orchestration)
against a small sample of intentionally-flawed code, with no GitHub webhook,
no network call, and no API key required.

Run:
    python demo.py

This is the fastest way to confirm the whole pipeline actually works on your
machine before wiring up the GitHub webhook or Docker.
"""
from graph import run_review

SAMPLE_FILES = {
    "sample_app.py": (
        "import os\n"
        "import pickle\n"
        "\n"
        "API_KEY = \"sk-ant-1234567890abcdef\"\n"
        "\n"
        "\n"
        "def GetUserClaims(db, user_ids):\n"
        "    claims = []\n"
        "    for uid in user_ids:\n"
        "        claims.append(db.execute(f\"SELECT * FROM claims WHERE user_id = {uid}\"))\n"
        "    return claims\n"
        "\n"
        "\n"
        "def load_config(stream):\n"
        "    return pickle.loads(stream)\n"
        "\n"
        "\n"
        "async def fetch_status():\n"
        "    import time\n"
        "    time.sleep(2)\n"
        "    return \"ok\"\n"
    ),
    "clean_module.py": (
        '"""A module with no issues, to show a clean scan too."""\n'
        "\n"
        "\n"
        "def add(a, b):\n"
        '    """Return the sum of a and b."""\n'
        "    return a + b\n"
    ),
}


def main():
    final_state = run_review(SAMPLE_FILES, enable_llm_review=False)
    print("\n" + "=" * 70)
    print("REVIEW REPORT")
    print("=" * 70 + "\n")
    print(final_state["markdown_report"])


if __name__ == "__main__":
    main()
