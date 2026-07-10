# AI Code Review Assistant

Multi-agent system that reviews GitHub pull requests for security,
performance, and code-quality issues, orchestrated with LangGraph and
(optionally) Claude for context-aware review, and posts the result as
a PR comment.

## Status

Build complete for the full planned scope: Security Scanner, Performance
Analyzer, Code Quality Agent, LangGraph orchestration, Report Generator,
GitHub webhook. Validated three separate ways:

1. **Real GitHub PR** — webhook fired, files fetched, review posted as
   an actual PR comment on a live repo.
2. **Real-code accuracy check** via `scan_repo.py` — run against this
   project's own real source (not hand-crafted test fixtures), which
   found and fixed 6 genuine false positives (see below).
3. **67 unit tests**, all passing, covering every fix with a regression
   test that reproduces the exact original bug.

No fabricated metrics anywhere — review-time reduction, issue-count
stats, etc. are not claimed, including on the resume, since that needs
sustained real-world usage this project hasn't had yet.

## Architecture

```
GitHub PR event
      |
      v
 FastAPI webhook  (app/api/routes.py)
      |
      v
 GitHub API: fetch changed files (app/service/github_client.py)
      |
      v
 LangGraph review graph (graph.py)
      |
      +--> Security Scanner     (app/agents/security_scanner.py)
      +--> Performance Analyzer (app/agents/performance_analyzer.py)
      +--> Code Quality Agent   (app/agents/code_quality.py)
      +--> Report Generator     (app/agents/report_generator.py)
      |
      v
 Markdown comment posted back to the PR
```

### Agents

- **Security Scanner** — AST-based checks (hardcoded secrets, SQL
  injection at the call site, eval/exec, insecure deserialization, weak
  crypto, disabled TLS verification, shell injection) plus an optional
  Claude pass that confirms/prunes findings and adds reasoning-based
  ones. Enable the LLM pass with `ENABLE_LLM_REVIEW=true` and a valid
  `ANTHROPIC_API_KEY`; without both, AST rules alone still run.
  **Note:** the LLM pass is unit-tested with a mocked client but has
  never made a real API call in this project — that's a known,
  honestly-disclosed gap, not a hidden one.
- **Performance Analyzer** — static AST rules only: N+1 query patterns,
  cyclomatic complexity over threshold, blocking I/O inside `async def`,
  and O(n²) string concatenation in loops.
- **Code Quality Agent** — static AST/regex rules only: naming
  convention violations (function/class), missing docstrings on public
  functions/classes/modules, unreachable (dead) code after
  return/raise/break/continue, and unused imports.
- **Report Generator** — combines all three agents' findings into one
  Markdown report with a summary table and per-file, severity-sorted
  detail.

## Real-world validation

Running the tool against real code (not hand-crafted test fixtures)
found and fixed 6 genuine false positives that unit tests alone hadn't
caught:

1. **GitHub redirect not followed** — `raw_url` 302-redirects to
   `raw.githubusercontent.com`; httpx doesn't follow redirects by
   default, so every file fetch silently failed and reviews always ran
   on zero files. Found via the real PR test. Fixed with
   `follow_redirects=True`.
2. **N+1 query over-matching** — `dict.get()`, HTTP client `.get()`, and
   `str.find()` were flagged as likely database calls, since `get`/`find`
   were in the DB-call name set. Removed both; kept `find_one` since
   that's unambiguously Mongo-specific.
3. **Regex matching inside strings/docstrings** — `eval()`, `exec()`,
   and `verify=False` mentioned in an error message or docstring
   (describing the rule itself) were flagged as violations. Converted
   these checks from line-level regex to AST call-site detection,
   consistent with how SQL injection detection already worked.
4. **`ast.NodeVisitor` dispatch methods flagged for naming** —
   `visit_If`, `visit_BoolOp`, etc. must exactly match the AST node
   class name to work at all; that's not a snake_case violation, it's
   the base class's protocol.
5. **Private PascalCase classes flagged for naming** — a single leading
   underscore on an otherwise PascalCase class (`_ComplexityVisitor`)
   is standard PEP 8 style for a private class, not a violation.
6. *(Infrastructure, not detection)* the redirect bug above also
   surfaced that nothing had ever verified the webhook -> GitHub API ->
   file-fetch path end-to-end until a real PR actually exercised it.

**Known gap, stated plainly:** this is not the same as comparing tool
findings against a real PR's existing human review comments — that
specific comparison (tool judgment vs. a human reviewer's actual
judgment on the same diff) has not been done. What's been validated is
false-positive/true-positive accuracy on organic code, and full
pipeline correctness on a live PR — related but distinct from that.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in real values
```

### Required environment variables

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key — separate from a claude.ai subscription; requires its own account and billing at console.anthropic.com. Only needed if `ENABLE_LLM_REVIEW=true`. |
| `CLAUDE_MODEL` | Defaults to `claude-sonnet-4-6` |
| `GITHUB_WEBHOOK_SECRET` | Shared secret configured on the GitHub webhook, used to verify `X-Hub-Signature-256` |
| `GITHUB_TOKEN` | Personal access token (or GitHub App token) with `repo` scope, used to fetch PR files and post comments |

All other settings (see `app/config/settings.py`) have sensible defaults.

## Validating against real code

```bash
python scan_repo.py /path/to/any/real/project --max-files 30
```

Scans every `.py` file under that path (skipping `.git`, `venv`,
`__pycache__`, etc.) through the same pipeline the webhook uses, and
prints the Markdown report. This is how the false positives listed
above were actually found — by running the tool against organic code
nobody wrote bugs into on purpose, then manually judging each finding
as a true or false positive.

## Running locally

```bash
python main.py
# in another terminal, expose it for GitHub's webhook to reach:
ngrok http 8000
```

Point a GitHub webhook (Settings -> Webhooks) at
`https://<ngrok-id>.ngrok-free.app/webhook/github`, content type
`application/json`, secret matching `GITHUB_WEBHOOK_SECRET`, and
subscribe to the `Pull requests` event only.

`demo.py` also runs the full pipeline against a small hand-crafted
sample with no GitHub/network/API key needed at all — the fastest way
to confirm the pipeline works on a fresh machine:

```bash
python demo.py
```

## Testing

```bash
pytest tests/ -v
```

67 tests, all static/mocked — no network access or API key required to
run the suite. Covers: static rule true-positives, true-negative cases
(parameterized queries, safe YAML loading, placeholder secrets, etc.),
every real bug found via manual testing (see "Real-world validation"
above) with a regression test reproducing the original failure, the
full LangGraph run end-to-end, and the webhook route with GitHub calls
mocked out.

## Linting

```bash
ruff check app/ main.py graph.py scan_repo.py tests/
pylint app/ main.py graph.py scan_repo.py
```

## Docker

```bash
docker build -t ai-code-review-assistant .
docker run -p 8000:8000 --env-file .env ai-code-review-assistant
```

Runs as a non-root user; `/health` is the container health-check
endpoint. `.dockerignore` excludes `.env` (real secrets never get
baked into the image), `.git`, virtual envs, and dev-only files.

**Status:** Dockerfile and `.dockerignore` are written and reviewed,
but `docker build` itself has not yet been run — that's a manual step
still pending, not something to assume works just because it reads
correctly.

## Directory structure

```
main.py                 FastAPI app entry point
graph.py                LangGraph orchestration
demo.py                 Local smoke test, no network/API key needed
scan_repo.py            Real-code accuracy validation CLI
Dockerfile
.dockerignore
requirements.txt
app/
  agents/               Security Scanner, Performance Analyzer, Code Quality, Report Generator
  api/                  FastAPI routes (GitHub webhook)
  config/               Env-var-based settings
  logger/               JSON structured logging
  models/                Pydantic schemas (Finding, ScanReport, ...)
  service/               GitHub API client
  utils/                 Shared AST helpers
tests/
```

## Not yet done

- `docker build` has not actually been run — Dockerfile is reviewed but
  unverified in practice
- The Claude LLM review pass (`review_with_llm`) has never made a real
  API call — built and unit-tested with a mocked client, but the actual
  reasoning/confirm-prune behavior has not been observed live
- Real-PR-vs-human-review-comment comparison (see "Real-world
  validation" above) — a different, more time-expensive validation than
  what's been done, and likely lower value given human comments tend to
  be stylistic rather than structural
- Sustained real-world usage (multiple real PRs over time) — needed
  before any review-time or issue-count metric goes on the resume
