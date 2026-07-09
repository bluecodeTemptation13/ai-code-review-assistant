# AI Code Review Assistant

Multi-agent system that reviews GitHub pull requests for security and
performance issues, orchestrated with LangGraph and (optionally) Claude
for context-aware review, and posts the result as a PR comment.

## Status

Build complete for the full planned scope: Security Scanner, Performance
Analyzer, Code Quality Agent, LangGraph orchestration, Report Generator,
GitHub webhook. **Not yet run against a real PR** — that's the next step
before any metrics (review time reduction, issues caught, PR count) get
added anywhere, including the resume. No fabricated numbers here.

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

- **Security Scanner** — static AST/regex rules (hardcoded secrets, SQL
  injection at the call site, eval/exec, insecure deserialization, weak
  crypto, disabled TLS verification, shell injection) plus an optional
  Claude pass that confirms/prunes findings and adds reasoning-based ones.
  Enable the LLM pass with `ENABLE_LLM_REVIEW=true` and a valid
  `ANTHROPIC_API_KEY`; without both, static rules alone still run.
- **Performance Analyzer** — static AST rules only: N+1 query patterns,
  cyclomatic complexity over threshold, blocking I/O inside `async def`,
  and O(n²) string concatenation in loops.
- **Code Quality Agent** — static AST/regex rules only: naming convention
  violations (function/class), missing docstrings on public
  functions/classes/modules, unreachable (dead) code after
  return/raise/break/continue, and unused imports.
- **Report Generator** — combines all three agents' findings into one
  Markdown report with a summary table and per-file, severity-sorted detail.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # fill in real values
```

### Required environment variables

| Variable | Purpose |
|---|---|
| `ANTHROPIC_API_KEY` | Claude API key (only needed if `ENABLE_LLM_REVIEW=true`) |
| `CLAUDE_MODEL` | Defaults to `claude-sonnet-4-6` |
| `GITHUB_WEBHOOK_SECRET` | Shared secret configured on the GitHub webhook, used to verify `X-Hub-Signature-256` |
| `GITHUB_TOKEN` | Personal access token (or GitHub App token) with `repo` scope, used to fetch PR files and post comments |

All other settings (see `app/config/settings.py`) have sensible defaults.

## Running locally

```bash
python main.py
# in another terminal, expose it for GitHub's webhook to reach:
ngrok http 8000
```

Point a GitHub webhook (Settings → Webhooks) at
`https://<ngrok-id>.ngrok.io/webhook/github`, content type
`application/json`, secret matching `GITHUB_WEBHOOK_SECRET`, and
subscribe to the `Pull requests` event.

## Testing

```bash
pytest tests/ -v
```

56 tests, all static/mocked — no network access or API key required to
run the suite. Covers: static rule true-positives, true-negative cases
(parameterized queries, safe YAML loading, placeholder secrets, etc.),
the full LangGraph run end-to-end, and the webhook route with GitHub
calls mocked out.

## Linting

```bash
ruff check app/ main.py graph.py tests/
pylint app/ main.py graph.py
```

## Docker

```bash
docker build -t ai-code-review-assistant .
docker run -p 8000:8000 --env-file .env ai-code-review-assistant
```

Runs as a non-root user; `/health` is the container health-check endpoint.

## Directory structure

```
main.py                 FastAPI app entry point
graph.py                LangGraph orchestration
Dockerfile
requirements.txt
app/
  agents/               Security Scanner, Performance Analyzer, Report Generator
  api/                  FastAPI routes (GitHub webhook)
  config/               Env-var-based settings
  logger/               JSON structured logging
  models/                Pydantic schemas (Finding, ScanReport, ...)
  service/               GitHub API client
  utils/                 Shared AST helpers
tests/
```

## Not yet done

- Real-PR validation (accuracy check against actual review comments a
  human would leave)
- Metrics of any kind — pending the above
