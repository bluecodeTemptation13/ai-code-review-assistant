"""
GitHub webhook endpoint.

Flow for a `pull_request` event (opened / synchronize):
  1. Verify the X-Hub-Signature-256 header against GITHUB_WEBHOOK_SECRET.
  2. Pull owner/repo/pr_number out of the payload.
  3. Fetch changed file contents via the GitHub API.
  4. Run the review graph (Security Scanner -> Performance Analyzer -> Report Generator).
  5. Post the resulting Markdown as a PR comment.

Any other event type or action is acknowledged with 200 and ignored —
GitHub retries on non-2xx, so we don't want to reject events we simply
don't act on.
"""
import json

from fastapi import APIRouter, HTTPException, Request

from app.config.settings import get_settings
from app.logger.json_logger import get_logger
from app.service.github_client import GitHubClient, verify_signature

logger = get_logger(__name__)

router = APIRouter(prefix="/webhook", tags=["webhook"])

_RELEVANT_ACTIONS = {"opened", "synchronize", "reopened"}


@router.post("/github")
async def github_webhook(request: Request):
    """Receive a GitHub webhook delivery and, for relevant PR events, run a review."""
    settings = get_settings()
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")

    if not verify_signature(body, signature, settings.github_webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event = request.headers.get("X-GitHub-Event", "")
    payload = json.loads(body)

    if event != "pull_request" or payload.get("action") not in _RELEVANT_ACTIONS:
        logger.info("Ignoring event=%s action=%s", event, payload.get("action"))
        return {"status": "ignored"}

    owner = payload["repository"]["owner"]["login"]
    repo = payload["repository"]["name"]
    pr_number = payload["pull_request"]["number"]

    # Imported here (not at module level) so this module stays import-light
    # for services that only need the client/graph, and to keep the graph's
    # langgraph dependency optional at import time for simpler unit tests.
    from graph import run_review  # pylint: disable=import-outside-toplevel

    client = GitHubClient()
    files = client.get_changed_python_files(owner, repo, pr_number)
    if not files:
        logger.info("No scannable files changed in PR #%d", pr_number)
        return {"status": "no_scannable_files"}

    final_state = run_review(files)
    markdown_report = final_state["markdown_report"]

    client.post_pr_comment(owner, repo, pr_number, markdown_report)
    logger.info("Posted review comment on %s/%s PR #%d", owner, repo, pr_number)

    return {"status": "reviewed", "files_scanned": len(files)}
