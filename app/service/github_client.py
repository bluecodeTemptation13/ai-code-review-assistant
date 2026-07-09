"""
GitHub integration for the webhook flow.

Two responsibilities, kept separate from the webhook route so they can be
unit tested without a real network call:
  1. verify_signature   — HMAC-SHA256 check on inbound webhook payloads.
  2. GitHubClient        — outbound calls to fetch PR files and post a
                            review comment, using a personal access token.
"""
import hashlib
import hmac

import httpx

from app.config.settings import get_settings
from app.logger.json_logger import get_logger

logger = get_logger(__name__)

# GitHub PR file statuses we don't need to scan (nothing to review).
_SKIP_STATUSES = {"removed"}
_MAX_FILES_PER_PR = 50


def verify_signature(payload_body: bytes, signature_header: str | None, secret: str) -> bool:
    """
    Verify the `X-Hub-Signature-256` header GitHub sends with each webhook
    delivery. Returns False (not an exception) on any mismatch or missing
    header so the caller can respond with a clean 401.
    """
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    if not secret:
        # No secret configured means we can't verify — fail closed.
        return False
    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


class GitHubClient:
    """Thin wrapper around the subset of the GitHub REST API this service needs."""

    def __init__(self, token: str | None = None, base_url: str | None = None):
        settings = get_settings()
        self.token = token if token is not None else settings.github_token
        self.base_url = base_url if base_url is not None else settings.github_api_base_url

    def _headers(self) -> dict:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def get_pr_files(self, owner: str, repo: str, pr_number: int) -> list[dict]:
        """Return the list of changed files for a PR (name, status, raw_url, patch)."""
        url = f"{self.base_url}/repos/{owner}/{repo}/pulls/{pr_number}/files"
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            params = {"per_page": _MAX_FILES_PER_PR}
            response = client.get(url, headers=self._headers(), params=params)
            response.raise_for_status()
            return response.json()

    def get_file_content(self, raw_url: str) -> str:
        """Fetch the raw content of a file from its GitHub-provided raw_url."""
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            response = client.get(raw_url, headers=self._headers())
            response.raise_for_status()
            return response.text

    def get_changed_python_files(self, owner: str, repo: str, pr_number: int) -> dict[str, str]:
        """Fetch changed files for a PR, returning {path: content} for scannable files."""
        files: dict[str, str] = {}
        for file_meta in self.get_pr_files(owner, repo, pr_number):
            if file_meta.get("status") in _SKIP_STATUSES:
                continue
            raw_url = file_meta.get("raw_url")
            filename = file_meta.get("filename")
            if not raw_url or not filename:
                continue
            try:
                files[filename] = self.get_file_content(raw_url)
            except httpx.HTTPError as exc:
                logger.warning("Failed to fetch content for %s: %s", filename, exc)
        return files

    def post_pr_comment(self, owner: str, repo: str, pr_number: int, body: str) -> None:
        """Post a Markdown comment on a PR (uses the issues API, which PRs share)."""
        url = f"{self.base_url}/repos/{owner}/{repo}/issues/{pr_number}/comments"
        with httpx.Client(timeout=15, follow_redirects=True) as client:
            response = client.post(url, headers=self._headers(), json={"body": body})
            response.raise_for_status()
