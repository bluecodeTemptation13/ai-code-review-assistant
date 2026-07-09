"""
Tests for the GitHub webhook route.

All GitHub API calls are mocked (monkeypatched on GitHubClient) — no
network access, no real token/secret needed.
"""
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from app.config.settings import get_settings
from app.service.github_client import verify_signature
from main import app


@pytest.fixture(autouse=True)
def _configure_secret(monkeypatch):
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "test-secret")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def _sign(body: bytes, secret: str = "test-secret") -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_verify_signature_accepts_correct_signature():
    body = b'{"a": 1}'
    sig = _sign(body)
    assert verify_signature(body, sig, "test-secret") is True


def test_verify_signature_rejects_wrong_secret():
    body = b'{"a": 1}'
    sig = _sign(body, secret="wrong")
    assert verify_signature(body, sig, "test-secret") is False


def test_verify_signature_rejects_missing_header():
    assert verify_signature(b"{}", None, "test-secret") is False


def test_webhook_rejects_invalid_signature():
    client = TestClient(app)
    body = json.dumps({"action": "opened"}).encode()
    response = client.post(
        "/webhook/github",
        content=body,
        headers={"X-Hub-Signature-256": "sha256=deadbeef", "X-GitHub-Event": "pull_request"},
    )
    assert response.status_code == 401


def test_webhook_ignores_non_pull_request_event():
    client = TestClient(app)
    payload = {"action": "opened"}
    body = json.dumps(payload).encode()
    response = client.post(
        "/webhook/github",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "push"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_webhook_ignores_irrelevant_pr_action():
    client = TestClient(app)
    payload = {
        "action": "closed",
        "repository": {"owner": {"login": "acme"}, "name": "widgets"},
        "pull_request": {"number": 7},
    }
    body = json.dumps(payload).encode()
    response = client.post(
        "/webhook/github",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "ignored"


def test_webhook_runs_review_and_posts_comment(monkeypatch):
    from app.service import github_client as gh_module

    def fake_get_changed_python_files(self, owner, repo, pr_number):
        return {"app.py": 'api_key = "sk-ant-1234567890abcdef"\n'}

    posted = {}

    def fake_post_pr_comment(self, owner, repo, pr_number, body):
        posted["owner"] = owner
        posted["repo"] = repo
        posted["pr_number"] = pr_number
        posted["body"] = body

    monkeypatch.setattr(gh_module.GitHubClient, "get_changed_python_files", fake_get_changed_python_files)
    monkeypatch.setattr(gh_module.GitHubClient, "post_pr_comment", fake_post_pr_comment)

    client = TestClient(app)
    payload = {
        "action": "opened",
        "repository": {"owner": {"login": "acme"}, "name": "widgets"},
        "pull_request": {"number": 42},
    }
    body = json.dumps(payload).encode()
    response = client.post(
        "/webhook/github",
        content=body,
        headers={"X-Hub-Signature-256": _sign(body), "X-GitHub-Event": "pull_request"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "reviewed"
    assert posted["owner"] == "acme"
    assert posted["repo"] == "widgets"
    assert posted["pr_number"] == 42
    assert "hardcoded_secret" in posted["body"] or "SEC-HARDCODED-SECRET" in posted["body"]
