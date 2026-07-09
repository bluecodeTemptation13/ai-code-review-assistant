"""
Tests for GitHubClient, using httpx.MockTransport so no real network call is made.

The redirect-following tests exist because of a real bug found during manual
end-to-end testing: GitHub's PR-files `raw_url` 302-redirects to
raw.githubusercontent.com, and httpx does not follow redirects by default.
Without `follow_redirects=True`, every single file fetch failed silently
(logged as a warning, swallowed) and the review always ran on zero files.
"""
import httpx
import pytest

from app.service.github_client import GitHubClient


@pytest.fixture
def mock_httpx_client(monkeypatch):
    """Patch httpx.Client so every call in GitHubClient routes through a MockTransport."""

    def _install(handler):
        real_client_cls = httpx.Client

        def patched_client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(handler)
            return real_client_cls(*args, **kwargs)

        monkeypatch.setattr(httpx, "Client", patched_client)

    return _install


def test_get_file_content_follows_redirect(mock_httpx_client):
    """The real bug: GitHub's raw_url 302s, and content must still be fetched."""

    def handler(request: httpx.Request) -> httpx.Response:
        if "raw.githubusercontent.com" not in str(request.url):
            return httpx.Response(
                302, headers={"Location": "https://raw.githubusercontent.com/a/b/main/file.py"}
            )
        return httpx.Response(200, text="print('hello')\n")

    mock_httpx_client(handler)
    client = GitHubClient(token="fake-token")
    content = client.get_file_content("https://github.com/a/b/raw/main/file.py")
    assert content == "print('hello')\n"


def test_get_pr_files_returns_parsed_json(mock_httpx_client):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json=[{"filename": "a.py", "status": "modified", "raw_url": "https://github.com/x/raw/a.py"}],
        )

    mock_httpx_client(handler)
    client = GitHubClient(token="fake-token")
    files = client.get_pr_files("owner", "repo", 1)
    assert files[0]["filename"] == "a.py"


def test_get_changed_python_files_end_to_end(mock_httpx_client):
    """Full flow: list PR files (one modified, one removed) then fetch content, redirect included."""

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        if "/pulls/1/files" in url:
            return httpx.Response(
                200,
                json=[
                    {"filename": "kept.py", "status": "modified",
                     "raw_url": "https://github.com/o/r/raw/sha/kept.py"},
                    {"filename": "gone.py", "status": "removed",
                     "raw_url": "https://github.com/o/r/raw/sha/gone.py"},
                ],
            )
        if url == "https://github.com/o/r/raw/sha/kept.py":
            return httpx.Response(
                302, headers={"Location": "https://raw.githubusercontent.com/o/r/sha/kept.py"}
            )
        if url == "https://raw.githubusercontent.com/o/r/sha/kept.py":
            return httpx.Response(200, text="x = 1\n")
        raise AssertionError(f"Unexpected request to {url}")

    mock_httpx_client(handler)
    client = GitHubClient(token="fake-token")
    files = client.get_changed_python_files("o", "r", 1)

    assert files == {"kept.py": "x = 1\n"}  # removed file skipped, redirect followed


def test_post_pr_comment_sends_body(mock_httpx_client):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content
        return httpx.Response(201, json={"id": 1})

    mock_httpx_client(handler)
    client = GitHubClient(token="fake-token")
    client.post_pr_comment("owner", "repo", 1, "hello review")
    assert b"hello review" in captured["body"]