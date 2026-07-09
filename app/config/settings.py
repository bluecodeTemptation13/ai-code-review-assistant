"""
Application configuration.

All configurable values are sourced from environment variables.
No secrets or connection strings are hardcoded.
"""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Application
    app_name: str = "ai-code-review-assistant"
    log_level: str = "INFO"

    # Claude API
    anthropic_api_key: str = ""
    claude_model: str = "claude-sonnet-4-6"
    claude_max_tokens: int = 2000

    # GitHub webhook (used from Day 5 onward)
    github_webhook_secret: str = ""
    github_token: str = ""
    github_api_base_url: str = "https://api.github.com"

    # Security scanner behavior
    max_file_size_bytes: int = 500_000
    enable_llm_review: bool = True


@lru_cache
def get_settings() -> Settings:
    """Return a cached Settings instance."""
    return Settings()
