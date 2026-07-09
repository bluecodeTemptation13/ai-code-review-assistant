"""
Entry point for the AI Code Review Assistant.

Wires the GitHub webhook router (Day 5) alongside the health-check endpoint.
"""
from fastapi import FastAPI

from app.api.routes import router as webhook_router
from app.logger.json_logger import get_logger

logger = get_logger(__name__)

app = FastAPI(title="ai-code-review-assistant")
app.include_router(webhook_router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting ai-code-review-assistant")
    uvicorn.run(app, host="0.0.0.0", port=8000)
