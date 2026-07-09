"""
JSON structured logging, matching the log schema used across
IndustryOps-style services:

{
  "@timestamp": "...",
  "message": "...",
  "function_name": "...",
  "file_name": "...",
  "line_no": 22,
  "logger_name": "<servicename>",
  "@version": "1.0",
  "thread_name": "MainThread",
  "level": "INFO",
  "application": "ai-code-review-assistant"
}
"""
import inspect
import json
import logging
import sys
import threading
from datetime import datetime, timezone

APPLICATION_NAME = "ai-code-review-assistant"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "message": record.getMessage(),
            "function_name": record.funcName,
            "file_name": record.filename,
            "line_no": record.lineno,
            "logger_name": record.name,
            "@version": "1.0",
            "thread_name": threading.current_thread().name,
            "level": record.levelname,
            "application": APPLICATION_NAME,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a configured JSON logger for the given name (defaults to caller's module)."""
    if name is None:
        frame = inspect.stack()[1]
        name = frame.frame.f_globals.get("__name__", "app")

    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger
