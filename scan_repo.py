"""
Scan any local directory of real Python files through the full review
pipeline (Security Scanner + Performance Analyzer + Code Quality +
Report Generator) and print the Markdown report.

This exists specifically to do real accuracy validation — running the
tool against organic code nobody wrote bugs into on purpose (unlike
demo.py's hand-crafted sample) and manually judging each finding as a
true or false positive. That's the only way to actually know the
false-positive rate, and it's the missing piece before any accuracy
claim goes on a resume.

Usage:
    python scan_repo.py /path/to/some/real/project
    python scan_repo.py /path/to/some/real/project --max-files 20
    python scan_repo.py /path/to/some/real/project --output report.md

Skips common non-source directories (venv, node_modules, .git, __pycache__)
and anything over the configured max file size (mirrors the security
scanner's own size guard, so this behaves the same as the real webhook path).
"""
import argparse
import sys
from pathlib import Path

from graph import run_review

_SKIP_DIRS = {
    ".git", ".venv", "venv", "__pycache__", "node_modules",
    ".pytest_cache", ".ruff_cache", "build", "dist", ".mypy_cache",
}
_MAX_FILE_SIZE_BYTES = 500_000


def collect_python_files(root: Path, max_files: int) -> dict[str, str]:
    """Walk `root`, returning {relative_path: content} for scannable .py files."""
    files: dict[str, str] = {}
    for path in sorted(root.rglob("*.py")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if path.stat().st_size > _MAX_FILE_SIZE_BYTES:
            print(f"Skipping {path} (exceeds {_MAX_FILE_SIZE_BYTES} bytes)", file=sys.stderr)
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            print(f"Skipping {path}: {exc}", file=sys.stderr)
            continue
        files[str(path.relative_to(root))] = content
        if len(files) >= max_files:
            break
    return files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", help="Path to the real codebase to scan")
    parser.add_argument(
        "--max-files", type=int, default=30,
        help="Cap on number of files to scan (default: 30, keeps runs fast)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Write the report to this file instead of only printing it",
    )
    parser.add_argument(
        "--llm-review", action="store_true",
        help="Enable the Claude LLM review pass (requires ANTHROPIC_API_KEY)",
    )
    args = parser.parse_args()

    root = Path(args.directory).expanduser().resolve()
    if not root.is_dir():
        print(f"Error: {root} is not a directory", file=sys.stderr)
        sys.exit(1)

    files = collect_python_files(root, args.max_files)
    if not files:
        print(f"No scannable .py files found under {root}", file=sys.stderr)
        sys.exit(1)

    print(f"Scanning {len(files)} file(s) under {root} ...", file=sys.stderr)
    final_state = run_review(files, enable_llm_review=args.llm_review)
    report = final_state["markdown_report"]

    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
        print(f"Report written to {args.output}", file=sys.stderr)
    print(report)


if __name__ == "__main__":
    main()