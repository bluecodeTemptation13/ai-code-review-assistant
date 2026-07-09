"""
LangGraph orchestration for the AI Code Review Assistant.

Graph shape (Day 1-4 agents wired together):

    START -> security_scan -> performance_scan -> generate_report -> END

Kept sequential rather than fanned-out/parallel: the two scanner nodes
are independent and *could* run concurrently, but sequential execution
keeps the state updates simple and deterministic for now, and file-level
scans are cheap (no network calls unless ANTHROPIC_API_KEY / LLM review
is enabled). Revisit if latency becomes a real constraint once wired to
the GitHub webhook (Day 5) with realistically-sized PRs.
"""
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from app.agents.performance_analyzer import PerformanceAnalyzerAgent
from app.agents.report_generator import ReportGeneratorAgent
from app.agents.security_scanner import SecurityScannerAgent
from app.logger.json_logger import get_logger
from app.models.schemas import ScanReport, ScanRequest

logger = get_logger(__name__)


class ReviewState(TypedDict):
    """State threaded through the graph. `files` is the only required input."""

    files: dict[str, str]
    security_report: ScanReport | None
    performance_report: ScanReport | None
    markdown_report: str | None


def build_review_graph(enable_llm_review: bool | None = None):
    """Construct and compile the code-review graph. Returns a runnable graph."""
    security_agent = SecurityScannerAgent(enable_llm_review=enable_llm_review)
    performance_agent = PerformanceAnalyzerAgent()
    report_agent = ReportGeneratorAgent()

    def security_scan(state: ReviewState) -> dict:
        logger.info("Running security_scan node on %d file(s)", len(state["files"]))
        report = security_agent.scan(ScanRequest(files=state["files"]))
        return {"security_report": report}

    def performance_scan(state: ReviewState) -> dict:
        logger.info("Running performance_scan node on %d file(s)", len(state["files"]))
        report = performance_agent.scan(ScanRequest(files=state["files"]))
        return {"performance_report": report}

    def generate_report(state: ReviewState) -> dict:
        logger.info("Running generate_report node")
        markdown = report_agent.generate({
            "Security Scanner": state["security_report"],
            "Performance Analyzer": state["performance_report"],
        })
        return {"markdown_report": markdown}

    graph = StateGraph(ReviewState)
    graph.add_node("security_scan", security_scan)
    graph.add_node("performance_scan", performance_scan)
    graph.add_node("generate_report", generate_report)

    graph.add_edge(START, "security_scan")
    graph.add_edge("security_scan", "performance_scan")
    graph.add_edge("performance_scan", "generate_report")
    graph.add_edge("generate_report", END)

    return graph.compile()


def run_review(files: dict[str, str], enable_llm_review: bool | None = None) -> ReviewState:
    """Convenience entry point: build the graph, run it once, return the final state."""
    graph = build_review_graph(enable_llm_review=enable_llm_review)
    initial_state: ReviewState = {
        "files": files,
        "security_report": None,
        "performance_report": None,
        "markdown_report": None,
    }
    return graph.invoke(initial_state)
