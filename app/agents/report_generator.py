"""
Report Generator agent.

Combines one or more ScanReport objects (Security, Performance, ...) into a
single structured Markdown review report suitable for posting as a PR comment.
"""
from datetime import datetime, timezone

from app.models.schemas import ScanReport, Severity

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
_SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class ReportGeneratorAgent:
    """Combines agent scan reports into one Markdown document."""

    name = "report_generator"

    def generate(self, reports: dict[str, ScanReport]) -> str:
        """
        reports: mapping of section title -> ScanReport, e.g.
            {"Security Scanner": security_report, "Performance Analyzer": perf_report}
        """
        total_findings = sum(r.total_findings for r in reports.values())
        lines = [
            "# AI Code Review Report",
            "",
            f"_Generated {datetime.now(timezone.utc).isoformat()}_",
            "",
            self._summary_table(reports),
            "",
        ]

        if total_findings == 0:
            lines.append("No issues found. ✅")
            return "\n".join(lines)

        for section_title, report in reports.items():
            if report.total_findings == 0:
                continue
            lines.append(f"## {section_title}")
            lines.append("")
            for file_result in report.results:
                if not file_result.has_findings:
                    continue
                lines.append(f"### `{file_result.file_path}`")
                lines.append("")
                sorted_findings = sorted(
                    file_result.findings,
                    key=lambda f: _SEVERITY_ORDER.index(f.severity),
                )
                for finding in sorted_findings:
                    emoji = _SEVERITY_EMOJI.get(finding.severity, "")
                    location = f"L{finding.line_number}" if finding.line_number else "—"
                    lines.append(
                        f"- {emoji} **{finding.severity.value}** [{location}] "
                        f"`{finding.rule_id}` — {finding.message}"
                    )
                    if finding.snippet:
                        lines.append(f"  ```\n  {finding.snippet}\n  ```")
                lines.append("")

        return "\n".join(lines)

    def _summary_table(self, reports: dict[str, ScanReport]) -> str:
        header = "| Category | Critical | High | Medium | Low | Info | Total |"
        divider = "|---|---|---|---|---|---|---|"
        rows = [header, divider]
        for section_title, report in reports.items():
            counts = report.findings_by_severity
            row = "| " + " | ".join([
                section_title,
                str(counts.get("CRITICAL", 0)),
                str(counts.get("HIGH", 0)),
                str(counts.get("MEDIUM", 0)),
                str(counts.get("LOW", 0)),
                str(counts.get("INFO", 0)),
                str(report.total_findings),
            ]) + " |"
            rows.append(row)
        return "\n".join(rows)
