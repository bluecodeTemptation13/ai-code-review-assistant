"""Tests for the Report Generator agent."""
from app.agents.report_generator import ReportGeneratorAgent
from app.models.schemas import FileScanResult, Finding, ScanReport, Severity


def make_finding(rule_id, category, severity, file_path="a.py", line=1, message="issue"):
    return Finding(
        rule_id=rule_id, category=category, severity=severity,
        file_path=file_path, line_number=line, message=message,
    )


def test_no_findings_reports_clean():
    report = ScanReport(results=[FileScanResult(file_path="a.py", findings=[], lines_scanned=10)])
    markdown = ReportGeneratorAgent().generate({"Security Scanner": report})
    assert "No issues found" in markdown


def test_includes_file_path_and_rule_id():
    finding = make_finding("SEC-HARDCODED-SECRET", "hardcoded_secret", Severity.CRITICAL, "config.py", 3)
    report = ScanReport(results=[FileScanResult(file_path="config.py", findings=[finding], lines_scanned=5)])
    markdown = ReportGeneratorAgent().generate({"Security Scanner": report})
    assert "config.py" in markdown
    assert "SEC-HARDCODED-SECRET" in markdown
    assert "CRITICAL" in markdown


def test_summary_table_counts_by_severity():
    findings = [
        make_finding("R1", "cat1", Severity.CRITICAL),
        make_finding("R2", "cat2", Severity.HIGH),
        make_finding("R3", "cat3", Severity.HIGH),
    ]
    report = ScanReport(results=[FileScanResult(file_path="a.py", findings=findings, lines_scanned=5)])
    markdown = ReportGeneratorAgent().generate({"Security Scanner": report})
    # summary row: Security Scanner | 1 | 2 | 0 | 0 | 0 | 3
    assert "| Security Scanner | 1 | 2 | 0 | 0 | 0 | 3 |" in markdown


def test_multiple_sections_combined():
    sec_report = ScanReport(results=[
        FileScanResult(file_path="a.py", findings=[make_finding("R1", "cat1", Severity.HIGH)], lines_scanned=5)
    ])
    perf_report = ScanReport(results=[
        FileScanResult(file_path="b.py", findings=[make_finding("R2", "cat2", Severity.LOW)], lines_scanned=5)
    ])
    markdown = ReportGeneratorAgent().generate(
        {"Security Scanner": sec_report, "Performance Analyzer": perf_report}
    )
    assert "## Security Scanner" in markdown
    assert "## Performance Analyzer" in markdown


def test_findings_sorted_by_severity_within_file():
    findings = [
        make_finding("R-LOW", "cat", Severity.LOW, line=1),
        make_finding("R-CRIT", "cat", Severity.CRITICAL, line=2),
    ]
    report = ScanReport(results=[FileScanResult(file_path="a.py", findings=findings, lines_scanned=5)])
    markdown = ReportGeneratorAgent().generate({"Security Scanner": report})
    assert markdown.index("R-CRIT") < markdown.index("R-LOW")
