"""
Data models for the Security Scanner agent.
"""
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingSource(str, Enum):
    STATIC_RULE = "STATIC_RULE"
    LLM_REVIEW = "LLM_REVIEW"


class Finding(BaseModel):
    """A single issue detected in a source file."""

    rule_id: str = Field(..., description="Stable identifier for the detection rule")
    category: str = Field(..., description="e.g. hardcoded_secret, sql_injection, input_validation")
    severity: Severity
    file_path: str
    line_number: int | None = None
    message: str
    snippet: str | None = None
    source: FindingSource = FindingSource.STATIC_RULE


class FileScanResult(BaseModel):
    """Result of scanning a single file."""

    file_path: str
    findings: list[Finding] = Field(default_factory=list)
    lines_scanned: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0


class ScanRequest(BaseModel):
    """Input payload for a scan job (one or more files)."""

    files: dict[str, str] = Field(
        ..., description="Mapping of file_path -> file content to scan"
    )


class ScanReport(BaseModel):
    """Aggregate result across all files in a scan request."""

    results: list[FileScanResult] = Field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.results)

    @property
    def findings_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for result in self.results:
            for finding in result.findings:
                counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
        return counts
