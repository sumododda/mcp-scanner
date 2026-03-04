from abc import ABC, abstractmethod
import re
from dataclasses import dataclass, field
from enum import Enum

from mcp_scanner.models.scan_context import ScanContext

# Test directory/file patterns to skip during source scanning
_TEST_DIR_SEGMENTS = {"test", "tests", "__tests__", "spec", "specs", "testing", "testdata", "test_data", "fixtures"}
_TEST_FILE_RE = re.compile(
    r"(?:^|/)"
    r"(?:"
    r"test_[^/]*"               # test_*.py
    r"|[^/]*_test\.[^/]+"      # *_test.go, *_test.py
    r"|[^/]*\.(?:test|spec)\.[^/]+"  # *.test.ts, *.spec.js
    r"|[^/]*Tests?\.[^/]+"     # FooTest.java, FooTests.cs
    r")$"
)


def is_test_path(file_path: str) -> bool:
    """Return True if the file path is inside a test directory or is a test file."""
    parts = file_path.replace("\\", "/").lower().split("/")
    if any(p in _TEST_DIR_SEGMENTS for p in parts):
        return True
    return bool(_TEST_FILE_RE.search(file_path.lower()))


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def weight(self) -> int:
        return {"critical": 25, "high": 15, "medium": 5, "low": 1}[self.value]


@dataclass
class FindingData:
    checker: str
    severity: Severity
    title: str
    description: str
    evidence: str
    location: str
    remediation: str = ""
    cwe_id: str | None = None
    llm_analysis: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    compliance_refs: list = field(default_factory=list)


@dataclass
class SecurityQuestion:
    id: str
    question: str
    answer: str
    status: str  # "clear" | "issue" | "skipped"
    items_checked: int
    items_checked_label: str
    finding_ids: list[str] = field(default_factory=list)
    severity: str | None = None
    detail: str | None = None


@dataclass
class CheckerResult:
    findings: list[FindingData] = field(default_factory=list)
    checker_name: str = ""
    sbom_entries: list[dict] = field(default_factory=list)
    security_questions: list[SecurityQuestion] = field(default_factory=list)


_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


def deduplicate_findings(
    findings: list[FindingData], max_per_location: int = 10
) -> list[FindingData]:
    """Consolidate overlapping findings by (checker, location, cwe_id)."""
    if not findings:
        return []

    groups: dict[tuple[str, str, str | None], list[FindingData]] = {}
    for f in findings:
        loc_base = f.location.removesuffix(":normalized")
        key = (f.checker, loc_base, f.cwe_id)
        groups.setdefault(key, []).append(f)

    deduped: list[FindingData] = []
    for group in groups.values():
        group.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        best = group[0]
        if len(group) > 1:
            extra = [f.evidence for f in group[1:] if f.evidence != best.evidence]
            if extra:
                merged = best.evidence + " | Additional: " + "; ".join(extra[:3])
                best = FindingData(
                    checker=best.checker, severity=best.severity, title=best.title,
                    description=best.description, evidence=merged, location=best.location,
                    remediation=best.remediation, cwe_id=best.cwe_id,
                    llm_analysis=best.llm_analysis, source_file=best.source_file,
                    source_line=best.source_line,
                    compliance_refs=best.compliance_refs,
                )
        deduped.append(best)

    deduped.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    loc_counts: dict[str, int] = {}
    capped: list[FindingData] = []
    for f in deduped:
        loc_base = f.location.removesuffix(":normalized")
        loc_counts[loc_base] = loc_counts.get(loc_base, 0) + 1
        if loc_counts[loc_base] <= max_per_location:
            capped.append(f)

    return capped


def deduplicate_across_tiers(
    findings: list[FindingData], max_per_location: int = 10
) -> list[FindingData]:
    """Merge findings from different checkers that flag the same tool for the same issue.

    Groups by (tool_location_prefix, cwe_id) — ignoring checker name — so that
    overlapping detections from e.g. tool_poisoning and data_exfiltration are
    collapsed into a single, higher-confidence finding.
    """
    if not findings:
        return []

    groups: dict[tuple[str, str | None], list[FindingData]] = {}
    for f in findings:
        tool_prefix = f.location.split(":")[0]
        key = (tool_prefix, f.cwe_id)
        groups.setdefault(key, []).append(f)

    deduped: list[FindingData] = []
    for group in groups.values():
        group.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))
        best = group[0]

        if len(group) > 1:
            # Collect evidence from other findings in the group
            other_evidence = [
                f.evidence for f in group[1:] if f.evidence != best.evidence
            ]
            merged_evidence = best.evidence
            if other_evidence:
                merged_evidence += " | Corroborated: " + "; ".join(other_evidence[:3])

            # Build confirmation note from contributing checkers
            other_checkers = sorted(
                {f.checker for f in group if f.checker != best.checker}
            )
            confirmed_note = ""
            if other_checkers:
                all_checkers = sorted({f.checker for f in group})
                confirmed_note = f" (confirmed by {', '.join(all_checkers)})"

            merged_description = best.description + confirmed_note

            # Merge LLM analyses from all findings
            llm_parts = [
                f.llm_analysis for f in group if f.llm_analysis
            ]
            merged_llm = " | ".join(llm_parts) if llm_parts else best.llm_analysis

            best = FindingData(
                checker=best.checker,
                severity=best.severity,
                title=best.title,
                description=merged_description,
                evidence=merged_evidence,
                location=best.location,
                remediation=best.remediation,
                cwe_id=best.cwe_id,
                llm_analysis=merged_llm,
                source_file=best.source_file,
                source_line=best.source_line,
                compliance_refs=best.compliance_refs,
            )

        deduped.append(best)

    deduped.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 99))

    # Cap findings per tool location
    loc_counts: dict[str, int] = {}
    capped: list[FindingData] = []
    for f in deduped:
        tool_prefix = f.location.split(":")[0]
        loc_counts[tool_prefix] = loc_counts.get(tool_prefix, 0) + 1
        if loc_counts[tool_prefix] <= max_per_location:
            capped.append(f)

    return capped


class BaseChecker(ABC):
    name: str
    description: str

    @abstractmethod
    async def check(self, context: ScanContext) -> CheckerResult:
        ...
