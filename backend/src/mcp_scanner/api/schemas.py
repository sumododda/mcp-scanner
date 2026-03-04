import ipaddress
import socket
import uuid
from datetime import datetime
from urllib.parse import urlparse

from pydantic import BaseModel, field_validator

_BLOCKED_NETWORKS_V4 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("169.254.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
]

_BLOCKED_NETWORKS_V6 = [
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("fc00::/7"),
]


def validate_repo_url(url: str) -> str:
    """Validate a repository URL is safe to clone.

    Enforces https-only scheme and blocks private/reserved IPs
    after DNS resolution to prevent SSRF.
    """
    if url.startswith("ext::"):
        raise ValueError("ext:: transport is not allowed")

    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError(f"Only https:// URLs are allowed, got {parsed.scheme}://")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("URL must include a hostname")

    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise ValueError(f"Could not resolve hostname: {hostname}")

    for family, _, _, _, sockaddr in addrinfo:
        ip_str = sockaddr[0]
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            continue

        if isinstance(addr, ipaddress.IPv4Address):
            for net in _BLOCKED_NETWORKS_V4:
                if addr in net:
                    raise ValueError("URL resolves to private/reserved IP address")
        elif isinstance(addr, ipaddress.IPv6Address):
            for net in _BLOCKED_NETWORKS_V6:
                if addr in net:
                    raise ValueError("URL resolves to private/reserved IP address")

    return url


class ScanRequest(BaseModel):
    repo_url: str
    llm_judge_enabled: bool | None = None

    @field_validator("repo_url")
    @classmethod
    def check_repo_url(cls, v: str) -> str:
        return validate_repo_url(v)


class FindingResponse(BaseModel):
    id: uuid.UUID
    checker: str
    severity: str
    title: str
    description: str
    evidence: str
    location: str
    remediation: str
    cwe_id: str | None = None
    llm_analysis: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    dismissed_as: str | None = None
    dismissed_reason: str | None = None


class DismissFindingRequest(BaseModel):
    dismissed_as: str
    reason: str


class SecurityQuestionResponse(BaseModel):
    id: str
    question: str
    answer: str
    status: str
    items_checked: int
    items_checked_label: str
    finding_ids: list[str] = []
    severity: str | None = None
    detail: str | None = None


class CheckerDetailResponse(BaseModel):
    id: str
    description: str
    status: str
    items_checked: int
    findings_count: int
    checks: list[str] = []
    error: str | None = None
    security_questions: list[SecurityQuestionResponse] = []


class ScanSummary(BaseModel):
    total: int
    by_severity: dict[str, int]
    by_checker: dict[str, int]
    checker_details: list[CheckerDetailResponse] = []


class ToolSnapshotResponse(BaseModel):
    server_name: str
    tool_name: str
    description: str = ""
    parameters: list[dict] = []
    parameter_count: int = 0


class PromptArgumentResponse(BaseModel):
    name: str
    description: str = ""
    required: bool = False


class PromptResponse(BaseModel):
    name: str
    title: str | None = None
    description: str = ""
    arguments: list[PromptArgumentResponse] = []
    argument_count: int = 0


class ResourceResponse(BaseModel):
    name: str
    title: str | None = None
    uri: str = ""
    description: str = ""
    mime_type: str | None = None
    size: int | None = None


class ServerOverview(BaseModel):
    name: str
    tools: list[ToolSnapshotResponse] = []
    tool_count: int = 0
    prompts: list[PromptResponse] = []
    prompt_count: int = 0
    resources: list[ResourceResponse] = []
    resource_count: int = 0


class CodeGraphStats(BaseModel):
    total_functions: int = 0
    total_imports: int = 0
    total_call_sites: int = 0
    tool_handlers: int = 0
    dangerous_calls: int = 0
    network_calls: int = 0
    file_access_calls: int = 0


class ScanResponse(BaseModel):
    id: uuid.UUID
    status: str
    created_at: datetime
    overall_score: int | None = None
    grade: str | None = None
    repo_url: str | None = None
    commit_hash: str | None = None
    summary: ScanSummary | None = None
    findings: list[FindingResponse] = []
    error_message: str | None = None
    servers: list[ServerOverview] = []
    code_graph: dict | None = None


class ScanListItem(BaseModel):
    id: uuid.UUID
    status: str
    created_at: datetime
    overall_score: int | None = None
    grade: str | None = None
    repo_url: str | None = None
    commit_hash: str | None = None
    summary: ScanSummary | None = None


class PaginatedScans(BaseModel):
    scans: list[ScanListItem]
    total: int
    page: int
    per_page: int


class SettingsResponse(BaseModel):
    openrouter_api_key: str  # masked
    openrouter_model: str
    llm_judge_enabled: bool


class SettingsUpdate(BaseModel):
    openrouter_api_key: str | None = None
    openrouter_model: str | None = None
    llm_judge_enabled: bool | None = None


class TriageChatMessage(BaseModel):
    role: str
    content: str


class TriageChatRequest(BaseModel):
    message: str
    history: list[TriageChatMessage] = []


class SbomVulnerability(BaseModel):
    id: str
    summary: str = ""
    aliases: list[str] = []
    purl: str = ""
    fixed_version: str | None = None


class SbomResponse(BaseModel):
    id: str
    scan_id: str
    server_name: str
    package_name: str
    package_version: str
    format: str
    sbom_data: dict
    dependency_count: int | None = 0
    vulnerability_count: int | None = 0
    vulnerabilities: list[SbomVulnerability] = []


class VulnerabilityResponse(BaseModel):
    id: str
    package_name: str
    package_version: str
    severity: str = ""
    cvss_score: float | None = None
    summary: str = ""
    fixed_version: str | None = None
    purl: str = ""
    aliases: list[str] = []


class VulnerabilitySummary(BaseModel):
    total: int
    by_severity: dict[str, int] = {}
    vulnerabilities: list[VulnerabilityResponse] = []
