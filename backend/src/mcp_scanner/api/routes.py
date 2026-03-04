import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from mcp_scanner.api.schemas import (
    DismissFindingRequest,
    FindingResponse,
    PaginatedScans,
    PromptArgumentResponse,
    PromptResponse,
    ResourceResponse,
    SbomResponse,
    SbomVulnerability,
    ScanListItem,
    ScanResponse,
    ScanRequest,
    ScanSummary,
    ServerOverview,
    SettingsResponse,
    SettingsUpdate,
    ToolSnapshotResponse,
    TriageChatRequest,
    VulnerabilityResponse,
    VulnerabilitySummary,
)
from mcp_scanner.config import settings
from mcp_scanner.database import get_session
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.sbom import Sbom
from mcp_scanner.models.scan import Scan
from mcp_scanner.services.orchestrator import ScanOrchestrator
from mcp_scanner.services.code_graph_chat import stream_code_graph_chat
from mcp_scanner.services.triage import stream_triage_chat

router = APIRouter(prefix="/api")


@router.post("/scan")
async def start_scan(
    request: Request,
    session: AsyncSession = Depends(get_session),
):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    try:
        scan_req = ScanRequest(**body)
    except Exception:
        raise HTTPException(status_code=422, detail="repo_url is required")
    repo_url = scan_req.repo_url

    # Per-scan LLM judge override
    original_llm_enabled = settings.llm_judge_enabled
    if scan_req.llm_judge_enabled is not None:
        settings.llm_judge_enabled = scan_req.llm_judge_enabled

    orchestrator = ScanOrchestrator()
    try:
        result = await orchestrator.run_scan(repo_url=repo_url, session=session)
    finally:
        settings.llm_judge_enabled = original_llm_enabled

    findings = [
        FindingResponse(
            id=uuid.uuid4(),
            checker=f.checker,
            severity=f.severity.value,
            title=f.title,
            description=f.description,
            evidence=f.evidence,
            location=f.location,
            remediation=f.remediation,
            cwe_id=f.cwe_id,
            llm_analysis=f.llm_analysis,
            source_file=f.source_file,
            source_line=f.source_line,
        )
        for f in result["findings"]
    ]

    return ScanResponse(
        id=uuid.UUID(result["scan_id"]),
        status="completed",
        created_at=datetime.now(timezone.utc),
        overall_score=result["score"],
        grade=result["grade"],
        summary=ScanSummary(**result["summary"]),
        findings=findings,
    )


@router.get("/scan/{scan_id}")
async def get_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    stmt = (
        select(Scan)
        .where(Scan.id == scan_uuid)
        .options(selectinload(Scan.findings), selectinload(Scan.tool_snapshots))
    )
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = [_finding_to_response(f) for f in scan.findings]

    summary = ScanSummary(**scan.summary) if scan.summary else None

    # Build server overview from tool snapshots
    servers_map: dict[str, list[ToolSnapshotResponse]] = {}
    for ts in scan.tool_snapshots:
        defn = ts.full_definition or {}
        schema = defn.get("input_schema", {})
        props = schema.get("properties", {})
        required = set(schema.get("required", []))
        params = [
            {
                "name": name,
                "type": info.get("type", "any"),
                "description": info.get("description", ""),
                "required": name in required,
            }
            for name, info in props.items()
        ]
        tool = ToolSnapshotResponse(
            server_name=ts.server_name,
            tool_name=ts.tool_name,
            description=defn.get("description", ""),
            parameters=params,
            parameter_count=len(params),
        )
        servers_map.setdefault(ts.server_name, []).append(tool)

    # Build prompts and resources from server_metadata JSONB
    metadata = scan.server_metadata or {}
    prompts_map: dict[str, list[PromptResponse]] = {}
    resources_map: dict[str, list[ResourceResponse]] = {}
    for srv_name, srv_meta in metadata.items():
        prompts_map[srv_name] = [
            PromptResponse(
                name=p["name"],
                title=p.get("title"),
                description=p.get("description") or "",
                arguments=[
                    PromptArgumentResponse(**a) for a in p.get("arguments", [])
                ],
                argument_count=len(p.get("arguments", [])),
            )
            for p in srv_meta.get("prompts", [])
        ]
        resources_map[srv_name] = [
            ResourceResponse(
                name=r["name"],
                title=r.get("title"),
                uri=r.get("uri", ""),
                description=r.get("description") or "",
                mime_type=r.get("mime_type"),
                size=r.get("size"),
            )
            for r in srv_meta.get("resources", [])
        ]

    # Merge all server names from tools and metadata
    all_server_names = set(servers_map.keys()) | set(metadata.keys())
    servers = [
        ServerOverview(
            name=name,
            tools=servers_map.get(name, []),
            tool_count=len(servers_map.get(name, [])),
            prompts=prompts_map.get(name, []),
            prompt_count=len(prompts_map.get(name, [])),
            resources=resources_map.get(name, []),
            resource_count=len(resources_map.get(name, [])),
        )
        for name in sorted(all_server_names)
    ]

    return ScanResponse(
        id=scan.id,
        status=scan.status.value,
        created_at=scan.created_at,
        overall_score=scan.overall_score,
        grade=scan.grade,
        repo_url=scan.repo_url,
        commit_hash=scan.commit_hash,
        summary=summary,
        findings=findings,
        error_message=scan.error_message,
        servers=servers,
        code_graph=scan.code_graph,
    )


@router.get("/history")
async def list_scans(
    page: int = 1,
    per_page: int = 20,
    session: AsyncSession = Depends(get_session),
):
    count_stmt = select(func.count()).select_from(Scan)
    count_result = await session.execute(count_stmt)
    total = count_result.scalar_one()

    offset = (page - 1) * per_page
    stmt = select(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(per_page)
    result = await session.execute(stmt)
    scans = result.scalars().all()

    items = [
        ScanListItem(
            id=s.id,
            status=s.status.value,
            created_at=s.created_at,
            overall_score=s.overall_score,
            grade=s.grade,
            repo_url=s.repo_url,
            commit_hash=s.commit_hash,
            summary=ScanSummary(**s.summary) if s.summary else None,
        )
        for s in scans
    ]

    return PaginatedScans(scans=items, total=total, page=page, per_page=per_page)


@router.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str, session: AsyncSession = Depends(get_session)):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    stmt = select(Scan).where(Scan.id == scan_uuid)
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    await session.delete(scan)
    await session.commit()
    return {"deleted": True}


@router.get("/scan/{scan_id}/sbom", response_model=list[SbomResponse])
async def get_scan_sbom(scan_id: str, session: AsyncSession = Depends(get_session)):
    """Get SBOM entries for a scan."""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    stmt = select(Sbom).where(Sbom.scan_id == scan_uuid)
    result = await session.execute(stmt)
    sboms = list(result.scalars().all())

    return [
        SbomResponse(
            id=str(s.id),
            scan_id=str(s.scan_id),
            server_name=s.server_name,
            package_name=s.package_name,
            package_version=s.package_version,
            format=s.format,
            sbom_data=s.sbom_data,
            dependency_count=s.dependency_count,
            vulnerability_count=s.vulnerability_count,
            vulnerabilities=[
                SbomVulnerability(
                    id=v.get("id", ""),
                    summary=v.get("summary", ""),
                    aliases=v.get("aliases", []),
                    purl=v.get("purl", ""),
                    fixed_version=v.get("fixed_version"),
                )
                for v in (s.vulnerabilities or [])
            ],
        )
        for s in sboms
    ]


@router.get("/scan/{scan_id}/sbom/export")
async def export_scan_sbom(
    scan_id: str,
    format: str = "cyclonedx-json",
    session: AsyncSession = Depends(get_session),
):
    """Export merged SBOM for a scan in various formats."""
    from mcp_scanner.services.sbom_generator import SbomGenerator, SbomResult

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    stmt = select(Sbom).where(Sbom.scan_id == scan_uuid)
    result = await session.execute(stmt)
    sboms = list(result.scalars().all())

    if not sboms:
        raise HTTPException(status_code=404, detail="No SBOM data found for this scan")

    # Merge all SBOM components into a single BOM
    all_components: list[dict] = []
    all_dependencies: list[dict] = []
    main_name = sboms[0].package_name
    main_version = sboms[0].package_version

    for s in sboms:
        bom_data = s.sbom_data or {}
        all_components.extend(bom_data.get("components", []))
        all_dependencies.extend(bom_data.get("dependencies", []))

    merged_bom = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": sboms[0].sbom_data.get("metadata", {}).get("timestamp", ""),
            "tools": {
                "components": [
                    {"type": "application", "name": "mcp-scanner", "version": "1.0.0"}
                ]
            },
            "component": {
                "type": "application",
                "name": main_name,
                "version": main_version,
            },
        },
        "components": all_components,
        "dependencies": all_dependencies,
    }

    merged_result = SbomResult(
        bom_json=merged_bom,
        component_count=len(all_components),
        main_name=main_name,
        main_version=main_version,
    )

    generator = SbomGenerator()
    try:
        exported = generator.export(merged_result, format)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        await generator.close()

    content_type = "application/json"
    if format == "cyclonedx-xml":
        content_type = "application/xml"

    from fastapi.responses import Response

    return Response(content=exported, media_type=content_type)


@router.get("/scan/{scan_id}/sbom/vulnerabilities", response_model=VulnerabilitySummary)
async def get_scan_vulnerabilities(
    scan_id: str,
    session: AsyncSession = Depends(get_session),
):
    """Get vulnerability summary from SBOM data for a scan."""
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    stmt = select(Sbom).where(Sbom.scan_id == scan_uuid)
    result = await session.execute(stmt)
    sboms = list(result.scalars().all())

    if not sboms:
        raise HTTPException(status_code=404, detail="No SBOM data found for this scan")

    all_vulns: list[VulnerabilityResponse] = []
    severity_counts: dict[str, int] = {}

    for s in sboms:
        vuln_list = s.vulnerabilities or []
        for v in vuln_list:
            # Determine severity from CVSS score or default
            severity = "medium"
            cvss = v.get("cvss_score")
            if cvss is not None:
                if cvss >= 9.0:
                    severity = "critical"
                elif cvss >= 7.0:
                    severity = "high"
                elif cvss >= 4.0:
                    severity = "medium"
                else:
                    severity = "low"

            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            all_vulns.append(VulnerabilityResponse(
                id=v.get("id", ""),
                package_name=s.package_name,
                package_version=s.package_version,
                severity=severity,
                cvss_score=cvss,
                summary=v.get("summary", ""),
                fixed_version=v.get("fixed_version"),
                purl=v.get("purl", ""),
                aliases=v.get("aliases", []),
            ))

    return VulnerabilitySummary(
        total=len(all_vulns),
        by_severity=severity_counts,
        vulnerabilities=all_vulns,
    )


@router.post("/finding/{finding_id}/triage")
async def triage_finding(
    finding_id: str,
    body: TriageChatRequest,
    session: AsyncSession = Depends(get_session),
):
    if not settings.openrouter_api_key:
        raise HTTPException(status_code=503, detail="OpenRouter API key not configured")

    try:
        finding_uuid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding ID format")

    stmt = (
        select(Finding)
        .where(Finding.id == finding_uuid)
        .options(
            selectinload(Finding.scan).selectinload(Scan.tool_snapshots)
        )
    )
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Build finding dict
    finding_dict = {
        "checker": finding.checker,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "evidence": finding.evidence,
        "location": finding.location,
        "cwe_id": finding.cwe_id,
    }

    # Find matching tool definition from location (format: "server/tool:description" or "server/tool")
    tool_definition = None
    if finding.scan and finding.scan.tool_snapshots:
        location = finding.location or ""
        # Parse server_name/tool_name from location
        loc_base = location.split(":")[0] if ":" in location else location
        parts = loc_base.split("/", 1)
        if len(parts) == 2:
            server_name, tool_name = parts
            for ts in finding.scan.tool_snapshots:
                if ts.server_name == server_name and ts.tool_name == tool_name:
                    tool_definition = ts.full_definition
                    break

    history = [{"role": m.role, "content": m.content} for m in body.history]

    return StreamingResponse(
        stream_triage_chat(finding_dict, tool_definition, body.message, history),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/scan/{scan_id}/graph/chat")
async def code_graph_chat(
    scan_id: str,
    body: TriageChatRequest,
    session: AsyncSession = Depends(get_session),
):
    if not settings.openrouter_api_key:
        raise HTTPException(status_code=503, detail="OpenRouter API key not configured")

    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    stmt = select(Scan).where(Scan.id == scan_uuid)
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.code_graph:
        raise HTTPException(status_code=404, detail="No code graph available for this scan")

    history = [{"role": m.role, "content": m.content} for m in body.history]

    return StreamingResponse(
        stream_code_graph_chat(scan.code_graph, body.message, history),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


VALID_DISMISS_STATUSES = {"false_positive", "accepted_risk", "mitigated"}


def _finding_to_response(f: Finding) -> FindingResponse:
    return FindingResponse(
        id=f.id,
        checker=f.checker,
        severity=f.severity.value,
        title=f.title,
        description=f.description,
        evidence=f.evidence,
        location=f.location,
        remediation=f.remediation,
        cwe_id=f.cwe_id,
        llm_analysis=f.llm_analysis,
        source_file=f.source_file,
        source_line=f.source_line,
        dismissed_as=f.dismissed_as,
        dismissed_reason=f.dismissed_reason,
    )


async def _recalculate_scan_summary(scan: Scan, session: AsyncSession) -> None:
    """Recalculate scan summary counts, score, and grade from non-dismissed findings."""
    stmt = select(Finding).where(
        Finding.scan_id == scan.id,
        Finding.dismissed_as.is_(None),
    )
    result = await session.execute(stmt)
    active_findings = result.scalars().all()

    by_severity: dict[str, int] = {}
    by_checker: dict[str, int] = {}
    for f in active_findings:
        sev = f.severity.value
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_checker[f.checker] = by_checker.get(f.checker, 0) + 1

    scan.summary = {
        "total": len(active_findings),
        "by_severity": by_severity,
        "by_checker": by_checker,
        **({"checker_details": scan.summary["checker_details"]} if scan.summary and "checker_details" in scan.summary else {}),
    }

    # Recalculate score and grade from active findings
    score = 100
    for f in active_findings:
        score -= f.severity.weight
    score = max(0, score)

    scan.overall_score = score
    if score >= 90:
        scan.grade = "A"
    elif score >= 70:
        scan.grade = "B"
    elif score >= 50:
        scan.grade = "C"
    elif score >= 30:
        scan.grade = "D"
    else:
        scan.grade = "F"


@router.patch("/finding/{finding_id}/dismiss")
async def dismiss_finding(
    finding_id: str,
    body: DismissFindingRequest,
    session: AsyncSession = Depends(get_session),
):
    if body.dismissed_as not in VALID_DISMISS_STATUSES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid dismissed_as value. Must be one of: {', '.join(sorted(VALID_DISMISS_STATUSES))}",
        )

    try:
        finding_uuid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding ID format")

    stmt = select(Finding).where(Finding.id == finding_uuid)
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.dismissed_as = body.dismissed_as
    finding.dismissed_reason = body.reason

    # Recalculate scan summary
    scan_stmt = select(Scan).where(Scan.id == finding.scan_id)
    scan_result = await session.execute(scan_stmt)
    scan = scan_result.scalar_one_or_none()
    if scan:
        await _recalculate_scan_summary(scan, session)

    await session.commit()
    await session.refresh(finding)

    return _finding_to_response(finding)


@router.delete("/finding/{finding_id}/dismiss")
async def restore_finding(
    finding_id: str,
    session: AsyncSession = Depends(get_session),
):
    try:
        finding_uuid = uuid.UUID(finding_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid finding ID format")

    stmt = select(Finding).where(Finding.id == finding_uuid)
    result = await session.execute(stmt)
    finding = result.scalar_one_or_none()

    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.dismissed_as = None
    finding.dismissed_reason = None

    # Recalculate scan summary
    scan_stmt = select(Scan).where(Scan.id == finding.scan_id)
    scan_result = await session.execute(scan_stmt)
    scan = scan_result.scalar_one_or_none()
    if scan:
        await _recalculate_scan_summary(scan, session)

    await session.commit()
    await session.refresh(finding)

    return _finding_to_response(finding)


def _mask_api_key(key: str) -> str:
    if not key:
        return ""
    if len(key) > 8:
        return f"{key[:4]}...{key[-4:]}"
    return "***"


@router.get("/settings")
async def get_settings():
    return SettingsResponse(
        openrouter_api_key=_mask_api_key(settings.openrouter_api_key),
        openrouter_model=settings.openrouter_model,
        llm_judge_enabled=settings.llm_judge_enabled,
    )


@router.put("/settings")
async def update_settings(body: SettingsUpdate):
    if body.openrouter_api_key is not None:
        settings.openrouter_api_key = body.openrouter_api_key
    if body.openrouter_model is not None:
        settings.openrouter_model = body.openrouter_model
    if body.llm_judge_enabled is not None:
        settings.llm_judge_enabled = body.llm_judge_enabled

    return SettingsResponse(
        openrouter_api_key=_mask_api_key(settings.openrouter_api_key),
        openrouter_model=settings.openrouter_model,
        llm_judge_enabled=settings.llm_judge_enabled,
    )
