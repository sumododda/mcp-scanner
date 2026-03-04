import uuid

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from mcp_scanner.database import get_session
from mcp_scanner.models.scan import Scan
from mcp_scanner.services.pdf_report import PDFReportGenerator

router = APIRouter(prefix="/api")


@router.get("/scan/{scan_id}/pdf")
async def download_pdf(scan_id: str, session: AsyncSession = Depends(get_session)):
    try:
        scan_uuid = uuid.UUID(scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan ID format")

    stmt = (
        select(Scan)
        .where(Scan.id == scan_uuid)
        .options(selectinload(Scan.findings))
    )
    result = await session.execute(stmt)
    scan = result.scalar_one_or_none()

    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan_data = {
        "score": scan.overall_score or 0,
        "grade": scan.grade or "N/A",
        "findings": [
            {
                "checker": f.checker,
                "severity": f.severity.value,
                "title": f.title,
                "description": f.description,
                "evidence": f.evidence,
                "location": f.location,
                "remediation": f.remediation,
                "cwe_id": f.cwe_id,
                "llm_analysis": f.llm_analysis,
                "source_file": f.source_file,
                "source_line": f.source_line,
                "dismissed_as": f.dismissed_as,
                "dismissed_reason": f.dismissed_reason,
            }
            for f in scan.findings
        ],
        "summary": scan.summary or {"total": 0, "by_severity": {}, "by_checker": {}},
    }

    gen = PDFReportGenerator()
    pdf_bytes = gen.generate(scan_data)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=mcp-scan-{scan_id}.pdf"},
    )
