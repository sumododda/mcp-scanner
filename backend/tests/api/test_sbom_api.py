import uuid
import pytest

from mcp_scanner.api.schemas import SbomResponse


def test_sbom_response_schema():
    """SbomResponse schema has required fields."""
    data = SbomResponse(
        id=str(uuid.uuid4()),
        scan_id=str(uuid.uuid4()),
        server_name="srv",
        package_name="pkg",
        package_version="1.0.0",
        format="cyclonedx",
        sbom_data={"bomFormat": "CycloneDX", "components": []},
        dependency_count=3,
        vulnerability_count=0,
    )
    assert data.package_name == "pkg"
    assert data.format == "cyclonedx"
