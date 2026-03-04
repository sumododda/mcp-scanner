"""SBOM generator service for CycloneDX 1.6 and SPDX 2.3 export.

Builds a Software Bill of Materials from local repository manifests or
registry dependency graphs, enriches with OSV.dev vulnerability data,
and exports to CycloneDX JSON, CycloneDX XML, or SPDX 2.3 JSON formats.
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring

from packageurl import PackageURL

from mcp_scanner.services.manifest_parsers import ParsedComponent, parse_all
from mcp_scanner.services.osv_client import OsvClient, OsvVulnerability

logger = logging.getLogger(__name__)

_TOOL_NAME = "mcp-scanner"
_TOOL_VERSION = "1.0.0"
_CDX_SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
_CDX_SPEC_VERSION = "1.6"
_CDX_NS = "http://cyclonedx.org/schema/bom/1.6"

# System name to PURL type mapping for deps.dev
_SYSTEM_TO_PURL_TYPE: dict[str, str] = {
    "NPM": "npm",
    "GO": "golang",
    "PYPI": "pypi",
    "CARGO": "cargo",
    "MAVEN": "maven",
    "NUGET": "nuget",
}


@dataclass
class SbomResult:
    """Result of SBOM generation with metadata."""

    bom_json: dict
    component_count: int
    vulnerabilities: list[OsvVulnerability] = field(default_factory=list)
    vulnerability_count: int = 0
    license_summary: dict = field(default_factory=dict)
    main_name: str = ""
    main_version: str = ""


class SbomGenerator:
    """Generates CycloneDX 1.6 SBOMs from repo manifests or registry graphs."""

    def __init__(self, osv_client: OsvClient | None = None) -> None:
        self._owns_client = osv_client is None
        self._osv_client = osv_client or OsvClient()

    async def close(self) -> None:
        """Close the owned OSV client if we created it."""
        if self._owns_client:
            await self._osv_client.close()

    # ------------------------------------------------------------------
    # Public generation methods
    # ------------------------------------------------------------------

    async def generate_from_repo(self, repo_path: Path) -> SbomResult | None:
        """Generate an SBOM from manifest files found in a repository.

        1. Parse all manifest files via manifest_parsers.parse_all()
        2. If no components found, return None
        3. Build CycloneDX 1.6 BOM
        4. Query OSV.dev for vulnerability enrichment
        5. Return SbomResult
        """
        parse_result = parse_all(repo_path)

        if not parse_result.components:
            return None

        # Build the CycloneDX BOM
        components = self._components_to_cdx(parse_result.components)
        dependencies = self._deps_to_cdx(parse_result.dependencies)

        bom = self._build_bom(
            components=components,
            dependencies=dependencies,
            main_name=parse_result.main_name or repo_path.name,
            main_version=parse_result.main_version or "0.0.0",
            component_type="application",
        )

        # Query OSV for vulnerabilities
        purls = [str(c.purl) for c in parse_result.components]
        vulns = await self._osv_client.query_batch(purls)

        # Build license summary from components (best-effort)
        license_summary = self._build_license_summary(parse_result.components)

        return SbomResult(
            bom_json=bom,
            component_count=len(parse_result.components),
            vulnerabilities=vulns,
            vulnerability_count=len(vulns),
            license_summary=license_summary,
            main_name=parse_result.main_name or repo_path.name,
            main_version=parse_result.main_version or "0.0.0",
        )

    async def generate_from_registry(
        self,
        deps_client,
        system: str,
        package_name: str,
        package_version: str,
    ) -> SbomResult | None:
        """Generate an SBOM from a deps.dev dependency graph.

        1. Call deps_client.get_dependencies(system, name, version)
        2. Parse nodes/edges into CycloneDX components
        3. Build CycloneDX 1.6 BOM
        4. Query OSV.dev for vulnerability enrichment
        5. Return SbomResult
        """
        dep_data = await deps_client.get_dependencies(
            system, package_name, package_version
        )
        if dep_data is None:
            return None

        nodes = dep_data.get("nodes", [])
        edges = dep_data.get("edges", [])

        if not nodes:
            return None

        # Parse nodes into components, tracking PURLs by node index
        purl_type = _SYSTEM_TO_PURL_TYPE.get(system.upper(), system.lower())
        node_purls: list[str] = []
        components: list[dict] = []

        for node in nodes:
            vk = node.get("versionKey", {})
            name = vk.get("name", "")
            version = vk.get("version", "")
            node_system = vk.get("system", system).upper()
            node_purl_type = _SYSTEM_TO_PURL_TYPE.get(node_system, purl_type)

            purl = self._build_purl(node_purl_type, name, version)
            purl_str = str(purl)
            node_purls.append(purl_str)

            relation = node.get("relation", "")
            if relation == "SELF":
                continue

            components.append({
                "type": "library",
                "bom-ref": purl_str,
                "name": name,
                "version": version,
                "purl": purl_str,
            })

        # Build dependency edges
        dependencies: list[dict] = []
        dep_map: dict[str, list[str]] = {}
        for edge in edges:
            from_idx = edge.get("fromNode", 0)
            to_idx = edge.get("toNode", 0)
            if from_idx < len(node_purls) and to_idx < len(node_purls):
                from_purl = node_purls[from_idx]
                dep_map.setdefault(from_purl, []).append(node_purls[to_idx])

        for ref, depends_on in dep_map.items():
            dependencies.append({"ref": ref, "dependsOn": depends_on})

        bom = self._build_bom(
            components=components,
            dependencies=dependencies,
            main_name=package_name,
            main_version=package_version,
            component_type="library",
        )

        # Query OSV for vulnerabilities
        component_purls = [c["purl"] for c in components]
        vulns = await self._osv_client.query_batch(component_purls)

        return SbomResult(
            bom_json=bom,
            component_count=len(components),
            vulnerabilities=vulns,
            vulnerability_count=len(vulns),
            license_summary={},
            main_name=package_name,
            main_version=package_version,
        )

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------

    def export(self, result: SbomResult, format: str) -> str:
        """Export an SbomResult to the specified format.

        Supported formats:
        - cyclonedx-json: CycloneDX 1.6 JSON
        - cyclonedx-xml: CycloneDX 1.6 XML
        - spdx-json: SPDX 2.3 JSON
        """
        if format == "cyclonedx-json":
            return json.dumps(result.bom_json, indent=2)
        elif format == "cyclonedx-xml":
            return self._convert_to_xml(result.bom_json)
        elif format == "spdx-json":
            spdx = self._convert_to_spdx(result.bom_json)
            return json.dumps(spdx, indent=2)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    # ------------------------------------------------------------------
    # BOM building
    # ------------------------------------------------------------------

    def _build_bom(
        self,
        components: list[dict],
        dependencies: list[dict],
        main_name: str,
        main_version: str,
        component_type: str,
    ) -> dict:
        """Build a CycloneDX 1.6 BOM dictionary."""
        return {
            "$schema": _CDX_SCHEMA,
            "bomFormat": "CycloneDX",
            "specVersion": _CDX_SPEC_VERSION,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "name": _TOOL_NAME,
                            "version": _TOOL_VERSION,
                        }
                    ]
                },
                "component": {
                    "type": component_type,
                    "name": main_name,
                    "version": main_version,
                },
            },
            "components": components,
            "dependencies": dependencies,
        }

    # ------------------------------------------------------------------
    # Conversion helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _convert_to_spdx(bom: dict) -> dict:
        """Convert a CycloneDX 1.6 BOM to SPDX 2.3 JSON format."""
        main_comp = bom.get("metadata", {}).get("component", {})
        main_name = main_comp.get("name", "unknown")
        timestamp = bom.get("metadata", {}).get("timestamp", "")

        packages = []
        for comp in bom.get("components", []):
            spdx_id = "SPDXRef-" + re.sub(
                r"[^a-zA-Z0-9.-]", "-", comp.get("name", "unknown")
            )
            pkg = {
                "SPDXID": spdx_id,
                "name": comp.get("name", ""),
                "versionInfo": comp.get("version", ""),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "externalRefs": [],
            }
            if comp.get("purl"):
                pkg["externalRefs"].append({
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp["purl"],
                })
            packages.append(pkg)

        return {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": main_name,
            "documentNamespace": f"https://spdx.org/spdxdocs/{main_name}-{uuid.uuid4()}",
            "creationInfo": {
                "created": timestamp,
                "creators": [f"Tool: {_TOOL_NAME}-{_TOOL_VERSION}"],
            },
            "packages": packages,
        }

    @staticmethod
    def _convert_to_xml(bom: dict) -> str:
        """Convert a CycloneDX 1.6 BOM to XML format."""
        root = Element("bom")
        root.set("xmlns", _CDX_NS)
        root.set("version", str(bom.get("version", 1)))
        root.set("serialNumber", bom.get("serialNumber", ""))

        # Metadata
        metadata_data = bom.get("metadata", {})
        metadata_el = SubElement(root, "metadata")

        ts_el = SubElement(metadata_el, "timestamp")
        ts_el.text = metadata_data.get("timestamp", "")

        # Tools
        tools_el = SubElement(metadata_el, "tools")
        for tool in metadata_data.get("tools", {}).get("components", []):
            tool_el = SubElement(tools_el, "tool")
            name_el = SubElement(tool_el, "name")
            name_el.text = tool.get("name", "")
            ver_el = SubElement(tool_el, "version")
            ver_el.text = tool.get("version", "")

        # Main component
        main_comp = metadata_data.get("component", {})
        if main_comp:
            comp_el = SubElement(metadata_el, "component")
            comp_el.set("type", main_comp.get("type", "application"))
            name_el = SubElement(comp_el, "name")
            name_el.text = main_comp.get("name", "")
            ver_el = SubElement(comp_el, "version")
            ver_el.text = main_comp.get("version", "")

        # Components
        components_el = SubElement(root, "components")
        for comp in bom.get("components", []):
            comp_el = SubElement(components_el, "component")
            comp_el.set("type", comp.get("type", "library"))
            comp_el.set("bom-ref", comp.get("bom-ref", ""))

            name_el = SubElement(comp_el, "name")
            name_el.text = comp.get("name", "")

            ver_el = SubElement(comp_el, "version")
            ver_el.text = comp.get("version", "")

            if comp.get("purl"):
                purl_el = SubElement(comp_el, "purl")
                purl_el.text = comp["purl"]

        # Dependencies
        deps_data = bom.get("dependencies", [])
        if deps_data:
            deps_el = SubElement(root, "dependencies")
            for dep in deps_data:
                dep_el = SubElement(deps_el, "dependency")
                dep_el.set("ref", dep.get("ref", ""))
                for depends_on in dep.get("dependsOn", []):
                    child_el = SubElement(dep_el, "dependency")
                    child_el.set("ref", depends_on)

        xml_bytes = tostring(root, encoding="unicode", xml_declaration=True)
        return xml_bytes

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _components_to_cdx(components: list[ParsedComponent]) -> list[dict]:
        """Convert ParsedComponent list to CycloneDX component dicts."""
        result = []
        for comp in components:
            purl_str = str(comp.purl)
            result.append({
                "type": "library",
                "bom-ref": purl_str,
                "name": comp.name,
                "version": comp.version,
                "purl": purl_str,
            })
        return result

    @staticmethod
    def _deps_to_cdx(dependencies: dict[str, list[str]]) -> list[dict]:
        """Convert dependency map to CycloneDX dependency list."""
        result = []
        for ref, depends_on in dependencies.items():
            result.append({"ref": ref, "dependsOn": depends_on})
        return result

    @staticmethod
    def _build_purl(purl_type: str, name: str, version: str) -> PackageURL:
        """Build a PackageURL from type, name and version.

        Handles scoped npm packages and Go module paths.
        """
        if purl_type == "npm" and name.startswith("@") and "/" in name:
            namespace, pkg_name = name.split("/", 1)
            return PackageURL(
                type="npm", namespace=namespace, name=pkg_name, version=version
            )
        if purl_type == "golang" and "/" in name:
            last_slash = name.rfind("/")
            namespace = name[:last_slash]
            pkg_name = name[last_slash + 1:]
            return PackageURL(
                type="golang", namespace=namespace, name=pkg_name, version=version
            )
        return PackageURL(type=purl_type, name=name, version=version)

    @staticmethod
    def _build_license_summary(components: list[ParsedComponent]) -> dict:
        """Build a license summary from components (best-effort).

        Currently returns an empty dict since manifest parsers don't
        extract license info. Can be enriched later via registry lookups.
        """
        return {}
