from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
import uuid
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from mcp_scanner.checkers import get_all_checkers
from mcp_scanner.checkers.base import FindingData, Severity, deduplicate_across_tiers
from mcp_scanner.checkers.compliance import enrich_compliance
from mcp_scanner.api.schemas import validate_repo_url
from mcp_scanner.config import settings
from mcp_scanner.models.finding import Finding
from mcp_scanner.models.finding import Severity as DBSeverity
from mcp_scanner.models.scan import Scan, ScanStatus
from mcp_scanner.models.scan_context import PromptDefinition, ResourceDefinition, ScanContext, ToolDefinition
from mcp_scanner.models.sbom import Sbom
from mcp_scanner.models.tool_snapshot import ToolSnapshot
from mcp_scanner.services.sbom_generator import SbomGenerator
from mcp_scanner.services.scorer import ScoreCalculator

logger = logging.getLogger(__name__)


class ScanOrchestrator:
    def __init__(self):
        self.checkers = get_all_checkers()
        self.scorer = ScoreCalculator()

    async def run_scan(
        self,
        repo_url: str | None = None,
        session: AsyncSession | None = None,
        scan_id: str | None = None,
        tool_definitions: dict[str, list[ToolDefinition]] | None = None,
        prompt_definitions: dict[str, list[PromptDefinition]] | None = None,
        resource_definitions: dict[str, list[ResourceDefinition]] | None = None,
    ) -> dict:
        if not scan_id:
            scan_id = str(uuid.uuid4())

        mcp_config: dict = {"mcpServers": {}}

        # DB persistence: create or fetch Scan record
        db_scan: Scan | None = None
        if session is not None:
            stmt = select(Scan).where(Scan.id == uuid.UUID(scan_id))
            result = await session.execute(stmt)
            db_scan = result.scalar_one_or_none()

            if db_scan is None:
                db_scan = Scan(
                    id=uuid.UUID(scan_id),
                    status=ScanStatus.PENDING,
                    mcp_config=mcp_config,
                    repo_url=repo_url,
                )
                session.add(db_scan)
                await session.commit()
            else:
                db_scan.status = ScanStatus.PENDING
                await session.commit()

        logger.info("=== Scan %s started ===", scan_id[:8])

        # Use pre-built definitions if provided, otherwise extract from source
        clone_dir: str | None = None
        commit_hash: str | None = None
        if tool_definitions is None:
            tool_definitions = {}
        if prompt_definitions is None:
            prompt_definitions = {}
        if resource_definitions is None:
            resource_definitions = {}

        skip_extraction = any([tool_definitions, prompt_definitions, resource_definitions])

        if repo_url and not skip_extraction:
            try:
                logger.info("[1/7] Cloning repository: %s", repo_url)
                clone_dir, commit_hash = await self._clone_repo(repo_url)
                logger.info("[1/7] Clone complete (commit: %s)", commit_hash[:8] if commit_hash else "unknown")
            except Exception:
                logger.warning("Repo clone failed, continuing without source analysis", exc_info=True)

        if clone_dir:
            try:
                logger.info("[2/7] Extracting tool definitions from source code...")
                from mcp_scanner.services.repo_analyzer import RepoAnalyzer
                analyzer = RepoAnalyzer()
                extracted = await analyzer.extract_tools_from_source(clone_dir)
                if extracted:
                    tool_definitions["source"] = extracted
                    logger.info("[2/7] Extracted %d tools from source", len(extracted))
                else:
                    tool_definitions["source"] = []
                    logger.info("[2/7] No tools found in source code")

                extracted_prompts = analyzer.extract_prompts_from_source(clone_dir, server_name="source")
                if extracted_prompts:
                    prompt_definitions["source"] = extracted_prompts
                    logger.info("[2/7] Extracted %d prompts from source", len(extracted_prompts))

                extracted_resources = analyzer.extract_resources_from_source(clone_dir, server_name="source")
                if extracted_resources:
                    resource_definitions["source"] = extracted_resources
                    logger.info("[2/7] Extracted %d resources from source", len(extracted_resources))
            except Exception:
                logger.warning("Source code tool extraction failed", exc_info=True)
                tool_definitions["source"] = []

        try:
            # Step 4: Load historical snapshots for rug pull comparison
            historical_snapshots = []
            if db_scan is not None and session is not None and repo_url:
                latest_scan_stmt = (
                    select(Scan.id)
                    .where(
                        Scan.repo_url == repo_url,
                        Scan.status == ScanStatus.COMPLETED,
                        Scan.id != db_scan.id,
                    )
                    .order_by(Scan.created_at.desc())
                    .limit(1)
                )
                prev_scan_id = (await session.execute(latest_scan_stmt)).scalar_one_or_none()
                if prev_scan_id:
                    snap_result = await session.execute(
                        select(ToolSnapshot).where(ToolSnapshot.scan_id == prev_scan_id)
                    )
                    historical_snapshots = list(snap_result.scalars().all())
                    logger.info(
                        "Loaded %d historical snapshots from previous scan",
                        len(historical_snapshots),
                    )

            # Build code graph from source (Tier 0.5)
            code_graph = None
            code_graph_summary = None
            if clone_dir:
                try:
                    logger.info("[2.5/7] Building code graph from source...")
                    from mcp_scanner.services.code_graph import CodeGraphBuilder
                    builder = CodeGraphBuilder()
                    code_graph = builder.build_from_directory(Path(clone_dir))
                    code_graph_summary = code_graph.to_summary_dict()
                    logger.info(
                        "[2.5/7] Code graph: %d functions, %d tool handlers, %d call sites",
                        len(code_graph.functions),
                        len(code_graph.tool_handlers),
                        len(code_graph.call_sites),
                    )
                except Exception:
                    logger.warning("Code graph building failed", exc_info=True)

            # Build scan context
            context = ScanContext(
                mcp_config=mcp_config,
                tool_definitions=tool_definitions,
                prompt_definitions=prompt_definitions,
                resource_definitions=resource_definitions,
                historical_snapshots=historical_snapshots,
                source_code_path=Path(clone_dir) if clone_dir else None,
                code_graph=code_graph,
            )

            # Step 5: Pipeline setup
            if db_scan is not None and session is not None:
                db_scan.status = ScanStatus.RUNNING
                await session.commit()

            all_sbom_entries: list[dict] = []
            all_findings: list[FindingData] = []
            checker_details: list[dict] = []

            # Tier 0: Capability Analysis (runs FIRST, enriches context for checkers)
            cap_report = None
            try:
                logger.info("[3/7] Running capability analyzer (schema labeling + toxic flow detection)...")
                from mcp_scanner.services.capability_analyzer import CapabilityAnalyzer

                cap = CapabilityAnalyzer()
                cap_report = cap.analyze_all(tool_definitions, include_same_server=True)
                context.capability_report = cap_report
                for flow in cap_report.toxic_flows:
                    sev = Severity.CRITICAL if flow.severity == "critical" else (
                        Severity.HIGH if flow.severity == "high" else Severity.MEDIUM
                    )
                    all_findings.append(FindingData(
                        checker="capability_analyzer",
                        severity=sev,
                        title=f"Toxic flow: {flow.flow_type}",
                        description=(
                            f"Tool '{flow.source_tool}' on '{flow.source_server}' can feed "
                            f"data to '{flow.sink_tool}' on '{flow.sink_server}'."
                        ),
                        evidence=f"{flow.source_server}/{flow.source_tool} → {flow.sink_server}/{flow.sink_tool}",
                        location=f"{flow.sink_server}/{flow.sink_tool}:capability",
                        remediation="Review cross-server data flow for potential exfiltration or injection chain.",
                        cwe_id="CWE-200",
                    ))
                cap_items = sum(len(t) for t in tool_definitions.values())
                logger.info(
                    "[3/7] Capability analysis complete: %d tools labeled, %d toxic flows detected",
                    cap_items, len(cap_report.toxic_flows),
                )
                checker_details.append({
                    "id": "capability_analyzer",
                    "description": "Schema-based capability labeling and toxic flow detection",
                    "status": "completed",
                    "items_checked": cap_items,
                    "findings_count": len(cap_report.toxic_flows),
                    "checks": [
                        f"Labeled {cap_items} tools across 4 risk dimensions",
                        f"Detected {len(cap_report.toxic_flows)} toxic flows",
                    ],
                })
            except Exception as exc:
                logger.error("Capability analyzer failed: %s", exc, exc_info=True)
                checker_details.append({
                    "id": "capability_analyzer",
                    "description": "Schema-based capability labeling and toxic flow detection",
                    "status": "error", "error": str(exc),
                    "items_checked": 0, "findings_count": 0, "checks": [],
                })

            # Tier 1: Run all checkers (enriched with capability_report in context)
            logger.info("[4/7] Running %d security checkers...", len(self.checkers))
            for checker in self.checkers:
                checker_name = getattr(checker, "name", checker.__class__.__name__)
                checker_desc = getattr(checker, "description", "")
                logger.info("  -> Running checker: %s", checker_name)

                try:
                    result = await checker.check(context)
                    all_findings.extend(result.findings)
                    logger.info("  -> %s complete: %d findings", checker_name, len(result.findings))
                    checker_details.append(
                        self._build_checker_detail(
                            checker_name, checker_desc, context, result.findings,
                            security_questions=result.security_questions,
                        )
                    )
                except Exception as exc:
                    logger.error("  -> Checker %s failed: %s", checker_name, exc)
                    checker_details.append({
                        "id": checker_name, "description": checker_desc,
                        "status": "error", "error": str(exc),
                        "items_checked": 0, "findings_count": 0, "checks": [],
                    })

            # Tier 2: Specialized LLM Judges (per-category, concurrent)
            if settings.llm_judge_enabled and settings.openrouter_api_key:
                logger.info("[5/7] Running LLM behavioral mismatch judge...")
                from mcp_scanner.services.llm_judge import SpecializedLLMJudge

                specialized_judge = SpecializedLLMJudge()
                llm_finding_count = 0
                sev_map = {
                    "critical": Severity.CRITICAL, "high": Severity.HIGH,
                    "medium": Severity.MEDIUM, "low": Severity.LOW,
                }
                category_counts: dict[str, int] = {}

                for server_name, tools in tool_definitions.items():
                    for tool in tools:
                        try:
                            # Build code graph facts for behavioral_mismatch judge
                            graph_facts: str | None = None
                            if code_graph is not None:
                                handler_info = []
                                for h in code_graph.tool_handlers:
                                    if h.name == tool.tool_name or tool.tool_name in h.name:
                                        handler_calls = [
                                            c for c in code_graph.call_sites
                                            if c.parent_function == h.name and c.file_path == h.file_path
                                        ]
                                        calls_str = ", ".join(c.callee for c in handler_calls[:20])
                                        handler_info.append(
                                            f"Handler: {h.name} ({h.file_path}:{h.line})\n"
                                            f"Parameters: {', '.join(h.parameters)}\n"
                                            f"Calls: {calls_str or 'none'}\n"
                                            f"Body snippet: {h.body_text[:500]}"
                                        )
                                if handler_info:
                                    graph_facts = "\n\n".join(handler_info)

                            verdicts = await specialized_judge.analyze_tool(
                                tool_name=tool.tool_name,
                                server_name=server_name,
                                description=tool.description or "",
                                input_schema=tool.input_schema,
                                code_graph_facts=graph_facts,
                            )

                            for v in verdicts.threats:
                                llm_finding_count += 1
                                category_counts[v.category] = category_counts.get(v.category, 0) + 1
                                all_findings.append(FindingData(
                                    checker="llm_judge",
                                    severity=sev_map.get(v.severity, Severity.MEDIUM),
                                    title=f"LLM Judge [{v.category}]: {v.reasoning[:70]}",
                                    description=v.reasoning,
                                    evidence=v.evidence[:200],
                                    location=f"{server_name}/{tool.tool_name}:llm_judge:{v.category}",
                                    remediation=f"Review this tool for {v.category.replace('_', ' ')} risks.",
                                    cwe_id=v.cwe_id,
                                    llm_analysis=(
                                        f"Specialized Judge ({v.category}, {v.severity}, "
                                        f"confidence={v.confidence:.1%}): {v.reasoning}"
                                    ),
                                ))
                        except Exception:
                            logger.warning(
                                "Specialized judge failed for %s/%s",
                                server_name, tool.tool_name, exc_info=True,
                            )
                llm_items = sum(len(t) for t in tool_definitions.values())
                category_summary = ", ".join(f"{k}={v}" for k, v in sorted(category_counts.items()))
                logger.info(
                    "[5/7] Specialized judges complete: %d tools, %d threats (%s)",
                    llm_items, llm_finding_count, category_summary or "none",
                )
                judge_checks = [
                    f"Analyzed {llm_items} tools for behavioral mismatch (description vs code)",
                    f"Found {llm_finding_count} threats",
                ]
                if category_counts:
                    judge_checks.append(f"Breakdown: {category_summary}")
                checker_details.append({
                    "id": "llm_judge",
                    "description": "LLM behavioral mismatch judge (description vs code analysis)",
                    "status": "completed",
                    "items_checked": llm_items,
                    "findings_count": llm_finding_count,
                    "checks": judge_checks,
                })
            else:
                logger.info("[5/7] LLM judge skipped (not configured)")

            # SBOM generation via SbomGenerator service
            sbom_gen = SbomGenerator()
            try:
                # Repo-based SBOM from manifest files
                if context.source_code_path:
                    try:
                        repo_result = await sbom_gen.generate_from_repo(context.source_code_path)
                        if repo_result:
                            servers = context.mcp_config.get("mcpServers", {})
                            all_sbom_entries.append({
                                "server_name": next(iter(servers), "source"),
                                "package_name": repo_result.main_name,
                                "package_version": repo_result.main_version,
                                "format": "cyclonedx",
                                "sbom_data": repo_result.bom_json,
                                "dependency_count": repo_result.component_count,
                                "vulnerability_count": repo_result.vulnerability_count,
                                "vulnerabilities": [
                                    {"id": v.id, "summary": v.summary, "aliases": v.aliases,
                                     "purl": v.purl, "fixed_version": v.fixed_version}
                                    for v in repo_result.vulnerabilities
                                ],
                                "license_summary": repo_result.license_summary,
                            })
                            logger.info(
                                "Repo SBOM generated: %d components, %d vulns",
                                repo_result.component_count,
                                repo_result.vulnerability_count,
                            )
                    except Exception:
                        logger.warning("Repo SBOM generation failed", exc_info=True)

                # Registry-based SBOMs for each server with extractable package info
                from mcp_scanner.checkers.supply_chain import _extract_package_info
                from mcp_scanner.services.deps_dev_client import DepsDevClient

                deps_client = DepsDevClient()
                try:
                    for server_name, server_config in context.mcp_config.get("mcpServers", {}).items():
                        if not isinstance(server_config, dict):
                            continue
                        pkg, version, ecosystem = _extract_package_info(server_config)
                        if not pkg:
                            continue
                        deps_system = "NPM" if ecosystem == "npm" else "PYPI"

                        # Resolve version if not pinned
                        if not version:
                            pkg_data = await deps_client.get_package(deps_system, pkg)
                            if pkg_data:
                                versions = pkg_data.get("versions", [])
                                if versions:
                                    version = versions[-1].get("versionKey", {}).get("version")
                        if not version:
                            continue

                        try:
                            reg_result = await sbom_gen.generate_from_registry(
                                deps_client, deps_system, pkg, version
                            )
                            if reg_result:
                                all_sbom_entries.append({
                                    "server_name": server_name,
                                    "package_name": reg_result.main_name,
                                    "package_version": reg_result.main_version,
                                    "format": "cyclonedx",
                                    "sbom_data": reg_result.bom_json,
                                    "dependency_count": reg_result.component_count,
                                    "vulnerability_count": reg_result.vulnerability_count,
                                    "vulnerabilities": [
                                        {"id": v.id, "summary": v.summary, "aliases": v.aliases,
                                         "purl": v.purl, "fixed_version": v.fixed_version}
                                        for v in reg_result.vulnerabilities
                                    ],
                                    "license_summary": reg_result.license_summary,
                                })
                        except Exception:
                            logger.warning(
                                "Registry SBOM generation failed for %s/%s@%s",
                                server_name, pkg, version, exc_info=True,
                            )
                finally:
                    await deps_client.close()
            finally:
                await sbom_gen.close()

            logger.info("SBOM generation complete: %d entries", len(all_sbom_entries))

            # Cross-tier deduplication: merge overlapping findings from different checkers
            pre_dedup = len(all_findings)
            logger.info("[6/7] Deduplicating findings (%d raw findings)...", pre_dedup)
            all_findings = deduplicate_across_tiers(all_findings)
            logger.info("[6/7] Dedup complete: %d -> %d findings", pre_dedup, len(all_findings))
        finally:
            # Clean up cloned repo
            if clone_dir:
                shutil.rmtree(clone_dir, ignore_errors=True)

        # Step 6.5: Enrich all findings with compliance framework references
        enrich_compliance(all_findings)

        # Step 7: Calculate score
        logger.info("[7/7] Calculating score and building summary...")
        score, grade = self.scorer.calculate(all_findings)

        # Step 8: Build summary
        summary = self._build_summary(all_findings, checker_details)

        # DB persistence: persist findings and update scan to COMPLETED
        if db_scan is not None and session is not None:
            for f in all_findings:
                db_finding = Finding(
                    scan_id=db_scan.id,
                    checker=f.checker,
                    severity=DBSeverity(f.severity.value),
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
                session.add(db_finding)

            # Save tool snapshots for future rug pull comparison
            for srv_name, tools in tool_definitions.items():
                for tool in tools:
                    definition = {
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                    }
                    snapshot = ToolSnapshot(
                        scan_id=db_scan.id,
                        server_name=srv_name,
                        tool_name=tool.tool_name,
                        definition_hash=ToolSnapshot.compute_hash(
                            srv_name, tool.tool_name, definition,
                        ),
                        full_definition=definition,
                    )
                    session.add(snapshot)

            # Save SBOM entries from SBOM generator service
            for entry in all_sbom_entries:
                sbom = Sbom(
                    scan_id=db_scan.id,
                    server_name=entry["server_name"],
                    package_name=entry["package_name"],
                    package_version=entry["package_version"],
                    format=entry.get("format", "cyclonedx"),
                    sbom_data=entry["sbom_data"],
                    dependency_count=entry.get("dependency_count", 0),
                    vulnerability_count=entry.get("vulnerability_count", 0),
                    vulnerabilities=entry.get("vulnerabilities"),
                    license_summary=entry.get("license_summary"),
                )
                session.add(sbom)

            # Persist server metadata (prompts + resources) as JSONB
            all_server_names = set(tool_definitions.keys()) | set(prompt_definitions.keys()) | set(resource_definitions.keys())
            server_metadata = {}
            for srv_name in all_server_names:
                srv_prompts = prompt_definitions.get(srv_name, [])
                srv_resources = resource_definitions.get(srv_name, [])
                server_metadata[srv_name] = {
                    "prompts": [
                        {"name": p.name, "title": p.title, "description": p.description, "arguments": p.arguments}
                        for p in srv_prompts
                    ],
                    "resources": [
                        {"name": r.name, "title": r.title, "uri": r.uri, "description": r.description, "mime_type": r.mime_type, "size": r.size}
                        for r in srv_resources
                    ],
                }
            db_scan.server_metadata = server_metadata

            db_scan.status = ScanStatus.COMPLETED
            db_scan.overall_score = score
            db_scan.grade = grade
            db_scan.summary = summary
            if code_graph_summary:
                db_scan.code_graph = code_graph_summary
            if commit_hash:
                db_scan.commit_hash = commit_hash
            await session.commit()

        logger.info(
            "=== Scan %s complete: score=%d, grade=%s, findings=%d ===",
            scan_id[:8], score, grade, len(all_findings),
        )

        return {
            "scan_id": scan_id,
            "findings": all_findings,
            "score": score,
            "grade": grade,
            "summary": summary,
            "status": "completed",
        }

    async def _clone_repo(self, repo_url: str) -> tuple[str, str | None]:
        """Clone a git repo. Returns (clone_path, commit_hash)."""
        validate_repo_url(repo_url)
        tmp_dir = tempfile.mkdtemp(prefix="mcp_scan_")
        clone_path = str(Path(tmp_dir) / "repo")
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth", "1", repo_url, clone_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await proc.communicate()
            if proc.returncode != 0:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise RuntimeError(f"git clone failed: {stderr.decode()}")

            logger.info("Cloned repo %s to %s", repo_url, clone_path)

            # Capture commit hash
            commit_hash = None
            try:
                rev_proc = await asyncio.create_subprocess_exec(
                    "git", "-C", clone_path, "rev-parse", "HEAD",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await rev_proc.communicate()
                if rev_proc.returncode == 0:
                    commit_hash = stdout.decode().strip()
            except Exception:
                pass  # Non-critical

            # Check repo size
            total_size = sum(f.stat().st_size for f in Path(clone_path).rglob("*") if f.is_file())
            max_bytes = settings.max_repo_size_mb * 1024 * 1024
            if total_size > max_bytes:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise RuntimeError(
                    f"Repo size {total_size / 1024 / 1024:.1f}MB exceeds limit of {settings.max_repo_size_mb}MB"
                )

            return clone_path, commit_hash
        except Exception:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise

    def _build_summary(
        self, findings: list[FindingData], checker_details: list[dict] | None = None,
    ) -> dict:
        by_severity = {}
        by_checker = {}
        for f in findings:
            sev = f.severity.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_checker[f.checker] = by_checker.get(f.checker, 0) + 1
        summary: dict = {
            "total": len(findings),
            "by_severity": by_severity,
            "by_checker": by_checker,
        }
        if checker_details:
            summary["checker_details"] = checker_details
        return summary

    @staticmethod
    def _build_checker_detail(
        name: str, description: str, context: ScanContext, findings: list[FindingData],
        security_questions: list | None = None,
    ) -> dict:
        """Build an audit log for what a checker inspected."""
        checks: list[str] = []
        items_checked = 0

        # Count tools inspected
        tool_count = sum(len(tools) for tools in context.tool_definitions.values())
        server_count = len(context.mcp_config.get("mcpServers", {}))

        if name == "tool_poisoning":
            items_checked = tool_count
            checks.append(f"Scanned {tool_count} tool definitions across {server_count} servers")
            checks.append("Checked for: XML priority/override tags, instruction-verb phrases, "
                          "sensitive file path references, hidden base64 payloads, excessive whitespace, "
                          "social engineering / authority framing, task manipulation / sleeper payloads")
            for srv, tools in context.tool_definitions.items():
                for t in tools:
                    checks.append(f"  Inspected tool '{t.tool_name}' on server '{srv}' — "
                                  f"description ({len(t.description)} chars), "
                                  f"{len(t.input_schema.get('properties', {}))} parameters")

        elif name == "rug_pull":
            items_checked = tool_count
            snapshots = len(context.historical_snapshots)
            checks.append(f"Compared {tool_count} current tools against {snapshots} historical snapshots")
            if snapshots == 0:
                checks.append("No historical data — first scan establishes baseline (no findings)")
            else:
                checks.append("Checked for: description changes, schema changes, "
                              "privilege escalation in changed definitions")

        elif name == "data_exfiltration":
            items_checked = tool_count
            checks.append(f"Scanned {tool_count} tool definitions across {server_count} servers")
            checks.append("Checked for: suspicious parameter names (callback, webhook, metadata), "
                          "sensitive data parameters (token, secret, password), "
                          "external URLs in descriptions, cross-server tool shadowing")

        elif name == "supply_chain":
            items_checked = server_count
            checks.append(f"Analyzed {server_count} server configurations for supply chain risks")
            checks.append(
                "Layer 1: Typosquatting (Levenshtein + deps.dev), scope verification, unpinned npx detection"
            )
            checks.append(
                "Layer 2: Package metadata analysis (age, deprecation, install scripts)"
            )
            checks.append(
                "Layer 3: Vulnerability scanning (CVEs, MAL advisories) + SBOM generation"
            )
            checks.append(
                "Layer 4: Repository health (OpenSSF Scorecard via deps.dev)"
            )
            checks.append(
                "Layer 5: Aggregate risk scoring (combined signal escalation)"
            )
            for srv_name, srv_cfg in context.mcp_config.get("mcpServers", {}).items():
                cmd = srv_cfg.get("command", "")
                args = srv_cfg.get("args", [])
                checks.append(f"  Server '{srv_name}': command='{cmd}', args={args}")

        elif name == "infra_security":
            items_checked = server_count
            checks.append(f"Analyzed {server_count} server configurations")
            checks.append("Config checks: insecure HTTP, plaintext secrets, elevated privileges")
            if context.code_graph:
                cg = context.code_graph
                items_checked += len(cg.functions) + len(cg.tool_handlers)
                checks.append(f"Code graph: {len(cg.functions)} functions, {len(cg.tool_handlers)} tool handlers, {len(cg.imports)} imports")
                checks.append("Code checks: auth, validation, HTTP URLs, dangerous ops, deserialization, weak crypto, insecure TLS, hardcoded secrets, error handling, file access, rate limiting")
            for srv_name, srv_cfg in context.mcp_config.get("mcpServers", {}).items():
                env_count = len(srv_cfg.get("env", {}))
                header_count = len(srv_cfg.get("headers", {}))
                url = srv_cfg.get("url", "N/A")
                cmd = srv_cfg.get("command", "N/A")
                checks.append(f"  Server '{srv_name}': url={url}, command={cmd}, {env_count} env vars, {header_count} headers")

        elif name == "injection":
            items_checked = tool_count
            checks.append(f"Scanned {tool_count} tool definitions across {server_count} servers")
            checks.append("Checked for: command injection surfaces (cmd, shell, exec params), "
                          "SQL injection surfaces (query, sql, statement params), "
                          "dangerous keywords in parameter descriptions")

        else:
            items_checked = tool_count
            checks.append(f"Scanned {tool_count} tools across {server_count} servers")

        result = {
            "id": name,
            "description": description,
            "status": "completed",
            "items_checked": items_checked,
            "findings_count": len([f for f in findings if f.checker == name]),
            "checks": checks,
        }

        if security_questions:
            result["security_questions"] = [
                {
                    "id": sq.id, "question": sq.question, "answer": sq.answer,
                    "status": sq.status, "items_checked": sq.items_checked,
                    "items_checked_label": sq.items_checked_label,
                    "finding_ids": sq.finding_ids, "severity": sq.severity,
                    "detail": sq.detail,
                }
                for sq in security_questions
            ]

        return result
