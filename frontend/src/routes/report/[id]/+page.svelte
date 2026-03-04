<script lang="ts">
	import { page } from '$app/state';
	import { getScan, getScanSbom, dismissFinding, restoreFinding, type ScanResult, type CheckerDetail, type Finding, type ServerOverview, type Prompt, type Resource, type SbomEntry } from '$lib/api';
	import GradeCard from '$lib/components/GradeCard.svelte';
	import FindingsList from '$lib/components/FindingsList.svelte';
	import SecurityQA from '$lib/components/SecurityQA.svelte';
	import TriageChat from '$lib/components/TriageChat.svelte';
	import CodeGraphChat from '$lib/components/CodeGraphChat.svelte';
	import CodeGraphVisual from '$lib/components/CodeGraphVisual.svelte';
	import type { CodeGraphData } from '$lib/api';

	const API_BASE = 'http://localhost:8000';

	const checkerLabels: Record<string, string> = {
		tool_poisoning: 'TOOL POISONING',
		rug_pull: 'RUG PULL',
		data_exfiltration: 'DATA EXFIL',
		supply_chain: 'SUPPLY CHAIN',
		infra_security: 'INFRA',
		injection: 'INJECTION',
		semgrep: 'SOURCE CODE',
	};

	const checkerDescriptions: Record<string, string> = {
		tool_poisoning: 'Detects hidden instructions, priority overrides, social engineering, task manipulation, and manipulative content in tool definitions that could trick LLMs into executing malicious actions.',
		rug_pull: 'Compares current tool definitions against historical snapshots to detect unauthorized changes indicating supply chain compromise.',
		data_exfiltration: 'Identifies suspicious parameters, callback URLs, and cross-server tool shadowing patterns that could leak sensitive data.',
		supply_chain: 'Multi-layer supply chain analysis: typosquatting detection, package metadata verification, vulnerability & provenance scanning via deps.dev, repository health scoring, and aggregate risk assessment.',
		infra_security: 'Checks for insecure HTTP transport, plaintext secrets in environment variables, and elevated privileges in server configurations.',
		injection: 'Identifies command injection, SQL injection, and other injection surfaces in tool parameter schemas.',
		semgrep: 'Static analysis of the repository source code using custom Semgrep rules for MCP-specific security patterns.',
	};

	let loading = $state(true);
	let error = $state('');
	let scan: ScanResult | null = $state(null);
	let activeTab: string = $state('__overview');
	let sbomEntries: SbomEntry[] = $state([]);

	let scanId = $derived(page.params.id);

	async function loadScan(id: string) {
		loading = true;
		error = '';
		try {
			scan = await getScan(id);
			activeTab = '__overview';
			// Fetch SBOM data in background
			getScanSbom(id).then(entries => { sbomEntries = entries; }).catch(() => { sbomEntries = []; });
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load scan';
		} finally {
			loading = false;
		}
	}

	let totalSbomDeps = $derived(sbomEntries.reduce((sum, e) => sum + (e.dependency_count ?? 0), 0));
	let totalSbomVulns = $derived(sbomEntries.reduce((sum, e) => sum + (e.vulnerability_count ?? 0), 0));

	function downloadSbom() {
		if (sbomEntries.length === 0) return;
		// If single SBOM entry, download it directly (already valid CycloneDX)
		if (sbomEntries.length === 1) {
			const blob = new Blob([JSON.stringify(sbomEntries[0].sbom_data, null, 2)], { type: 'application/json' });
			const url = URL.createObjectURL(blob);
			const a = document.createElement('a');
			a.href = url;
			a.download = `sbom-${scan?.id?.slice(0, 8) ?? 'scan'}.cdx.json`;
			a.click();
			URL.revokeObjectURL(url);
			return;
		}
		// Multiple entries: merge into a valid CycloneDX 1.5 BOM
		const combined = {
			$schema: 'http://cyclonedx.org/schema/bom-1.5.schema.json',
			bomFormat: 'CycloneDX',
			specVersion: '1.5',
			serialNumber: `urn:uuid:${crypto.randomUUID()}`,
			version: 1,
			metadata: {
				timestamp: new Date().toISOString(),
				tools: {
					components: [{ type: 'application', name: 'mcp-scanner', version: '1.0.0' }]
				}
			},
			components: sbomEntries.flatMap(e => e.sbom_data?.components ?? []),
			dependencies: sbomEntries.flatMap(e => e.sbom_data?.dependencies ?? []),
		};
		const blob = new Blob([JSON.stringify(combined, null, 2)], { type: 'application/json' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = `sbom-${scan?.id?.slice(0, 8) ?? 'scan'}.cdx.json`;
		a.click();
		URL.revokeObjectURL(url);
	}

	$effect(() => {
		if (scanId) loadScan(scanId);
	});

	let totalFindings = $derived(scan?.summary?.total ?? 0);
	let criticalCount = $derived(scan?.summary?.by_severity?.critical ?? 0);
	let highCount = $derived(scan?.summary?.by_severity?.high ?? 0);
	let mediumCount = $derived(scan?.summary?.by_severity?.medium ?? 0);
	let lowCount = $derived(scan?.summary?.by_severity?.low ?? 0);
	let checkerDetails = $derived((scan?.summary?.checker_details ?? []).filter(d => d.id !== 'capability_analyzer'));
	let servers = $derived(scan?.servers ?? []);
	let totalTools = $derived(servers.reduce((sum, s) => sum + s.tool_count, 0));
	let totalPrompts = $derived(servers.reduce((sum, s) => sum + (s.prompt_count ?? 0), 0));
	let totalResources = $derived(servers.reduce((sum, s) => sum + (s.resource_count ?? 0), 0));
	let totalParams = $derived(servers.reduce((sum, s) => sum + s.tools.reduce((ts, t) => ts + t.parameter_count, 0), 0));
	let hasCodeGraph = $derived(scan?.code_graph?.stats != null);
	let codeGraphStats = $derived(scan?.code_graph?.stats ?? { total_functions: 0, total_imports: 0, total_call_sites: 0, tool_handlers: 0, dangerous_calls: 0, network_calls: 0, file_access_calls: 0 });
	let codeGraphHandlers = $derived((scan?.code_graph?.tool_handlers ?? []) as string[]);
	let codeGraphData = $derived(scan?.code_graph as CodeGraphData | null);
	let graphSelectedNode = $state('');
	let graphHighlightedNodes: string[] = $state([]);
	let graphNodeLabels = $derived(
		codeGraphData?.functions.map(f => f.name) ?? []
	);

	function handleGraphNodeClick(nodeName: string) {
		graphSelectedNode = nodeName;
		graphHighlightedNodes = [];
	}

	function handleMentionedNodes(names: string[]) {
		graphHighlightedNodes = names;
	}

	function formatSize(bytes: number | undefined | null): string {
		if (bytes == null) return '—';
		if (bytes < 1024) return `${bytes} B`;
		if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
		return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
	}

	function findingsForChecker(checkerId: string): Finding[] {
		return (scan?.findings ?? []).filter(f => f.checker === checkerId);
	}

	function maxSeverity(checkerId: string): string {
		const findings = findingsForChecker(checkerId);
		const order = ['critical', 'high', 'medium', 'low'];
		for (const sev of order) {
			if (findings.some(f => f.severity === sev)) return sev;
		}
		return 'clear';
	}

	function sevDotColor(sev: string): string {
		switch (sev) {
			case 'critical': return 'bg-crit';
			case 'high': return 'bg-high';
			case 'medium': return 'bg-med';
			case 'low': return 'bg-low';
			default: return 'bg-clear';
		}
	}

	function sevTextColor(sev: string): string {
		switch (sev) {
			case 'critical': return 'text-crit';
			case 'high': return 'text-high';
			case 'medium': return 'text-med';
			case 'low': return 'text-low';
			default: return 'text-clear';
		}
	}

	let activeDetail = $derived(checkerDetails.find(d => d.id === activeTab));
	let activeFindings = $derived(findingsForChecker(activeTab));
	let activeSev = $derived(maxSeverity(activeTab));

	let allFindings = $derived(scan?.findings ?? []);
	let triageInitialFinding: Finding | null = $state(null);

	function openTriageFor(finding: Finding) {
		triageInitialFinding = finding;
	}

	async function handleDismiss(finding: Finding, dismissedAs: string, reason: string) {
		if (!scan) return;
		try {
			const updated = await dismissFinding(finding.id, dismissedAs, reason);
			// Update local state
			const idx = scan.findings.findIndex(f => f.id === finding.id);
			if (idx !== -1) {
				scan.findings[idx] = { ...scan.findings[idx], dismissed_as: updated.dismissed_as, dismissed_reason: updated.dismissed_reason };
			}
			recalcSummary();
		} catch (err) {
			console.error('Failed to dismiss finding:', err);
		}
	}

	async function handleRestore(finding: Finding) {
		if (!scan) return;
		try {
			await restoreFinding(finding.id);
			const idx = scan.findings.findIndex(f => f.id === finding.id);
			if (idx !== -1) {
				scan.findings[idx] = { ...scan.findings[idx], dismissed_as: undefined, dismissed_reason: undefined };
			}
			recalcSummary();
		} catch (err) {
			console.error('Failed to restore finding:', err);
		}
	}

	const severityWeight: Record<string, number> = { critical: 25, high: 15, medium: 5, low: 1 };

	function recalcSummary() {
		if (!scan?.summary) return;
		const active = scan.findings.filter(f => !f.dismissed_as);
		const by_severity: Record<string, number> = {};
		const by_checker: Record<string, number> = {};
		for (const f of active) {
			by_severity[f.severity] = (by_severity[f.severity] ?? 0) + 1;
			by_checker[f.checker] = (by_checker[f.checker] ?? 0) + 1;
		}
		scan.summary = {
			...scan.summary,
			total: active.length,
			by_severity,
			by_checker,
		};

		// Recalculate score and grade
		let score = 100;
		for (const f of active) {
			score -= severityWeight[f.severity] ?? 0;
		}
		score = Math.max(0, score);
		scan.overall_score = score;
		scan.grade = score >= 90 ? 'A' : score >= 70 ? 'B' : score >= 50 ? 'C' : score >= 30 ? 'D' : 'F';
	}
</script>

<div class="space-y-6">
	<!-- Top bar -->
	<div class="flex items-center justify-between">
		<a href="/history" class="flex items-center gap-2 text-sm font-mono text-t3 transition-colors hover:text-t1">
			<svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
			</svg>
			HISTORY
		</a>
		{#if scan}
			<a
				href="{API_BASE}/api/scan/{scan.id}/pdf"
				target="_blank"
				rel="noopener noreferrer"
				class="text-sm font-mono text-t3 transition-colors hover:text-t1"
			>
				EXPORT PDF
			</a>
		{/if}
	</div>

	{#if loading}
		<div class="flex items-center justify-center py-24">
			<div class="flex items-center gap-3">
				<div class="h-4 w-4 rounded-full bg-blue anim-pulse"></div>
				<span class="text-sm font-mono text-t3 tracking-wider">LOADING REPORT</span>
			</div>
		</div>
	{:else if error}
		<div class="border border-crit/20 bg-crit/5 px-5 py-4">
			<p class="text-sm font-mono text-crit">{error}</p>
		</div>
	{:else if scan}
		<!-- Metadata -->
		<div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs font-mono text-t4">
			{#if scan.repo_url}
				<a href={scan.repo_url} target="_blank" rel="noopener noreferrer" class="text-sm font-mono font-medium text-blue hover:text-t1 transition-colors">
					{scan.repo_url.replace('https://github.com/', '')}
				</a>
			{/if}
			{#if scan.commit_hash}
				<a
					href="{scan.repo_url}/commit/{scan.commit_hash}"
					target="_blank"
					rel="noopener noreferrer"
					class="text-blue/70 hover:text-blue transition-colors"
					title={scan.commit_hash}
				>
					{scan.commit_hash.slice(0, 7)}
				</a>
			{/if}
			<span>{new Date(scan.created_at).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} {new Date(scan.created_at).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}</span>
			<span class={scan.status === 'completed' ? 'text-clear' : scan.status === 'failed' ? 'text-crit' : 'text-t4'}>{scan.status.toUpperCase()}</span>
			<span title={scan.id}>{scan.id.slice(0, 8)}</span>
		</div>

		{#if scan.error_message}
			<div class="border border-crit/20 bg-crit/5 px-5 py-4">
				<p class="text-sm font-mono text-crit">{scan.error_message}</p>
			</div>
		{/if}

		<!-- Score + Severity -->
		{#if scan.grade !== null || scan.summary !== null}
			<div class="anim-in space-y-4">
				{#if scan.grade !== null}
					<GradeCard grade={scan.grade} score={scan.overall_score} />
				{/if}

				{#if scan.summary}
					<div class="flex items-center gap-6 text-sm font-mono">
						{#if criticalCount > 0}
							<span class="flex items-center gap-2">
								<span class="h-2.5 w-2.5 rounded-full bg-crit"></span>
								<span class="text-crit font-semibold">{criticalCount}</span>
								<span class="text-t4">CRIT</span>
							</span>
						{/if}
						{#if highCount > 0}
							<span class="flex items-center gap-2">
								<span class="h-2.5 w-2.5 rounded-full bg-high"></span>
								<span class="text-high font-semibold">{highCount}</span>
								<span class="text-t4">HIGH</span>
							</span>
						{/if}
						{#if mediumCount > 0}
							<span class="flex items-center gap-2">
								<span class="h-2.5 w-2.5 rounded-full bg-med"></span>
								<span class="text-med font-semibold">{mediumCount}</span>
								<span class="text-t4">MED</span>
							</span>
						{/if}
						{#if lowCount > 0}
							<span class="flex items-center gap-2">
								<span class="h-2.5 w-2.5 rounded-full bg-low"></span>
								<span class="text-low font-semibold">{lowCount}</span>
								<span class="text-t4">LOW</span>
							</span>
						{/if}
						{#if totalFindings === 0}
							<span class="flex items-center gap-2">
								<span class="h-2.5 w-2.5 rounded-full bg-clear"></span>
								<span class="text-clear font-semibold">CLEAR</span>
							</span>
						{/if}
					</div>
				{/if}
			</div>
		{/if}

		<!-- Tabs + Content -->
		<div class="anim-in" style="animation-delay: 100ms">
			<!-- Tab row -->
			<div class="flex gap-0 border-b border-edge overflow-x-auto scrollbar-hide">
				<!-- Overview tab -->
				<button
					class="shrink-0 flex items-center gap-2 px-4 py-3 text-xs font-mono font-medium tracking-wider transition-all border-b-2
						{activeTab === '__overview'
						? 'border-blue text-blue bg-bg-raised'
						: 'border-transparent text-t4 hover:text-t2 hover:bg-bg-raised/50'}"
					onclick={() => (activeTab = '__overview')}
				>
					OVERVIEW
				</button>

				<!-- Code Graph tab -->
				{#if hasCodeGraph}
					<button
						class="shrink-0 flex items-center gap-2 px-4 py-3 text-xs font-mono font-medium tracking-wider transition-all border-b-2
							{activeTab === '__code_graph'
							? 'border-blue text-blue bg-bg-raised'
							: 'border-transparent text-t4 hover:text-t2 hover:bg-bg-raised/50'}"
						onclick={() => (activeTab = '__code_graph')}
					>
						<svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M17.25 6.75L22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3l-4.5 16.5" />
						</svg>
						CODE GRAPH
					</button>
				{/if}

				<!-- Checker tabs -->
				{#each checkerDetails as detail}
					{@const sev = maxSeverity(detail.id)}
					{@const hasFinding = detail.findings_count > 0}
					{@const isActive = activeTab === detail.id}
					<button
						class="shrink-0 flex items-center gap-2 px-4 py-3 text-xs font-mono font-medium tracking-wider transition-all border-b-2
							{isActive
							? (hasFinding ? 'border-current ' + sevTextColor(sev) + ' bg-bg-raised' : 'border-blue text-blue bg-bg-raised')
							: 'border-transparent text-t4 hover:text-t2 hover:bg-bg-raised/50'}"
						onclick={() => (activeTab = detail.id)}
					>
						<span class="h-2 w-2 rounded-full shrink-0 {hasFinding ? sevDotColor(sev) : detail.status === 'error' ? 'bg-crit' : 'bg-clear/40'}"></span>
						{checkerLabels[detail.id] ?? detail.id}
						{#if hasFinding}
							<span class="text-xs opacity-60">{detail.findings_count}</span>
						{/if}
					</button>
				{/each}
			</div>

			<!-- OVERVIEW TAB -->
			{#if activeTab === '__overview'}
				<div class="pt-6 space-y-8 anim-in">
					<!-- Stats row -->
					<div class="flex items-center gap-10 text-sm font-mono flex-wrap">
						<div>
							<span class="text-3xl font-bold text-t1">{servers.length}</span>
							<span class="text-t4 ml-2">SERVER{servers.length !== 1 ? 'S' : ''}</span>
						</div>
						<div>
							<span class="text-3xl font-bold text-t1">{totalTools}</span>
							<span class="text-t4 ml-2">TOOL{totalTools !== 1 ? 'S' : ''}</span>
						</div>
						<div>
							<span class="text-3xl font-bold text-t1">{totalPrompts}</span>
							<span class="text-t4 ml-2">PROMPT{totalPrompts !== 1 ? 'S' : ''}</span>
						</div>
						<div>
							<span class="text-3xl font-bold text-t1">{totalResources}</span>
							<span class="text-t4 ml-2">RESOURCE{totalResources !== 1 ? 'S' : ''}</span>
						</div>
						<div>
							<span class="text-3xl font-bold text-t1">{totalFindings}</span>
							<span class="text-t4 ml-2">FINDING{totalFindings !== 1 ? 'S' : ''}</span>
						</div>
					</div>

					<!-- Servers + Tools -->
					{#if servers.length > 0}
						{#each servers as server, si}
							<div class="anim-in" style="animation-delay: {si * 60}ms">
								<div class="flex items-center gap-3 mb-3">
									<span class="text-xs font-mono font-semibold text-t4 tracking-wider">SERVER</span>
									<span class="text-sm font-mono font-semibold text-t1">{server.name}</span>
									<span class="text-xs font-mono text-t4">
										{server.tool_count} tool{server.tool_count !== 1 ? 's' : ''}
										{#if (server.prompt_count ?? 0) > 0}
											· {server.prompt_count} prompt{server.prompt_count !== 1 ? 's' : ''}
										{/if}
										{#if (server.resource_count ?? 0) > 0}
											· {server.resource_count} resource{server.resource_count !== 1 ? 's' : ''}
										{/if}
									</span>
								</div>

								<!-- Tool table -->
								{#if server.tools.length > 0}
								<div class="border border-edge rounded-sm overflow-hidden">
									<!-- Header -->
									<div class="grid grid-cols-[200px_1fr_80px] gap-4 px-4 py-2.5 bg-bg-raised text-xs font-mono font-semibold text-t4 tracking-wider border-b border-edge">
										<span>TOOL</span>
										<span>DESCRIPTION</span>
										<span class="text-right">PARAMS</span>
									</div>
									<!-- Rows -->
									{#each server.tools as tool, ti}
										<details class="group">
											<summary class="grid grid-cols-[200px_1fr_80px] gap-4 px-4 py-3 text-sm font-mono cursor-pointer transition-colors hover:bg-bg-raised/50 border-b border-edge/50 last:border-b-0 list-none">
												<span class="text-t1 font-medium truncate">{tool.tool_name}</span>
												<span class="text-t3 truncate">{tool.description || '—'}</span>
												<span class="text-right text-t4">{tool.parameter_count}</span>
											</summary>

											<!-- Expanded: parameter details -->
											{#if tool.parameters.length > 0}
												<div class="anim-expand bg-bg-deep border-b border-edge/50 px-4 py-4">
													<div class="grid grid-cols-[160px_80px_1fr] gap-3 mb-2 text-xs font-mono font-semibold text-t4 tracking-wider">
														<span>PARAMETER</span>
														<span>TYPE</span>
														<span>DESCRIPTION</span>
													</div>
													{#each tool.parameters as param}
														<div class="grid grid-cols-[160px_80px_1fr] gap-3 py-1.5 text-sm font-mono">
															<span class="text-t2 truncate">
																{param.name}{#if param.required}<span class="text-crit ml-0.5">*</span>{/if}
															</span>
															<span class="text-t4">{param.type}</span>
															<span class="text-t3 truncate">{param.description || '—'}</span>
														</div>
													{/each}
												</div>
											{/if}
										</details>
									{/each}
								</div>
								{/if}

								<!-- Prompts table -->
								{#if (server.prompts ?? []).length > 0}
								<div class="border border-edge rounded-sm overflow-hidden mt-3">
									<div class="grid grid-cols-[200px_1fr_80px] gap-4 px-4 py-2.5 bg-bg-raised text-xs font-mono font-semibold text-t4 tracking-wider border-b border-edge">
										<span>PROMPT</span>
										<span>DESCRIPTION</span>
										<span class="text-right">ARGS</span>
									</div>
									{#each server.prompts as prompt}
										<details class="group">
											<summary class="grid grid-cols-[200px_1fr_80px] gap-4 px-4 py-3 text-sm font-mono cursor-pointer transition-colors hover:bg-bg-raised/50 border-b border-edge/50 last:border-b-0 list-none">
												<span class="text-t1 font-medium truncate">{prompt.name}</span>
												<span class="text-t3 truncate">{prompt.description || prompt.title || '—'}</span>
												<span class="text-right text-t4">{prompt.argument_count}</span>
											</summary>
											{#if prompt.arguments.length > 0}
												<div class="anim-expand bg-bg-deep border-b border-edge/50 px-4 py-4">
													<div class="grid grid-cols-[160px_1fr] gap-3 mb-2 text-xs font-mono font-semibold text-t4 tracking-wider">
														<span>ARGUMENT</span>
														<span>DESCRIPTION</span>
													</div>
													{#each prompt.arguments as arg}
														<div class="grid grid-cols-[160px_1fr] gap-3 py-1.5 text-sm font-mono">
															<span class="text-t2 truncate">
																{arg.name}{#if arg.required}<span class="text-crit ml-0.5">*</span>{/if}
															</span>
															<span class="text-t3 truncate">{arg.description || '—'}</span>
														</div>
													{/each}
												</div>
											{/if}
										</details>
									{/each}
								</div>
								{/if}

								<!-- Resources table -->
								{#if (server.resources ?? []).length > 0}
								<div class="border border-edge rounded-sm overflow-hidden mt-3">
									<div class="grid grid-cols-[200px_1fr_120px_80px] gap-4 px-4 py-2.5 bg-bg-raised text-xs font-mono font-semibold text-t4 tracking-wider border-b border-edge">
										<span>RESOURCE</span>
										<span>URI</span>
										<span>TYPE</span>
										<span class="text-right">SIZE</span>
									</div>
									{#each server.resources as resource}
										<div class="grid grid-cols-[200px_1fr_120px_80px] gap-4 px-4 py-3 text-sm font-mono border-b border-edge/50 last:border-b-0">
											<span class="text-t1 font-medium truncate" title={resource.description || resource.name}>{resource.name}</span>
											<span class="text-t3 truncate" title={resource.uri}>{resource.uri || '—'}</span>
											<span class="text-t4 truncate">{resource.mime_type || '—'}</span>
											<span class="text-right text-t4">{formatSize(resource.size)}</span>
										</div>
									{/each}
								</div>
								{/if}
							</div>
						{/each}
					{:else}
						<div class="py-8 text-center">
							<span class="text-sm font-mono text-t4">No tool data available for this scan</span>
						</div>
					{/if}
				</div>

			<!-- CODE GRAPH TAB -->
			{:else if activeTab === '__code_graph' && hasCodeGraph && codeGraphData}
				<div class="pt-4 anim-in">
					<div class="graph-split">
						<div class="graph-split-visual">
							<CodeGraphVisual
								codeGraph={codeGraphData}
								onNodeClick={handleGraphNodeClick}
								highlightedNodes={graphHighlightedNodes}
							/>
						</div>
						<div class="graph-split-chat">
							<CodeGraphChat
								scanId={scanId}
								stats={codeGraphStats}
								toolHandlers={codeGraphHandlers}
								selectedNode={graphSelectedNode}
								compact={true}
								nodeLabels={graphNodeLabels}
								onMentionedNodes={handleMentionedNodes}
							/>
						</div>
					</div>
				</div>

			<!-- CHECKER TAB -->
			{:else if activeDetail}
				<div class="pt-6 space-y-5 anim-in">
					<!-- Checker description -->
					<div class="space-y-2">
						<div class="flex items-center gap-3">
							<h3 class="text-base font-semibold text-t1 tracking-tight">
								{checkerLabels[activeDetail.id] ?? activeDetail.id}
							</h3>
							{#if activeDetail.findings_count > 0}
								<span class="text-xs font-mono font-semibold {sevTextColor(activeSev)}">
									{activeDetail.findings_count} finding{activeDetail.findings_count !== 1 ? 's' : ''}
								</span>
							{:else if activeDetail.status !== 'error'}
								<span class="text-xs font-mono text-clear/60">CLEAR</span>
							{/if}
							{#if activeDetail.status === 'error'}
								<span class="text-xs font-mono text-crit">ERROR</span>
							{/if}
						</div>
						<p class="text-sm text-t3 leading-relaxed max-w-3xl">
							{checkerDescriptions[activeDetail.id] ?? activeDetail.description}
						</p>
					</div>

					<!-- Error message -->
					{#if activeDetail.error}
						<div class="border border-crit/20 bg-crit/5 px-5 py-3">
							<p class="text-sm font-mono text-crit">{activeDetail.error}</p>
						</div>
					{/if}

					{#if activeDetail.id === 'infra_security' && activeDetail.security_questions?.length}
						<div class="space-y-3">
							<h4 class="text-xs font-mono font-semibold text-t4 tracking-wider">
								SECURITY QUESTIONS ({activeDetail.security_questions.length})
							</h4>
							<SecurityQA
								questions={activeDetail.security_questions}
								findings={activeFindings}
								onAskAI={openTriageFor}
								onDismiss={handleDismiss}
								onRestore={handleRestore}
							/>
						</div>
					{:else}
						<!-- What was checked -->
						<div class="space-y-2">
							<h4 class="text-xs font-mono font-semibold text-t4 tracking-wider">CHECKS PERFORMED</h4>
							<ul class="space-y-1.5">
								{#each activeDetail.checks as check}
									{#if check.startsWith('  ')}
										<li class="flex items-start gap-2 pl-5">
											<span class="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-t4"></span>
											<span class="text-xs font-mono text-t4 leading-relaxed">{check.trim()}</span>
										</li>
									{:else}
										<li class="flex items-start gap-2">
											<span class="text-t4 text-sm font-mono mt-[1px]">›</span>
											<span class="text-sm font-mono text-t3 leading-relaxed">{check}</span>
										</li>
									{/if}
								{/each}
							</ul>
							<p class="text-xs font-mono text-t4 pt-1">
								{activeDetail.items_checked} items analyzed · {activeDetail.status}
							</p>
						</div>

						<div class="border-t border-edge"></div>

						<!-- Findings -->
						{#if activeFindings.length > 0}
							<div class="space-y-3">
								<h4 class="text-xs font-mono font-semibold text-t4 tracking-wider">
									FINDINGS ({activeFindings.length})
								</h4>
								<FindingsList findings={activeFindings} onAskAI={openTriageFor} onDismiss={handleDismiss} onRestore={handleRestore} />
							</div>
						{:else if activeDetail.status !== 'error'}
							<div class="py-8 text-center">
								<span class="text-sm font-mono text-clear/60 tracking-wider">NO ISSUES DETECTED</span>
							</div>
						{/if}
					{/if}

					<!-- SBOM subsection (supply chain only) -->
					{#if activeDetail.id === 'supply_chain' && sbomEntries.length > 0}
						<div class="border-t border-edge"></div>
						<div class="space-y-4">
							<div class="flex items-center justify-between">
								<h4 class="text-xs font-mono font-semibold text-t4 tracking-wider">SOFTWARE BILL OF MATERIALS</h4>
								<button
									onclick={downloadSbom}
									class="flex items-center gap-2 px-3 py-1.5 text-xs font-mono font-medium text-blue border border-blue/30 rounded-sm transition-colors hover:bg-blue/10"
								>
									<svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
										<path stroke-linecap="round" stroke-linejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5M16.5 12L12 16.5m0 0L7.5 12m4.5 4.5V3" />
									</svg>
									DOWNLOAD SBOM
								</button>
							</div>

							<!-- Stats row -->
							<div class="flex items-center gap-8 text-sm font-mono">
								<div>
									<span class="text-2xl font-bold text-t1">{sbomEntries.length}</span>
									<span class="text-t4 ml-2">PACKAGE{sbomEntries.length !== 1 ? 'S' : ''}</span>
								</div>
								<div>
									<span class="text-2xl font-bold text-t1">{totalSbomDeps}</span>
									<span class="text-t4 ml-2">DEPENDENC{totalSbomDeps !== 1 ? 'IES' : 'Y'}</span>
								</div>
								<div>
									<span class="text-2xl font-bold {totalSbomVulns > 0 ? 'text-crit' : 'text-clear'}">{totalSbomVulns}</span>
									<span class="text-t4 ml-2">VULNERABILIT{totalSbomVulns !== 1 ? 'IES' : 'Y'}</span>
								</div>
							</div>

							<!-- Dependency table -->
							<div class="border border-edge rounded-sm overflow-hidden">
								<div class="grid grid-cols-[1fr_200px_100px_100px_120px] gap-4 px-4 py-2.5 bg-bg-raised text-xs font-mono font-semibold text-t4 tracking-wider border-b border-edge">
									<span>PACKAGE</span>
									<span>SERVER</span>
									<span class="text-right">DEPS</span>
									<span class="text-right">VULNS</span>
									<span class="text-right">FORMAT</span>
								</div>
								{#each sbomEntries as entry}
									<details class="group">
										<summary class="grid grid-cols-[1fr_200px_100px_100px_120px] gap-4 px-4 py-3 text-sm font-mono cursor-pointer transition-colors hover:bg-bg-raised/50 border-b border-edge/50 last:border-b-0 list-none">
											<span class="text-t1 font-medium truncate">{entry.package_name}<span class="text-t4 ml-1">@{entry.package_version}</span></span>
											<span class="text-t3 truncate">{entry.server_name}</span>
											<span class="text-right text-t3">{entry.dependency_count ?? 0}</span>
											<span class="text-right {(entry.vulnerability_count ?? 0) > 0 ? 'text-crit font-semibold' : 'text-t3'}">{entry.vulnerability_count ?? 0}</span>
											<span class="text-right text-t4 uppercase">{entry.format}</span>
										</summary>

										<!-- Expanded: vulnerabilities + dependency tree -->
										<div class="anim-expand bg-bg-deep border-b border-edge/50 px-4 py-4 max-h-80 overflow-y-auto space-y-4">
											{#if entry.vulnerabilities?.length > 0}
												<div>
													<div class="text-xs font-mono font-semibold text-crit tracking-wider mb-2">VULNERABILITIES ({entry.vulnerabilities.length})</div>
													{#each entry.vulnerabilities as vuln}
														<div class="flex items-start gap-3 py-2 border-b border-edge/30 last:border-b-0">
															<span class="shrink-0 px-1.5 py-0.5 text-[10px] font-mono font-bold bg-crit/15 text-crit rounded">{vuln.id}</span>
															<div class="min-w-0 flex-1">
																<div class="text-sm font-mono text-t2 truncate">{vuln.summary || 'No description'}</div>
																<div class="flex items-center gap-3 mt-1 text-xs font-mono text-t4">
																	{#if vuln.purl}
																		<span class="truncate max-w-[300px]">{vuln.purl}</span>
																	{/if}
																	{#if vuln.fixed_version}
																		<span class="text-clear">fix: {vuln.fixed_version}</span>
																	{/if}
																	{#if vuln.aliases?.length > 0}
																		<span>{vuln.aliases.join(', ')}</span>
																	{/if}
																</div>
															</div>
														</div>
													{/each}
												</div>
											{/if}
											{#if entry.sbom_data?.components}
												<div>
													<div class="text-xs font-mono font-semibold text-t4 tracking-wider mb-2">COMPONENTS ({(entry.sbom_data.components as Array<unknown>).length})</div>
													<div class="grid grid-cols-[1fr_120px_120px] gap-3 mb-1 text-xs font-mono font-semibold text-t4 tracking-wider">
														<span>NAME</span>
														<span>VERSION</span>
														<span>TYPE</span>
													</div>
													{#each (entry.sbom_data.components as Array<{name?: string; version?: string; type?: string}>) as comp}
														<div class="grid grid-cols-[1fr_120px_120px] gap-3 py-1 text-sm font-mono">
															<span class="text-t2 truncate">{comp.name ?? '—'}</span>
															<span class="text-t4">{comp.version ?? '—'}</span>
															<span class="text-t4">{comp.type ?? '—'}</span>
														</div>
													{/each}
												</div>
											{/if}
										</div>
									</details>
								{/each}
							</div>
						</div>
					{/if}
				</div>
			{/if}
		</div>

		<!-- Fallback when no checker details -->
		{#if checkerDetails.length === 0 && activeTab !== '__overview' && scan.status === 'completed'}
			{#if scan.findings && scan.findings.length > 0}
				<FindingsList findings={scan.findings} onAskAI={openTriageFor} onDismiss={handleDismiss} onRestore={handleRestore} />
			{:else}
				<div class="py-12 text-center">
					<span class="text-sm font-mono text-clear tracking-wider">NO SECURITY FINDINGS DETECTED</span>
				</div>
			{/if}
		{/if}
	{/if}
</div>

{#if scan && allFindings.length > 0}
	<TriageChat findings={allFindings} initialFinding={triageInitialFinding} />
{/if}

<style>
	.graph-split {
		display: flex;
		height: calc(100vh - 200px);
		min-height: 600px;
		max-height: 1200px;
		border: 1px solid var(--color-edge);
		border-radius: 8px;
		overflow: hidden;
		background: var(--color-bg-deep);
	}
	.graph-split-visual {
		flex: 0 0 65%;
		min-width: 0;
		display: flex;
		flex-direction: column;
	}
	.graph-split-chat {
		flex: 0 0 35%;
		min-width: 0;
		display: flex;
		flex-direction: column;
	}
</style>
