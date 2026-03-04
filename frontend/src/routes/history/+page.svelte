<script lang="ts">
	import { goto } from '$app/navigation';
	import { getHistory, deleteScan, type PaginatedScans, type ScanListItem } from '$lib/api';

	let loading = $state(true);
	let error = $state('');
	let data: PaginatedScans | null = $state(null);
	let currentPage = $state(1);
	let deleting: string | null = $state(null);

	let totalPages = $derived(data ? Math.ceil(data.total / data.per_page) : 0);

	async function load(page: number) {
		loading = true;
		error = '';
		try {
			data = await getHistory(page);
			currentPage = page;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to load history';
		} finally {
			loading = false;
		}
	}

	async function handleDelete(event: MouseEvent, scanId: string) {
		event.stopPropagation();
		if (!confirm('Delete this scan?')) return;
		deleting = scanId;
		try {
			await deleteScan(scanId);
			await load(currentPage);
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to delete scan';
		} finally {
			deleting = null;
		}
	}

	function navigateToReport(scanId: string) {
		goto(`/report/${scanId}`);
	}

	function formatDate(iso: string): string {
		const d = new Date(iso);
		return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) +
			' ' + d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
	}

	function findingsTotal(scan: ScanListItem): number {
		return scan.summary?.total ?? 0;
	}

	function gradeColor(grade: string | null): string {
		switch (grade) {
			case 'A': return 'text-clear';
			case 'B': return 'text-low';
			case 'C': return 'text-med';
			case 'D': return 'text-high';
			case 'F': return 'text-crit';
			default: return 'text-t4';
		}
	}

	function scoreBarColor(score: number): string {
		if (score >= 80) return 'bg-clear';
		if (score >= 60) return 'bg-low';
		if (score >= 40) return 'bg-med';
		if (score >= 20) return 'bg-high';
		return 'bg-crit';
	}

	function repoName(url: string | null | undefined): string {
		if (!url) return '';
		try {
			const parts = new URL(url).pathname.split('/').filter(Boolean);
			if (parts.length >= 2) return parts.slice(-2).join('/');
			return parts[parts.length - 1] || url;
		} catch {
			return url;
		}
	}

	load(1);
</script>

<div class="space-y-5">
	<div class="flex items-center justify-between">
		<div>
			<h1 class="text-lg font-semibold text-t1 tracking-tight">Scan History</h1>
			<p class="text-sm font-mono text-t4 mt-0.5">
				{#if data}{data.total} scan{data.total !== 1 ? 's' : ''}{:else}Loading{/if}
			</p>
		</div>
		<a href="/" class="text-sm font-mono font-medium text-blue transition-colors hover:text-blue-dim">
			NEW SCAN
		</a>
	</div>

	{#if error}
		<div class="border border-crit/20 bg-crit/5 px-4 py-2">
			<p class="text-xs font-mono text-crit">{error}</p>
		</div>
	{/if}

	{#if loading}
		<div class="flex items-center justify-center py-24">
			<div class="flex items-center gap-3">
				<div class="h-3 w-3 rounded-full bg-blue anim-pulse"></div>
				<span class="text-xs font-mono text-t3 tracking-wider">LOADING</span>
			</div>
		</div>
	{:else if data && data.scans.length > 0}
		<!-- Table header -->
		<div class="grid grid-cols-[48px_70px_1fr_100px_70px_32px] gap-4 items-center px-3 text-xs font-mono text-t4 tracking-wider border-b border-edge pb-2">
			<span>GRADE</span>
			<span>SCORE</span>
			<span>SCAN</span>
			<span class="text-right">FINDINGS</span>
			<span class="text-right">STATUS</span>
			<span></span>
		</div>

		<!-- Rows -->
		<div class="space-y-0">
			{#each data.scans as scan, i (scan.id)}
				<div
					class="group grid grid-cols-[48px_70px_1fr_100px_70px_32px] gap-4 items-center px-3 py-3 cursor-pointer border-b border-edge/50 transition-colors hover:bg-bg-raised anim-in"
					style="animation-delay: {Math.min(i * 30, 300)}ms"
					onclick={() => navigateToReport(scan.id)}
					role="button"
					tabindex="0"
					onkeydown={(e) => e.key === 'Enter' && navigateToReport(scan.id)}
				>
					<!-- Grade -->
					<span class="text-xl font-mono font-bold {gradeColor(scan.grade)}">
						{scan.grade ?? '-'}
					</span>

					<!-- Score -->
					<div class="flex flex-col gap-1">
						<span class="text-sm font-mono text-t3">{scan.overall_score ?? '-'}</span>
						<div class="h-1 w-full rounded-sm bg-edge overflow-hidden">
							{#if scan.overall_score !== null}
								<div
									class="h-full rounded-sm {scoreBarColor(scan.overall_score)}"
									style="width: {scan.overall_score}%"
								></div>
							{/if}
						</div>
					</div>

					<!-- ID + repo + date -->
					<div class="min-w-0">
						{#if scan.repo_url}
							<span class="text-sm font-mono text-t1 font-medium">{repoName(scan.repo_url)}</span>
							<span class="text-xs font-mono text-t4 ml-2">{scan.id.slice(0, 8)}</span>
						{:else}
							<span class="text-sm font-mono text-t2">{scan.id.slice(0, 8)}</span>
						{/if}
						<span class="text-xs font-mono text-t4 ml-2">{formatDate(scan.created_at)}</span>
					</div>

					<!-- Findings -->
					<div class="text-right">
						{#if findingsTotal(scan) > 0}
							<span class="text-sm font-mono font-semibold text-high">{findingsTotal(scan)}</span>
						{:else if scan.status === 'completed'}
							<span class="text-xs font-mono text-clear/60">clear</span>
						{/if}
					</div>

					<!-- Status -->
					<span class="text-right text-xs font-mono tracking-wider
						{scan.status === 'completed' ? 'text-clear/60' : scan.status === 'failed' ? 'text-crit/60' : 'text-t4'}">
						{scan.status === 'completed' ? 'OK' : scan.status.toUpperCase()}
					</span>

					<!-- Delete -->
					<button
						class="opacity-0 group-hover:opacity-100 p-1 text-t4 transition-all hover:text-crit"
						disabled={deleting === scan.id}
						onclick={(e) => handleDelete(e, scan.id)}
						title="Delete"
					>
						<svg class="h-3.5 w-3.5" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
						</svg>
					</button>
				</div>
			{/each}
		</div>

		<!-- Pagination -->
		{#if totalPages > 1}
			<div class="flex items-center justify-between pt-2 text-xs font-mono text-t4">
				<span>{currentPage}/{totalPages}</span>
				<div class="flex gap-3">
					<button
						class="transition-colors hover:text-t1 disabled:opacity-30"
						disabled={currentPage <= 1}
						onclick={() => load(currentPage - 1)}
					>PREV</button>
					<button
						class="transition-colors hover:text-t1 disabled:opacity-30"
						disabled={currentPage >= totalPages}
						onclick={() => load(currentPage + 1)}
					>NEXT</button>
				</div>
			</div>
		{/if}
	{:else if data}
		<div class="py-16 text-center">
			<p class="text-xs font-mono text-t4 tracking-wider">NO SCANS YET</p>
			<a href="/" class="inline-block mt-4 text-xs font-mono text-blue transition-colors hover:text-blue-dim">
				START A SCAN
			</a>
		</div>
	{/if}
</div>
