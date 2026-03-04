<script lang="ts">
	import type { Finding } from '$lib/api';
	import SeverityBadge from './SeverityBadge.svelte';

	interface Props {
		findings: Finding[];
		onAskAI?: (finding: Finding) => void;
		onDismiss?: (finding: Finding, dismissedAs: string, reason: string) => void;
		onRestore?: (finding: Finding) => void;
	}

	let { findings, onAskAI, onDismiss, onRestore }: Props = $props();

	let expandedIds: Set<string> = $state(new Set());
	let dismissingIds: Set<string> = $state(new Set());
	let dismissForm: Record<string, { status: string; reason: string }> = $state({});

	function toggleExpand(id: string) {
		const next = new Set(expandedIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		expandedIds = next;
	}

	function startDismiss(id: string) {
		const next = new Set(dismissingIds);
		next.add(id);
		dismissingIds = next;
		dismissForm[id] = { status: 'false_positive', reason: '' };
	}

	function cancelDismiss(id: string) {
		const next = new Set(dismissingIds);
		next.delete(id);
		dismissingIds = next;
		delete dismissForm[id];
	}

	function confirmDismiss(finding: Finding) {
		const form = dismissForm[finding.id];
		if (!form || !form.reason.trim()) return;
		onDismiss?.(finding, form.status, form.reason.trim());
		cancelDismiss(finding.id);
	}

	function formatDismissStatus(status: string): string {
		return status.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
	}
</script>

<div class="space-y-0">
	{#each findings as finding, i (finding.id)}
		{@const isExpanded = expandedIds.has(finding.id)}
		{@const isLast = i === findings.length - 1}
		{@const isDismissed = !!finding.dismissed_as}
		{@const isDismissing = dismissingIds.has(finding.id)}

		<!-- Finding row -->
		<button
			class="group flex w-full items-center gap-3 text-left py-2 transition-colors hover:bg-bg-raised/50 -mx-2 px-2 rounded {isDismissed ? 'opacity-50' : ''}"
			onclick={() => toggleExpand(finding.id)}
		>
			<!-- Tree connector -->
			<span class="font-mono text-t4 text-sm shrink-0 w-4 text-center select-none">
				{isLast ? '└' : '├'}
			</span>

			<SeverityBadge severity={finding.severity} />

			<span class="flex-1 text-sm text-t2 truncate font-mono {isDismissed ? 'line-through' : ''}">{finding.title}</span>

			{#if isDismissed}
				<span class="shrink-0 text-xs font-mono px-1.5 py-0.5 rounded bg-t4/10 text-t4">{formatDismissStatus(finding.dismissed_as!)}</span>
			{/if}

			{#if finding.source_file}
				<span class="hidden sm:inline text-xs font-mono text-t4 truncate max-w-[200px]">{finding.source_file}{finding.source_line ? `:${finding.source_line}` : ''}</span>
			{:else if finding.location}
				<span class="hidden sm:inline text-xs font-mono text-t4 truncate max-w-[200px]">{finding.location}</span>
			{/if}
		</button>

		<!-- Expanded detail -->
		{#if isExpanded}
			<div class="anim-expand ml-7 mb-3 border-l border-edge pl-5 py-4 space-y-4">
				{#if isDismissed && finding.dismissed_reason}
					<div class="border border-t4/20 bg-t4/5 px-4 py-2.5 rounded">
						<span class="text-xs font-mono font-semibold text-t4 tracking-wider">{formatDismissStatus(finding.dismissed_as!)}</span>
						<p class="text-sm text-t3 mt-1 italic">{finding.dismissed_reason}</p>
					</div>
				{/if}

				<p class="text-sm text-t2 leading-relaxed">{finding.description}</p>

				{#if finding.remediation}
					<div>
						<span class="text-xs font-mono font-semibold text-clear tracking-wider">REMEDIATION</span>
						<p class="text-sm text-t2 leading-relaxed mt-1">{finding.remediation}</p>
					</div>
				{/if}

				{#if finding.evidence}
					<div>
						<span class="text-xs font-mono font-semibold text-t3 tracking-wider">EVIDENCE</span>
						<pre class="mt-1 overflow-x-auto rounded border border-edge bg-bg-deep p-3 text-xs text-t3 font-mono leading-relaxed">{finding.evidence}</pre>
					</div>
				{/if}

				<div class="flex flex-wrap items-center gap-3 pt-1">
					{#if finding.cwe_id}
						<span class="text-xs font-mono font-medium text-blue">{finding.cwe_id}</span>
					{/if}
					{#if finding.source_file}
						<span class="text-xs font-mono font-medium text-amber-400">{finding.source_file}{finding.source_line ? `:${finding.source_line}` : ''}</span>
					{/if}
					{#if finding.location}
						<span class="text-xs font-mono text-t4">{finding.location}</span>
					{/if}
					<span class="text-xs font-mono text-t4">{finding.checker}</span>

					<div class="ml-auto flex items-center gap-2">
						{#if onAskAI}
							<button
								class="text-xs font-mono font-semibold px-2 py-0.5 rounded border border-blue/30 text-blue hover:bg-blue/10 transition-colors"
								onclick={(e) => { e.stopPropagation(); onAskAI(finding); }}
							>ASK AI</button>
						{/if}

						{#if isDismissed && onRestore}
							<button
								class="text-xs font-mono font-semibold px-2 py-0.5 rounded border border-clear/30 text-clear hover:bg-clear/10 transition-colors"
								onclick={(e) => { e.stopPropagation(); onRestore(finding); }}
							>RESTORE</button>
						{:else if !isDismissed && onDismiss}
							<button
								class="text-xs font-mono font-semibold px-2 py-0.5 rounded border border-blue/30 text-blue hover:bg-blue/10 transition-colors"
								onclick={(e) => { e.stopPropagation(); startDismiss(finding.id); }}
							>DISMISS</button>
						{/if}
					</div>
				</div>

				<!-- Inline dismiss form -->
				{#if isDismissing}
					<div class="border border-edge rounded bg-bg-raised p-4 space-y-3">
						<div class="flex gap-4">
							<label class="flex items-center gap-2 text-sm font-mono text-t2 cursor-pointer">
								<input type="radio" bind:group={dismissForm[finding.id].status} value="false_positive" class="accent-blue" />
								False Positive
							</label>
							<label class="flex items-center gap-2 text-sm font-mono text-t2 cursor-pointer">
								<input type="radio" bind:group={dismissForm[finding.id].status} value="accepted_risk" class="accent-blue" />
								Accepted Risk
							</label>
							<label class="flex items-center gap-2 text-sm font-mono text-t2 cursor-pointer">
								<input type="radio" bind:group={dismissForm[finding.id].status} value="mitigated" class="accent-blue" />
								Mitigated
							</label>
						</div>
						<textarea
							class="w-full bg-bg-deep border border-edge rounded px-3 py-2 text-sm font-mono text-t2 placeholder:text-t4 resize-none focus:outline-none focus:border-blue/50"
							rows="2"
							placeholder="Reason for dismissal..."
							bind:value={dismissForm[finding.id].reason}
						></textarea>
						<div class="flex gap-2">
							<button
								class="text-xs font-mono font-semibold px-3 py-1 rounded border border-blue/30 text-blue hover:bg-blue/10 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
								disabled={!dismissForm[finding.id]?.reason?.trim()}
								onclick={(e) => { e.stopPropagation(); confirmDismiss(finding); }}
							>CONFIRM</button>
							<button
								class="text-xs font-mono font-semibold px-3 py-1 rounded border border-t4/30 text-t4 hover:bg-t4/10 transition-colors"
								onclick={(e) => { e.stopPropagation(); cancelDismiss(finding.id); }}
							>CANCEL</button>
						</div>
					</div>
				{/if}

				{#if finding.llm_analysis}
					<div class="border-l-2 border-blue/30 pl-3 mt-2">
						<span class="text-xs font-mono font-semibold text-blue tracking-wider">AI ANALYSIS</span>
						<p class="text-sm text-t3 leading-relaxed mt-1 italic">{finding.llm_analysis}</p>
					</div>
				{/if}
			</div>
		{/if}
	{/each}
</div>
