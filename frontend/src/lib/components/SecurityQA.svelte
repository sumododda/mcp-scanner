<script lang="ts">
	import type { Finding, SecurityQuestion } from '$lib/api';
	import FindingsList from './FindingsList.svelte';
	import SeverityBadge from './SeverityBadge.svelte';

	interface Props {
		questions: SecurityQuestion[];
		findings: Finding[];
		onAskAI?: (finding: Finding) => void;
		onDismiss?: (finding: Finding, dismissedAs: string, reason: string) => void;
		onRestore?: (finding: Finding) => void;
	}

	let { questions, findings, onAskAI, onDismiss, onRestore }: Props = $props();

	let expandedIds: Set<string> = $state(new Set());
	let initialized = false;

	$effect(() => {
		if (!initialized && questions.length > 0) {
			initialized = true;
		}
	});

	function toggleExpand(id: string) {
		const next = new Set(expandedIds);
		if (next.has(id)) next.delete(id);
		else next.add(id);
		expandedIds = next;
	}

	// Map question IDs to CWE + location prefix for matching findings
	const Q_TO_CWE: Record<string, { cwe: string; locPrefix?: string }> = {
		http_transport: { cwe: 'CWE-319', locPrefix: 'config:' },
		plaintext_secrets_config: { cwe: 'CWE-798', locPrefix: 'config:' },
		elevated_privileges: { cwe: 'CWE-250' },
		auth_middleware: { cwe: 'CWE-306' },
		input_validation: { cwe: 'CWE-20' },
		http_in_source: { cwe: 'CWE-319', locPrefix: 'source:' },
		dangerous_operations: { cwe: 'CWE-78' },
		insecure_deserialization: { cwe: 'CWE-502' },
		weak_crypto: { cwe: 'CWE-328' },
		insecure_tls: { cwe: 'CWE-295' },
		hardcoded_secrets_source: { cwe: 'CWE-798', locPrefix: 'source:' },
		error_handling: { cwe: 'CWE-755' },
		file_access: { cwe: 'CWE-22' },
		rate_limiting: { cwe: 'CWE-770' },
	};

	function findingsForQuestion(q: SecurityQuestion): Finding[] {
		// First try explicit finding_ids
		if (q.finding_ids && q.finding_ids.length > 0) {
			const idSet = new Set(q.finding_ids);
			return findings.filter(f => idSet.has(f.id));
		}
		// Fall back to CWE + location matching
		const criteria = Q_TO_CWE[q.id];
		if (!criteria) return [];
		return findings.filter(f => {
			if (f.cwe_id !== criteria.cwe) return false;
			if (criteria.locPrefix && !f.location.startsWith(criteria.locPrefix)) return false;
			return true;
		});
	}

	function hasExpandableContent(q: SecurityQuestion, qFindings: Finding[]): boolean {
		return !!(q.detail || qFindings.length > 0 || q.status === 'issue');
	}
</script>

<div class="space-y-0">
	{#each questions as q (q.id)}
		{@const isExpanded = expandedIds.has(q.id)}
		{@const qFindings = findingsForQuestion(q)}
		{@const expandable = hasExpandableContent(q, qFindings)}

		<div class="border-b border-edge last:border-b-0">
			<button
				class="flex w-full items-start gap-3 text-left py-3 px-2 -mx-2 rounded transition-colors {expandable ? 'hover:bg-bg-raised/50 cursor-pointer' : 'cursor-default'}"
				onclick={() => expandable && toggleExpand(q.id)}
			>
				<span class="mt-0.5 text-sm shrink-0 font-mono">
					{#if q.status === 'clear'}
						<span class="text-clear">{@html '&#x2713;'}</span>
					{:else if q.status === 'issue'}
						<span class="text-warn">{@html '&#x26A0;'}</span>
					{:else}
						<span class="text-t4">{@html '&#x2014;'}</span>
					{/if}
				</span>

				<div class="flex-1 min-w-0">
					<span class="text-sm font-mono text-t2">{q.question}</span>
					<p class="text-xs font-mono text-t4 mt-0.5">{q.answer}</p>
				</div>

				<div class="flex items-center gap-2 shrink-0">
					{#if q.severity}
						<SeverityBadge severity={q.severity} />
					{/if}
					<span class="text-xs font-mono text-t4">
						{q.items_checked} {q.items_checked_label}
					</span>
					{#if expandable}
						<span class="text-xs text-t4 transition-transform duration-150 {isExpanded ? 'rotate-90' : ''}">
							{@html '&#x25B6;'}
						</span>
					{/if}
				</div>
			</button>

			{#if isExpanded}
				<div class="pl-7 pb-3 space-y-3">
					{#if q.detail}
						<div class="prose prose-sm prose-invert max-w-none text-xs font-mono text-t3 leading-relaxed security-detail">
							{@html renderMarkdown(q.detail)}
						</div>
					{:else if q.status === 'issue' && qFindings.length === 0}
						<p class="text-xs font-mono text-t4 italic">No detailed analysis available. Re-run scan with LLM Judge enabled for detailed explanations.</p>
					{/if}
					{#if qFindings.length > 0}
						<FindingsList findings={qFindings} {onAskAI} {onDismiss} {onRestore} />
					{/if}
				</div>
			{/if}
		</div>
	{/each}
</div>

<script lang="ts" context="module">
	function renderMarkdown(md: string): string {
		let html = md
			.replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
			.replace(/`([^`]+)`/g, '<code class="bg-bg-raised px-1 py-0.5 rounded text-accent">$1</code>')
			.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
			.replace(/\*([^*]+)\*/g, '<em>$1</em>')
			.replace(/^### (.+)$/gm, '<h4 class="text-xs font-bold text-t2 mt-2 mb-1">$1</h4>')
			.replace(/^## (.+)$/gm, '<h3 class="text-sm font-bold text-t1 mt-3 mb-1">$1</h3>')
			.replace(/^- (.+)$/gm, '<li class="ml-4 list-disc">$1</li>')
			.replace(/^\d+\. (.+)$/gm, '<li class="ml-4 list-decimal">$1</li>')
			.replace(/\n\n/g, '</p><p class="mt-1.5">')
			.replace(/\n/g, '<br/>');
		return `<p class="mt-1.5">${html}</p>`;
	}
</script>

<style>
	.security-detail :global(pre) {
		background: var(--bg-raised, #1a1a2e);
		border-radius: 4px;
		padding: 8px 12px;
		margin: 4px 0;
		overflow-x: auto;
	}
	.security-detail :global(code) {
		font-size: 0.7rem;
	}
	.security-detail :global(h3),
	.security-detail :global(h4) {
		margin-top: 8px;
	}
	.security-detail :global(li) {
		margin: 2px 0;
	}
</style>
