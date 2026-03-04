<script lang="ts">
	import { startScan } from '$lib/api';
	import { goto } from '$app/navigation';

	let repoUrl = $state('');
	let scanning = $state(false);
	let errorMessage = $state('');
	let llmJudgeEnabled = $state(true);

	let canScan = $derived(repoUrl.trim().length > 0);

	async function runScan() {
		scanning = true;
		errorMessage = '';

		try {
			const result = await startScan(repoUrl, { llm_judge_enabled: llmJudgeEnabled });
			goto(`/report/${result.id}`);
		} catch (err) {
			if (err instanceof Error) {
				errorMessage = err.message;
			} else {
				errorMessage = 'An unexpected error occurred.';
			}
		} finally {
			scanning = false;
		}
	}
</script>

<div class="mx-auto max-w-xl pt-20 space-y-8">
	<!-- Title -->
	<div class="anim-in">
		<h1 class="text-3xl font-bold tracking-tight text-t1">MCP Security Scanner</h1>
		<p class="mt-2 text-base text-t3">Evaluate the security posture of MCP servers</p>
	</div>

	<!-- Input -->
	<div class="anim-in space-y-4" style="animation-delay: 80ms">
		<div>
			<input
				type="url"
				bind:value={repoUrl}
				placeholder="https://github.com/org/mcp-server"
				class="w-full border border-edge bg-bg rounded-sm px-4 py-3 text-sm font-mono text-t1 placeholder-t4 focus:border-blue focus:outline-none transition-colors"
				onkeydown={(e) => { if (e.key === 'Enter' && canScan && !scanning) runScan(); }}
			/>
			<p class="mt-2 text-[11px] font-mono text-t4">Analyzes MCP server source code for security issues.</p>
		</div>

		<!-- Scan options -->
		<div class="flex items-center gap-3">
			<label class="flex items-center gap-2 cursor-pointer select-none">
				<button
					type="button"
					role="switch"
					aria-checked={llmJudgeEnabled}
					class="relative inline-flex h-5 w-9 shrink-0 rounded-full border border-edge transition-colors {llmJudgeEnabled ? 'bg-blue' : 'bg-bg-raised'}"
					onclick={() => llmJudgeEnabled = !llmJudgeEnabled}
				>
					<span class="pointer-events-none inline-block h-4 w-4 rounded-full bg-white shadow-sm transition-transform {llmJudgeEnabled ? 'translate-x-4' : 'translate-x-0'}"></span>
				</button>
				<span class="text-xs font-mono text-t3">LLM Judge</span>
			</label>
			<span class="text-[11px] font-mono text-t4">
				{llmJudgeEnabled ? 'AI evaluates ambiguous findings for accuracy' : 'Pattern matching only (faster, no API cost)'}
			</span>
		</div>

		<!-- Error -->
		{#if errorMessage}
			<div class="border border-crit/20 bg-crit/5 px-4 py-2">
				<p class="text-xs font-mono text-crit">{errorMessage}</p>
			</div>
		{/if}

		<!-- Scan button -->
		<button
			onclick={runScan}
			disabled={!canScan || scanning}
			class="w-full border border-blue bg-blue/10 rounded-sm px-6 py-3 text-sm font-mono font-semibold text-blue transition-all hover:bg-blue/20 focus:outline-none disabled:opacity-30 disabled:cursor-not-allowed"
		>
			{#if scanning}
				<span class="inline-flex items-center gap-2">
					<span class="h-3 w-3 rounded-full border-2 border-blue/30 border-t-blue animate-spin"></span>
					SCANNING
				</span>
			{:else}
				RUN SCAN
			{/if}
		</button>
	</div>
</div>
