<script lang="ts">
	import { onMount } from 'svelte';
	import { getApiKey, setApiKey, getSettings, updateSettings, type ScannerSettings } from '$lib/api';

	let settings = $state<ScannerSettings | null>(null);
	let saving = $state(false);
	let error = $state('');
	let success = $state('');
	let newApiKey = $state('');
	let newModel = $state('');
	let llmEnabled = $state(false);
	let scannerApiKey = $state(getApiKey());
	let apiKeySaved = $state(false);

	onMount(async () => {
		try {
			settings = await getSettings();
			newModel = settings.openrouter_model;
			llmEnabled = settings.llm_judge_enabled;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load settings';
		}
	});

	async function save() {
		saving = true;
		error = '';
		success = '';
		try {
			const updates: Partial<ScannerSettings> = {
				openrouter_model: newModel,
				llm_judge_enabled: llmEnabled,
			};
			if (newApiKey) {
				updates.openrouter_api_key = newApiKey;
			}
			settings = await updateSettings(updates);
			newApiKey = '';
			success = 'Settings saved successfully';
			setTimeout(() => (success = ''), 3000);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to save settings';
		} finally {
			saving = false;
		}
	}

	function saveScannerApiKey() {
		setApiKey(scannerApiKey);
		apiKeySaved = true;
		setTimeout(() => (apiKeySaved = false), 3000);
	}

	const popularModels = [
		'google/gemini-3.1-pro-preview',
		'google/gemini-2.5-pro-preview',
		'openai/gpt-4o',
		'openai/gpt-4o-mini',
		'meta-llama/llama-3.3-70b-instruct',
		'deepseek/deepseek-chat-v3-0324',
	];
</script>

<div class="mx-auto max-w-2xl">
	<h1 class="mb-6 text-2xl font-bold text-t1">Scanner Settings</h1>

	{#if error}
		<div class="mb-4 rounded-lg border border-red/20 bg-red/5 px-4 py-3 text-sm text-red">{error}</div>
	{/if}

	{#if success}
		<div class="mb-4 rounded-lg border border-green/20 bg-green/5 px-4 py-3 text-sm text-green">{success}</div>
	{/if}

	{#if settings}
		<div class="space-y-6">
			<div class="rounded-xl border border-edge bg-bg-card p-6">
				<h2 class="text-lg font-semibold text-t1">Scanner API Key</h2>
				<p class="mt-1 text-sm text-t3">
					Authentication key for the scanner API. Stored locally in your browser.
				</p>
				<div class="mt-4">
					<input
						type="password"
						bind:value={scannerApiKey}
						placeholder="Enter API key"
						class="w-full rounded-lg border border-edge bg-bg-deep px-3 py-2 text-sm text-t1 placeholder-t4 focus:border-blue focus:outline-none"
					/>
				</div>
				<button
					onclick={saveScannerApiKey}
					class="mt-3 rounded-lg bg-blue px-4 py-2 text-sm font-medium text-white transition-opacity hover:opacity-90"
				>
					{apiKeySaved ? 'Saved!' : 'Save API Key'}
				</button>
			</div>

			<div class="rounded-xl border border-edge bg-bg-card p-6">
				<div class="flex items-center justify-between">
					<div>
						<h2 class="text-lg font-semibold text-t1">LLM-as-Judge</h2>
						<p class="mt-1 text-sm text-t3">
							When enabled, an LLM evaluates tool descriptions flagged by pattern detection
							for deeper semantic analysis.
						</p>
					</div>
					<button
						aria-label="Toggle LLM-as-Judge"
						onclick={() => (llmEnabled = !llmEnabled)}
						class="relative h-6 w-11 rounded-full transition-colors {llmEnabled ? 'bg-blue' : 'bg-t4/30'}"
					>
						<span
							class="absolute left-0.5 top-0.5 h-5 w-5 rounded-full bg-white transition-transform {llmEnabled ? 'translate-x-5' : ''}"
						></span>
					</button>
				</div>
			</div>

			<div class="rounded-xl border border-edge bg-bg-card p-6">
				<h2 class="mb-4 text-lg font-semibold text-t1">OpenRouter Configuration</h2>
				<div class="space-y-4">
					<div>
						<label for="api-key" class="mb-1 block text-sm font-medium text-t2">API Key</label>
						<p class="mb-2 text-xs text-t3">
							Current: <code class="rounded bg-bg-deep px-1.5 py-0.5">{settings.openrouter_api_key || 'Not set'}</code>
						</p>
						<input
							id="api-key"
							type="password"
							bind:value={newApiKey}
							placeholder="Enter new API key (leave blank to keep current)"
							class="w-full rounded-lg border border-edge bg-bg-deep px-3 py-2 text-sm text-t1 placeholder-t4 focus:border-blue focus:outline-none"
						/>
					</div>
					<div>
						<label for="model" class="mb-1 block text-sm font-medium text-t2">Model</label>
						<input
							id="model"
							type="text"
							bind:value={newModel}
							placeholder="e.g., google/gemini-3.1-pro-preview"
							list="model-suggestions"
							class="w-full rounded-lg border border-edge bg-bg-deep px-3 py-2 text-sm text-t1 placeholder-t4 focus:border-blue focus:outline-none"
						/>
						<datalist id="model-suggestions">
							{#each popularModels as model}
								<option value={model}></option>
							{/each}
						</datalist>
					</div>
				</div>
			</div>

			<button
				onclick={save}
				disabled={saving}
				class="w-full rounded-lg bg-blue px-4 py-2.5 text-sm font-medium text-white transition-opacity hover:opacity-90 disabled:opacity-50"
			>
				{saving ? 'Saving...' : 'Save Settings'}
			</button>
		</div>
	{:else if !error}
		<div class="flex justify-center py-12">
			<div class="h-6 w-6 animate-spin rounded-full border-2 border-blue border-t-transparent"></div>
		</div>
	{/if}
</div>
