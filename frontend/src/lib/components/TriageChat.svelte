<script lang="ts">
	import type { Finding, TriageChatMessage } from '$lib/api';
	import { streamTriageChat } from '$lib/api';
	import SeverityBadge from './SeverityBadge.svelte';

	interface Props {
		findings: Finding[];
		initialFinding?: Finding | null;
	}

	let { findings, initialFinding = null }: Props = $props();

	let open = $state(false);
	let selectedFinding: Finding | null = $state(null);
	let messages: TriageChatMessage[] = $state([]);
	let input = $state('');
	let streaming = $state(false);
	let streamBuffer = $state('');
	let error = $state('');
	let abortController: AbortController | null = $state(null);
	let messagesEnd: HTMLDivElement | undefined = $state();
	let inputEl: HTMLTextAreaElement | undefined = $state();

	// When initialFinding is set externally (e.g. from ASK AI button), open the drawer
	$effect(() => {
		if (initialFinding) {
			selectFinding(initialFinding);
			open = true;
		}
	});

	function scrollToBottom() {
		requestAnimationFrame(() => messagesEnd?.scrollIntoView({ behavior: 'smooth' }));
	}

	function toggle() {
		open = !open;
		if (open) {
			requestAnimationFrame(() => inputEl?.focus());
		}
	}

	function close() {
		open = false;
	}

	function selectFinding(f: Finding) {
		if (selectedFinding?.id === f.id) return;
		// Reset conversation when switching findings
		abortController?.abort();
		selectedFinding = f;
		messages = [];
		streamBuffer = '';
		streaming = false;
		error = '';
		abortController = null;
	}

	function send(text: string) {
		if (!text.trim() || streaming || !selectedFinding) return;
		const userMsg = text.trim();
		input = '';
		error = '';
		messages = [...messages, { role: 'user', content: userMsg }];
		streaming = true;
		streamBuffer = '';
		scrollToBottom();

		const history = messages.filter((m) => m.role !== 'user' || m.content !== userMsg);

		abortController = streamTriageChat(
			selectedFinding.id,
			userMsg,
			history,
			(token) => {
				streamBuffer += token;
				scrollToBottom();
			},
			() => {
				messages = [...messages, { role: 'assistant', content: streamBuffer }];
				streamBuffer = '';
				streaming = false;
				abortController = null;
				scrollToBottom();
			},
			(err) => {
				error = err;
				streaming = false;
				if (streamBuffer) {
					messages = [...messages, { role: 'assistant', content: streamBuffer }];
					streamBuffer = '';
				}
				abortController = null;
			}
		);
	}

	function stop() {
		abortController?.abort();
		if (streamBuffer) {
			messages = [...messages, { role: 'assistant', content: streamBuffer }];
			streamBuffer = '';
		}
		streaming = false;
		abortController = null;
	}

	function handleKeydown(e: KeyboardEvent) {
		if (e.key === 'Enter' && !e.shiftKey) {
			e.preventDefault();
			send(input);
		}
	}

	function handleBackdropClick(e: MouseEvent) {
		if (e.target === e.currentTarget) close();
	}

	const quickActions = [
		{ label: 'True or false positive?', icon: '?', prompt: 'Is this finding a true positive or a false positive? Explain your reasoning based on the evidence and tool definition.' },
		{ label: 'Show attack scenario', icon: '!', prompt: 'Describe a realistic attack scenario where this finding could be exploited. Include the attack chain and potential impact.' },
		{ label: 'How to remediate', icon: '>', prompt: 'What specific steps should be taken to remediate this finding? Be concrete and actionable.' },
	];

	let sevColor = $derived.by(() => {
		if (!selectedFinding) return 'blue';
		switch (selectedFinding.severity) {
			case 'critical': return 'crit';
			case 'high': return 'high';
			case 'medium': return 'med';
			case 'low': return 'low';
			default: return 'blue';
		}
	});

	$effect(() => {
		function onEsc(e: KeyboardEvent) {
			if (e.key === 'Escape' && open) close();
		}
		document.addEventListener('keydown', onEsc);
		return () => {
			document.removeEventListener('keydown', onEsc);
			abortController?.abort();
		};
	});
</script>

<!-- Floating trigger pill -->
<button
	class="triage-fab"
	class:triage-fab-open={open}
	onclick={toggle}
	aria-label={open ? 'Close AI Triage' : 'Open AI Triage'}
>
	<span class="triage-fab-glow"></span>
	<span class="triage-fab-inner">
		{#if open}
			<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
			</svg>
		{:else}
			<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
				<path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
				<path stroke-linecap="round" stroke-linejoin="round" d="M18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
			</svg>
			<span class="text-xs font-semibold tracking-wider">AI</span>
		{/if}
	</span>
</button>

<!-- Drawer overlay -->
{#if open}
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<div class="fixed inset-0 z-40" onclick={handleBackdropClick}>
		<div class="absolute inset-0 bg-black/40 anim-fade-in"></div>
	</div>

	<div class="triage-drawer anim-slide-in">
		<!-- Header -->
		<div class="triage-header">
			<div class="flex items-center gap-2.5">
				<div class="triage-header-icon">
					<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09z" />
					</svg>
				</div>
				<span class="text-xs font-mono font-semibold text-t1 tracking-widest">AI TRIAGE</span>
			</div>
			<button
				class="text-t4 hover:text-t1 transition-colors p-1 rounded hover:bg-bg-raised"
				onclick={close}
				aria-label="Close"
			>
				<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
					<path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
				</svg>
			</button>
		</div>

		<!-- Finding selector -->
		<div class="triage-finding-selector">
			{#if selectedFinding}
				<div class="flex items-center gap-2 min-w-0">
					<SeverityBadge severity={selectedFinding.severity} />
					<span class="text-xs font-mono text-t2 truncate">{selectedFinding.title}</span>
				</div>
			{/if}
			<details class="triage-picker">
				<summary class="triage-picker-trigger">
					{#if selectedFinding}
						<span class="text-[10px] font-mono text-t4 hover:text-t2 transition-colors cursor-pointer">SWITCH</span>
					{:else}
						<span class="text-xs font-mono text-t3 hover:text-t1 transition-colors cursor-pointer">Select a finding to analyze...</span>
					{/if}
				</summary>
				<div class="triage-picker-dropdown">
					{#each findings as f (f.id)}
						<button
							class="triage-picker-item"
							class:triage-picker-item-active={selectedFinding?.id === f.id}
							onclick={() => { selectFinding(f); }}
						>
							<SeverityBadge severity={f.severity} />
							<span class="flex-1 text-xs font-mono text-t2 truncate">{f.title}</span>
						</button>
					{/each}
					{#if findings.length === 0}
						<div class="px-3 py-4 text-xs font-mono text-t4 text-center">No findings in this scan</div>
					{/if}
				</div>
			</details>
		</div>

		<!-- Chat area -->
		<div class="triage-messages">
			{#if !selectedFinding}
				<!-- No finding selected state -->
				<div class="flex flex-col items-center justify-center h-full gap-3 px-6">
					<div class="w-10 h-10 rounded-full border border-edge-light flex items-center justify-center">
						<svg class="w-5 h-5 text-t4" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M15.042 21.672L13.684 16.6m0 0l-2.51 2.225.569-9.47 5.227 7.917-3.286-.672zM12 2.25V4.5m5.834.166l-1.591 1.591M20.25 10.5H18M7.757 14.743l-1.59 1.59M6 10.5H3.75m4.007-4.243l-1.59-1.59" />
						</svg>
					</div>
					<p class="text-xs font-mono text-t4 text-center leading-relaxed">
						Select a finding above<br/>to start triaging
					</p>
				</div>

			{:else if messages.length === 0 && !streaming}
				<!-- Quick actions -->
				<div class="flex flex-col gap-2 pt-3 px-1">
					<p class="text-[10px] font-mono text-t4 uppercase tracking-widest mb-1 px-1">Quick analysis</p>
					{#each quickActions as action}
						<button
							class="triage-quick-action"
							onclick={() => send(action.prompt)}
						>
							<span class="triage-quick-action-icon">{action.icon}</span>
							<span>{action.label}</span>
						</button>
					{/each}
				</div>
			{:else}
				<!-- Messages -->
				{#each messages as msg, i}
					{#if msg.role === 'user'}
						<div class="flex justify-end anim-msg" style="animation-delay: {i * 30}ms">
							<div class="triage-msg-user">
								<p>{msg.content}</p>
							</div>
						</div>
					{:else}
						<div class="flex justify-start anim-msg" style="animation-delay: {i * 30}ms">
							<div class="triage-msg-ai">
								<p>{msg.content}</p>
							</div>
						</div>
					{/if}
				{/each}

				{#if streaming && streamBuffer}
					<div class="flex justify-start">
						<div class="triage-msg-ai">
							<p>{streamBuffer}<span class="triage-cursor"></span></p>
						</div>
					</div>
				{:else if streaming}
					<div class="flex justify-start">
						<div class="triage-msg-ai triage-msg-thinking">
							<span class="triage-dot"></span>
							<span class="triage-dot" style="animation-delay: 150ms"></span>
							<span class="triage-dot" style="animation-delay: 300ms"></span>
						</div>
					</div>
				{/if}

				{#if error}
					<div class="triage-msg-error">
						<svg class="w-3.5 h-3.5 shrink-0 text-crit" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
							<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
						</svg>
						<p>{error}</p>
					</div>
				{/if}
			{/if}

			<div bind:this={messagesEnd}></div>
		</div>

		<!-- Input bar -->
		{#if selectedFinding}
			<div class="triage-input-bar">
				<div class="triage-input-wrap">
					<textarea
						bind:this={inputEl}
						class="triage-input"
						rows="1"
						placeholder="Ask about this finding..."
						bind:value={input}
						onkeydown={handleKeydown}
						disabled={streaming}
					></textarea>
					{#if streaming}
						<button class="triage-btn-stop" onclick={stop} aria-label="Stop">
							<svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
								<rect x="6" y="6" width="12" height="12" rx="2" />
							</svg>
						</button>
					{:else}
						<button
							class="triage-btn-send"
							onclick={() => send(input)}
							disabled={!input.trim()}
							aria-label="Send"
						>
							<svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke-width="2.5" stroke="currentColor">
								<path stroke-linecap="round" stroke-linejoin="round" d="M4.5 10.5L12 3m0 0l7.5 7.5M12 3v18" />
							</svg>
						</button>
					{/if}
				</div>
			</div>
		{/if}
	</div>
{/if}

<style>
	/* ── Floating Action Button ── */
	.triage-fab {
		position: fixed;
		bottom: 24px;
		right: 24px;
		z-index: 50;
		display: flex;
		align-items: center;
		justify-content: center;
		width: 48px;
		height: 48px;
		border: none;
		cursor: pointer;
		background: none;
		padding: 0;
		transition: all 0.2s ease;
	}
	.triage-fab:hover {
		transform: scale(1.08);
	}
	.triage-fab:active {
		transform: scale(0.96);
	}
	.triage-fab-open {
		z-index: 51;
	}

	.triage-fab-glow {
		position: absolute;
		inset: -3px;
		border-radius: 50%;
		background: conic-gradient(
			from 0deg,
			var(--color-blue) 0%,
			var(--color-crit) 25%,
			var(--color-high) 50%,
			var(--color-blue-dim) 75%,
			var(--color-blue) 100%
		);
		opacity: 0.7;
		animation: fab-spin 4s linear infinite;
		filter: blur(1px);
	}
	.triage-fab:hover .triage-fab-glow {
		opacity: 1;
		filter: blur(2px);
	}

	.triage-fab-inner {
		position: relative;
		display: flex;
		align-items: center;
		justify-content: center;
		gap: 4px;
		width: 100%;
		height: 100%;
		border-radius: 50%;
		background: var(--color-bg);
		color: var(--color-blue);
		font-family: var(--font-mono);
	}

	@keyframes fab-spin {
		from { transform: rotate(0deg); }
		to { transform: rotate(360deg); }
	}

	/* ── Drawer ── */
	.triage-drawer {
		position: fixed;
		top: 0;
		right: 0;
		bottom: 0;
		z-index: 45;
		width: 100%;
		max-width: 440px;
		display: flex;
		flex-direction: column;
		background: var(--color-bg-deep);
		border-left: 1px solid var(--color-edge);
		box-shadow: -8px 0 32px rgba(0, 0, 0, 0.4);
	}

	/* ── Header ── */
	.triage-header {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: 14px 16px;
		border-bottom: 1px solid var(--color-edge);
		background: var(--color-bg);
	}
	.triage-header-icon {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 24px;
		height: 24px;
		border-radius: 6px;
		background: color-mix(in srgb, var(--color-blue) 15%, transparent);
		color: var(--color-blue);
	}

	/* ── Finding selector ── */
	.triage-finding-selector {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: 8px;
		padding: 10px 16px;
		border-bottom: 1px solid var(--color-edge);
		background: color-mix(in srgb, var(--color-bg) 50%, var(--color-bg-deep));
		min-height: 42px;
	}
	.triage-picker {
		position: relative;
		flex-shrink: 0;
	}
	.triage-picker-trigger {
		list-style: none;
		cursor: pointer;
	}
	.triage-picker-trigger::-webkit-details-marker { display: none; }

	.triage-picker-dropdown {
		position: absolute;
		right: 0;
		top: calc(100% + 6px);
		width: 380px;
		max-height: 320px;
		overflow-y: auto;
		border: 1px solid var(--color-edge-light);
		border-radius: 8px;
		background: var(--color-bg);
		box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
		z-index: 10;
	}
	.triage-picker-item {
		display: flex;
		align-items: center;
		gap: 8px;
		width: 100%;
		padding: 10px 12px;
		border: none;
		border-bottom: 1px solid var(--color-edge);
		background: transparent;
		cursor: pointer;
		text-align: left;
		transition: background 0.1s;
	}
	.triage-picker-item:last-child { border-bottom: none; }
	.triage-picker-item:hover { background: var(--color-bg-raised); }
	.triage-picker-item-active { background: color-mix(in srgb, var(--color-blue) 8%, transparent); }

	/* ── Messages ── */
	.triage-messages {
		flex: 1;
		overflow-y: auto;
		padding: 16px;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.triage-msg-user {
		max-width: 85%;
		padding: 10px 14px;
		border-radius: 14px 14px 4px 14px;
		background: color-mix(in srgb, var(--color-blue) 12%, transparent);
		border: 1px solid color-mix(in srgb, var(--color-blue) 20%, transparent);
		font-family: var(--font-mono);
		font-size: 13px;
		line-height: 1.6;
		color: var(--color-t1);
		white-space: pre-wrap;
	}

	.triage-msg-ai {
		max-width: 88%;
		padding: 10px 14px;
		border-radius: 14px 14px 14px 4px;
		background: var(--color-bg);
		border: 1px solid var(--color-edge);
		font-family: var(--font-mono);
		font-size: 13px;
		line-height: 1.7;
		color: var(--color-t2);
		white-space: pre-wrap;
	}

	.triage-msg-thinking {
		display: flex;
		gap: 4px;
		padding: 14px 18px;
	}
	.triage-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: var(--color-t4);
		animation: dot-bounce 1.2s ease-in-out infinite;
	}
	@keyframes dot-bounce {
		0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
		30% { transform: translateY(-6px); opacity: 1; }
	}

	.triage-cursor {
		display: inline-block;
		width: 2px;
		height: 14px;
		background: var(--color-blue);
		margin-left: 2px;
		vertical-align: text-bottom;
		animation: cursor-blink 0.8s ease-in-out infinite;
	}
	@keyframes cursor-blink {
		0%, 100% { opacity: 1; }
		50% { opacity: 0; }
	}

	.triage-msg-error {
		display: flex;
		align-items: flex-start;
		gap: 8px;
		padding: 10px 14px;
		border-radius: 8px;
		border: 1px solid color-mix(in srgb, var(--color-crit) 25%, transparent);
		background: color-mix(in srgb, var(--color-crit) 5%, transparent);
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-crit);
	}

	/* ── Quick actions ── */
	.triage-quick-action {
		display: flex;
		align-items: center;
		gap: 10px;
		width: 100%;
		padding: 12px 14px;
		border-radius: 10px;
		border: 1px solid var(--color-edge);
		background: var(--color-bg);
		cursor: pointer;
		text-align: left;
		font-family: var(--font-mono);
		font-size: 12px;
		color: var(--color-t2);
		transition: all 0.15s ease;
	}
	.triage-quick-action:hover {
		border-color: var(--color-blue);
		background: color-mix(in srgb, var(--color-blue) 5%, var(--color-bg));
		color: var(--color-t1);
		transform: translateY(-1px);
		box-shadow: 0 2px 12px rgba(59, 130, 246, 0.1);
	}
	.triage-quick-action-icon {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 26px;
		height: 26px;
		border-radius: 6px;
		background: color-mix(in srgb, var(--color-blue) 10%, transparent);
		color: var(--color-blue);
		font-size: 14px;
		font-weight: 700;
		flex-shrink: 0;
	}

	/* ── Input ── */
	.triage-input-bar {
		padding: 12px 16px;
		border-top: 1px solid var(--color-edge);
		background: var(--color-bg);
	}
	.triage-input-wrap {
		display: flex;
		align-items: flex-end;
		gap: 8px;
		padding: 8px 10px;
		border-radius: 12px;
		border: 1px solid var(--color-edge-light);
		background: var(--color-bg-deep);
		transition: border-color 0.15s;
	}
	.triage-input-wrap:focus-within {
		border-color: color-mix(in srgb, var(--color-blue) 40%, transparent);
	}
	.triage-input {
		flex: 1;
		background: transparent;
		border: none;
		outline: none;
		resize: none;
		font-family: var(--font-mono);
		font-size: 13px;
		line-height: 1.5;
		color: var(--color-t1);
		padding: 2px 0;
		max-height: 80px;
	}
	.triage-input::placeholder { color: var(--color-t4); }
	.triage-input:disabled { opacity: 0.5; }

	.triage-btn-send, .triage-btn-stop {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 30px;
		height: 30px;
		border-radius: 8px;
		border: none;
		cursor: pointer;
		flex-shrink: 0;
		transition: all 0.15s;
	}
	.triage-btn-send {
		background: var(--color-blue);
		color: white;
	}
	.triage-btn-send:hover { filter: brightness(1.15); }
	.triage-btn-send:disabled { opacity: 0.25; cursor: default; }
	.triage-btn-stop {
		background: color-mix(in srgb, var(--color-crit) 20%, transparent);
		color: var(--color-crit);
	}
	.triage-btn-stop:hover { background: color-mix(in srgb, var(--color-crit) 30%, transparent); }

	/* ── Animations ── */
	@keyframes msg-in {
		from { opacity: 0; transform: translateY(6px); }
		to { opacity: 1; transform: translateY(0); }
	}
	:global(.anim-msg) {
		animation: msg-in 0.2s ease-out both;
	}
	:global(.anim-fade-in) {
		animation: fade-in 0.2s ease-out both;
	}
	@keyframes fade-in {
		from { opacity: 0; }
		to { opacity: 1; }
	}
</style>
