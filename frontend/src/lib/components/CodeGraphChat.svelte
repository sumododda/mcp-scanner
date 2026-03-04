<script lang="ts">
	import type { TriageChatMessage, CodeGraphStats } from '$lib/api';
	import { streamCodeGraphChat } from '$lib/api';

	interface Props {
		scanId: string;
		stats: CodeGraphStats;
		toolHandlers: string[];
		selectedNode?: string;
		compact?: boolean;
		nodeLabels?: string[];
		onMentionedNodes?: (names: string[]) => void;
	}

	let { scanId, stats, toolHandlers, selectedNode = '', compact = false, nodeLabels = [], onMentionedNodes }: Props = $props();

	let messages: TriageChatMessage[] = $state([]);
	let input = $state('');
	let streaming = $state(false);
	let streamBuffer = $state('');
	let error = $state('');
	let abortController: AbortController | null = $state(null);
	let messagesEnd: HTMLDivElement | undefined = $state();
	let inputEl: HTMLTextAreaElement | undefined = $state();

	function scrollToBottom() {
		requestAnimationFrame(() => messagesEnd?.scrollIntoView({ behavior: 'smooth' }));
	}

	function extractMentionedNodes(text: string): string[] {
		if (!nodeLabels.length || !onMentionedNodes) return [];
		const labelSet = new Set(nodeLabels.map(l => l.toLowerCase()));
		const mentioned = new Set<string>();

		// Match backtick-enclosed names
		const backtickPattern = /`([^`]+)`/g;
		let match;
		while ((match = backtickPattern.exec(text)) !== null) {
			const candidate = match[1].trim();
			// Check exact match (case-insensitive)
			if (labelSet.has(candidate.toLowerCase())) {
				// Find the original-cased label
				const orig = nodeLabels.find(l => l.toLowerCase() === candidate.toLowerCase());
				if (orig) mentioned.add(orig);
			}
		}

		// Match bare function-like names (word_word or word.word patterns)
		const barePattern = /\b([a-zA-Z_][a-zA-Z0-9_]*(?:\.[a-zA-Z_][a-zA-Z0-9_]*)*)\b/g;
		while ((match = barePattern.exec(text)) !== null) {
			const candidate = match[1];
			if (candidate.length < 3) continue; // skip very short matches
			if (labelSet.has(candidate.toLowerCase())) {
				const orig = nodeLabels.find(l => l.toLowerCase() === candidate.toLowerCase());
				if (orig) mentioned.add(orig);
			}
		}

		return Array.from(mentioned);
	}

	function send(text: string) {
		if (!text.trim() || streaming) return;
		const userMsg = text.trim();
		input = '';
		error = '';
		messages = [...messages, { role: 'user', content: userMsg }];
		streaming = true;
		streamBuffer = '';
		scrollToBottom();

		const history = messages.filter((m) => m.role !== 'user' || m.content !== userMsg);

		abortController = streamCodeGraphChat(
			scanId,
			userMsg,
			history,
			(token) => {
				streamBuffer += token;
				scrollToBottom();
			},
			() => {
				messages = [...messages, { role: 'assistant', content: streamBuffer }];
				// Extract mentioned function names and notify parent
				const fullResponse = streamBuffer;
				const mentioned = extractMentionedNodes(userMsg + '\n' + fullResponse);
				if (mentioned.length > 0 && onMentionedNodes) {
					onMentionedNodes(mentioned);
				}
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

	const quickActions = [
		{ label: 'What auth is used?', icon: '?', prompt: 'Does this MCP server implement authentication? What libraries or patterns are used to verify caller identity?' },
		{ label: 'List dangerous operations', icon: '!', prompt: 'List all dangerous operations (subprocess, eval, exec, os.system) found in the code. For each, explain the security risk and whether it appears to be properly sandboxed.' },
		{ label: 'Show tool handlers', icon: '>', prompt: 'Describe each tool handler found in the code. What does each one do, what parameters does it accept, and what operations does it perform?' },
		{ label: 'Any network calls?', icon: '~', prompt: 'Are there any outbound network calls in the code? List them and explain what data they send and where.' },
	];

	$effect(() => {
		return () => {
			abortController?.abort();
		};
	});

	$effect(() => {
		if (selectedNode && !streaming) {
			input = `Explain the \`${selectedNode}\` function. What does it do, what does it call, and are there any security concerns?`;
		}
	});
</script>

<div class="graph-chat" class:graph-chat-compact={compact}>
	<!-- Stats banner -->
	<div class="graph-stats">
		<div class="graph-stats-row">
			<div class="graph-stat">
				<span class="graph-stat-value">{stats.total_functions}</span>
				<span class="graph-stat-label">FUNCTIONS</span>
			</div>
			<div class="graph-stat">
				<span class="graph-stat-value {stats.tool_handlers > 0 ? 'text-blue' : ''}">{stats.tool_handlers}</span>
				<span class="graph-stat-label">TOOL HANDLERS</span>
			</div>
			<div class="graph-stat">
				<span class="graph-stat-value">{stats.total_call_sites}</span>
				<span class="graph-stat-label">CALL SITES</span>
			</div>
			<div class="graph-stat">
				<span class="graph-stat-value {stats.dangerous_calls > 0 ? 'text-crit' : ''}">{stats.dangerous_calls}</span>
				<span class="graph-stat-label">DANGEROUS</span>
			</div>
			<div class="graph-stat">
				<span class="graph-stat-value {stats.network_calls > 0 ? 'text-high' : ''}">{stats.network_calls}</span>
				<span class="graph-stat-label">NETWORK</span>
			</div>
			<div class="graph-stat">
				<span class="graph-stat-value">{stats.file_access_calls}</span>
				<span class="graph-stat-label">FILE I/O</span>
			</div>
		</div>

		{#if toolHandlers.length > 0}
			<div class="graph-handlers">
				<span class="graph-handlers-label">TOOL HANDLERS:</span>
				{#each toolHandlers as handler}
					<span class="graph-handler-tag">{handler}</span>
				{/each}
			</div>
		{/if}
	</div>

	<!-- Chat area -->
	<div class="graph-messages">
		{#if messages.length === 0 && !streaming}
			<!-- Quick actions -->
			<div class="graph-quick-actions">
				<p class="graph-quick-title">Ask about the analyzed source code</p>
				<div class="graph-quick-grid">
					{#each quickActions as action}
						<button
							class="graph-quick-btn"
							onclick={() => send(action.prompt)}
						>
							<span class="graph-quick-icon">{action.icon}</span>
							<span>{action.label}</span>
						</button>
					{/each}
				</div>
			</div>
		{:else}
			<!-- Messages -->
			{#each messages as msg, i}
				{#if msg.role === 'user'}
					<div class="flex justify-end anim-msg" style="animation-delay: {i * 30}ms">
						<div class="graph-msg-user">
							<p>{msg.content}</p>
						</div>
					</div>
				{:else}
					<div class="flex justify-start anim-msg" style="animation-delay: {i * 30}ms">
						<div class="graph-msg-ai">
							<p>{msg.content}</p>
						</div>
					</div>
				{/if}
			{/each}

			{#if streaming && streamBuffer}
				<div class="flex justify-start">
					<div class="graph-msg-ai">
						<p>{streamBuffer}<span class="graph-cursor"></span></p>
					</div>
				</div>
			{:else if streaming}
				<div class="flex justify-start">
					<div class="graph-msg-ai graph-msg-thinking">
						<span class="graph-dot"></span>
						<span class="graph-dot" style="animation-delay: 150ms"></span>
						<span class="graph-dot" style="animation-delay: 300ms"></span>
					</div>
				</div>
			{/if}

			{#if error}
				<div class="graph-msg-error">
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
	<div class="graph-input-bar">
		<div class="graph-input-wrap">
			<textarea
				bind:this={inputEl}
				class="graph-input"
				rows="1"
				placeholder="Ask about the source code..."
				bind:value={input}
				onkeydown={handleKeydown}
				disabled={streaming}
			></textarea>
			{#if streaming}
				<button class="graph-btn-stop" onclick={stop} aria-label="Stop">
					<svg class="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 24 24">
						<rect x="6" y="6" width="12" height="12" rx="2" />
					</svg>
				</button>
			{:else}
				<button
					class="graph-btn-send"
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
</div>

<style>
	.graph-chat {
		display: flex;
		flex-direction: column;
		min-height: 500px;
		max-height: 700px;
		border: 1px solid var(--color-edge);
		border-radius: 8px;
		overflow: hidden;
		background: var(--color-bg-deep);
	}

	/* ── Stats ── */
	.graph-stats {
		padding: 16px 20px;
		border-bottom: 1px solid var(--color-edge);
		background: var(--color-bg);
	}
	.graph-stats-row {
		display: flex;
		gap: 24px;
		flex-wrap: wrap;
	}
	.graph-stat {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.graph-stat-value {
		font-family: var(--font-mono);
		font-size: 20px;
		font-weight: 700;
		color: var(--color-t1);
		line-height: 1;
	}
	.graph-stat-label {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 600;
		color: var(--color-t4);
		letter-spacing: 0.05em;
	}

	.graph-handlers {
		display: flex;
		align-items: center;
		gap: 6px;
		margin-top: 12px;
		flex-wrap: wrap;
	}
	.graph-handlers-label {
		font-family: var(--font-mono);
		font-size: 10px;
		font-weight: 600;
		color: var(--color-t4);
		letter-spacing: 0.05em;
	}
	.graph-handler-tag {
		font-family: var(--font-mono);
		font-size: 11px;
		padding: 2px 8px;
		border-radius: 4px;
		background: color-mix(in srgb, var(--color-blue) 10%, transparent);
		border: 1px solid color-mix(in srgb, var(--color-blue) 20%, transparent);
		color: var(--color-blue);
	}

	/* ── Messages ── */
	.graph-messages {
		flex: 1;
		overflow-y: auto;
		padding: 16px 20px;
		display: flex;
		flex-direction: column;
		gap: 10px;
	}

	.graph-msg-user {
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

	.graph-msg-ai {
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

	.graph-msg-thinking {
		display: flex;
		gap: 4px;
		padding: 14px 18px;
	}
	.graph-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		background: var(--color-t4);
		animation: graph-dot-bounce 1.2s ease-in-out infinite;
	}
	@keyframes graph-dot-bounce {
		0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
		30% { transform: translateY(-6px); opacity: 1; }
	}

	.graph-cursor {
		display: inline-block;
		width: 2px;
		height: 14px;
		background: var(--color-blue);
		margin-left: 2px;
		vertical-align: text-bottom;
		animation: graph-cursor-blink 0.8s ease-in-out infinite;
	}
	@keyframes graph-cursor-blink {
		0%, 100% { opacity: 1; }
		50% { opacity: 0; }
	}

	.graph-msg-error {
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
	.graph-quick-actions {
		display: flex;
		flex-direction: column;
		gap: 12px;
		padding-top: 8px;
	}
	.graph-quick-title {
		font-family: var(--font-mono);
		font-size: 11px;
		font-weight: 600;
		color: var(--color-t4);
		letter-spacing: 0.04em;
		text-transform: uppercase;
	}
	.graph-quick-grid {
		display: grid;
		grid-template-columns: 1fr 1fr;
		gap: 8px;
	}
	.graph-quick-btn {
		display: flex;
		align-items: center;
		gap: 10px;
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
	.graph-quick-btn:hover {
		border-color: var(--color-blue);
		background: color-mix(in srgb, var(--color-blue) 5%, var(--color-bg));
		color: var(--color-t1);
		transform: translateY(-1px);
		box-shadow: 0 2px 12px rgba(59, 130, 246, 0.1);
	}
	.graph-quick-icon {
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
	.graph-input-bar {
		padding: 12px 16px;
		border-top: 1px solid var(--color-edge);
		background: var(--color-bg);
	}
	.graph-input-wrap {
		display: flex;
		align-items: flex-end;
		gap: 8px;
		padding: 8px 10px;
		border-radius: 12px;
		border: 1px solid var(--color-edge-light);
		background: var(--color-bg-deep);
		transition: border-color 0.15s;
	}
	.graph-input-wrap:focus-within {
		border-color: color-mix(in srgb, var(--color-blue) 40%, transparent);
	}
	.graph-input {
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
	.graph-input::placeholder { color: var(--color-t4); }
	.graph-input:disabled { opacity: 0.5; }

	.graph-btn-send, .graph-btn-stop {
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
	.graph-btn-send {
		background: var(--color-blue);
		color: white;
	}
	.graph-btn-send:hover { filter: brightness(1.15); }
	.graph-btn-send:disabled { opacity: 0.25; cursor: default; }
	.graph-btn-stop {
		background: color-mix(in srgb, var(--color-crit) 20%, transparent);
		color: var(--color-crit);
	}
	.graph-btn-stop:hover { background: color-mix(in srgb, var(--color-crit) 30%, transparent); }

	/* Compact / split mode */
	.graph-chat-compact {
		min-height: 0;
		max-height: 100%;
		border: none;
		border-left: 1px solid var(--color-edge);
		border-radius: 0;
	}
	.graph-chat-compact .graph-stats { display: none; }
	.graph-chat-compact .graph-quick-grid { grid-template-columns: 1fr; }
</style>
