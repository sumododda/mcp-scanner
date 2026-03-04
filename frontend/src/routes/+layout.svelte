<script lang="ts">
	import '../app.css';
	import favicon from '$lib/assets/favicon.svg';

	let { children } = $props();
</script>

<svelte:head>
	<link rel="icon" href={favicon} />
	<title>MCP Security Scanner</title>
</svelte:head>

<div class="min-h-screen bg-bg-deep font-sans text-t1">
	<nav class="sticky top-0 z-50 border-b border-edge bg-bg-deep/90 backdrop-blur-sm">
		<div class="mx-auto max-w-[1400px] px-6">
			<div class="flex h-14 items-center justify-between">
				<a href="/" class="flex items-center gap-2.5">
					<svg class="h-5 w-5 text-blue" fill="none" viewBox="0 0 24 24" stroke-width="2" stroke="currentColor">
						<path stroke-linecap="round" stroke-linejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
					</svg>
					<span class="text-base font-semibold text-t1 tracking-tight">MCP Scanner</span>
				</a>
				<div class="flex items-center gap-1">
					<a href="/" class="px-3 py-1.5 text-sm font-medium text-t3 transition-colors hover:text-t1">
						Scan
					</a>
					<a href="/history" class="px-3 py-1.5 text-sm font-medium text-t3 transition-colors hover:text-t1">
						History
					</a>
					<a href="/settings" class="px-3 py-1.5 text-sm font-medium text-t3 transition-colors hover:text-t1">
						Settings
					</a>
				</div>
			</div>
		</div>
	</nav>

	<main class="mx-auto max-w-[1400px] px-6 py-8">
		{@render children()}
	</main>
</div>
