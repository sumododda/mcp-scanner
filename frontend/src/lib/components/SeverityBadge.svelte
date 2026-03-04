<script lang="ts">
	interface Props {
		severity: 'critical' | 'high' | 'medium' | 'low';
	}

	let { severity }: Props = $props();

	const config: Record<string, { color: string; label: string }> = {
		critical: { color: 'bg-crit text-crit', label: 'CRIT' },
		high: { color: 'bg-high text-high', label: 'HIGH' },
		medium: { color: 'bg-med text-med', label: 'MED' },
		low: { color: 'bg-low text-low', label: 'LOW' },
	};

	let c = $derived(config[severity] ?? config.low);
</script>

<span class="inline-flex items-center gap-1.5 font-mono text-xs font-semibold tracking-wider {c.color}">
	<span class="h-2 w-2 rounded-full {c.color.split(' ')[0]}"></span>
	{c.label}
</span>
