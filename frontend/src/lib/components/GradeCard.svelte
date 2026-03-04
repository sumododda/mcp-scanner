<script lang="ts">
	interface Props {
		grade: string | null;
		score: number | null;
	}

	let { grade, score }: Props = $props();

	const gradeColors: Record<string, string> = {
		A: 'text-clear',
		B: 'text-low',
		C: 'text-med',
		D: 'text-high',
		F: 'text-crit',
	};

	const barColors: Record<string, string> = {
		A: 'bg-clear',
		B: 'bg-low',
		C: 'bg-med',
		D: 'bg-high',
		F: 'bg-crit',
	};

	let color = $derived(gradeColors[grade ?? 'F'] ?? 'text-crit');
	let bar = $derived(barColors[grade ?? 'F'] ?? 'bg-crit');
	let pct = $derived(Math.max(0, Math.min(100, score ?? 0)));
</script>

<div class="flex items-baseline gap-4">
	<span class="text-6xl font-bold font-mono tracking-tighter {color}">{score ?? '—'}</span>
	<span class="text-xl font-mono text-t4">/100</span>
	<div class="flex-1 ml-4">
		<div class="h-2 w-full rounded-sm bg-edge overflow-hidden">
			<div class="h-full rounded-sm {bar} anim-bar" style="width: {pct}%"></div>
		</div>
	</div>
</div>
