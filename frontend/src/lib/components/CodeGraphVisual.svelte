<script lang="ts">
	import type { CodeGraphData } from '$lib/api';

	interface Props {
		codeGraph: CodeGraphData;
		onNodeClick: (nodeName: string) => void;
		highlightedNodes?: string[];
	}

	let { codeGraph, onNodeClick, highlightedNodes = [] }: Props = $props();

	let container: HTMLDivElement | undefined = $state();
	let graph: any = $state(null);
	let showImports = $state(false);
	let hoveredNodeId: string | null = $state(null);
	let neighborSet: Set<string> = $state(new Set());
	let initError = $state('');
	let highlightedNodeId: string | null = $state(null);
	let searchQuery = $state('');
	let searchResults: GraphNode[] = $state([]);
	let searchSelectedIdx = $state(-1);
	let searchOpen = $state(false);
	// Not reactive — managed imperatively to avoid triggering $effect re-runs
	let edgeWaypointMap: Map<string, EdgeWaypoints> = new Map();

	const DANGEROUS_PATTERNS = ['subprocess', 'os.system', 'eval', 'exec', 'child_process', 'exec.Command', 'Popen', 'shell_exec', 'system'];
	const NETWORK_PATTERNS = ['requests', 'httpx', 'fetch', 'axios', 'aiohttp', 'http.Get', 'http.Post', 'urllib', 'urlopen'];
	const FILE_PATTERNS = ['open', 'pathlib', 'shutil', 'fs.readFile', 'os.ReadFile', 'writeFile', 'readFileSync'];

	type NodeType = 'tool-handler' | 'dangerous' | 'network' | 'file-io' | 'regular' | 'import';

	const NODE_COLORS: Record<NodeType, string> = {
		'tool-handler': '#6366f1',
		'dangerous': '#ef4444',
		'network': '#f97316',
		'file-io': '#eab308',
		'regular': '#475569',
		'import': '#334155',
	};

	const NODE_COLORS_LIGHT: Record<NodeType, string> = {
		'tool-handler': '#a5b4fc',
		'dangerous': '#fca5a5',
		'network': '#fdba74',
		'file-io': '#fde047',
		'regular': '#94a3b8',
		'import': '#64748b',
	};

	const NODE_SIZES: Record<NodeType, number> = {
		'tool-handler': 12,
		'dangerous': 9,
		'network': 8,
		'file-io': 8,
		'regular': 5,
		'import': 3,
	};

	interface GraphNode {
		id: string;
		label: string;
		type: NodeType;
		file?: string;
		x?: number;
		y?: number;
	}

	interface GraphLink {
		source: string | any;
		target: string | any;
		type: 'call' | 'import';
	}

	interface EdgeWaypoints {
		source: string;
		target: string;
		points: { x: number; y: number }[];
		type: 'call' | 'import';
	}

	// Pre-build adjacency index for fast neighbor lookup
	let adjacency = new Map<string, Set<string>>();

	function buildAdjacency(links: GraphLink[]) {
		const adj = new Map<string, Set<string>>();
		for (const l of links) {
			const src = typeof l.source === 'string' ? l.source : (l.source as any).id;
			const tgt = typeof l.target === 'string' ? l.target : (l.target as any).id;
			if (!adj.has(src)) adj.set(src, new Set());
			if (!adj.has(tgt)) adj.set(tgt, new Set());
			adj.get(src)!.add(tgt);
			adj.get(tgt)!.add(src);
		}
		return adj;
	}

	function classifyName(name: string): NodeType {
		const lower = name.toLowerCase();
		if (DANGEROUS_PATTERNS.some(p => lower.includes(p.toLowerCase()))) return 'dangerous';
		if (NETWORK_PATTERNS.some(p => lower.includes(p.toLowerCase()))) return 'network';
		if (FILE_PATTERNS.some(p => lower.includes(p.toLowerCase()))) return 'file-io';
		return 'regular';
	}

	const MAX_VISIBLE_NODES = 200;

	function buildGraphData(data: CodeGraphData) {
		// Phase 1: classify all functions and build full call graph index
		const allNodes = new Map<string, GraphNode>();
		const callEdges: { source: string; target: string }[] = [];

		for (const fn of data.functions) {
			const type: NodeType = fn.is_tool_handler ? 'tool-handler' : classifyName(fn.name);
			const id = `fn:${fn.name}`;
			if (!allNodes.has(id)) {
				allNodes.set(id, { id, label: fn.name, type, file: fn.file });
			}
		}

		const edgeKeys = new Set<string>();
		for (const cs of data.call_sites) {
			if (!cs.parent) continue;
			const sourceId = `fn:${cs.parent}`;
			const targetId = `fn:${cs.callee}`;
			if (!allNodes.has(sourceId)) continue;
			const ek = `${sourceId}->${targetId}`;
			if (edgeKeys.has(ek)) continue;
			edgeKeys.add(ek);
			// Create callee node if it doesn't exist yet
			if (!allNodes.has(targetId)) {
				allNodes.set(targetId, { id: targetId, label: cs.callee, type: classifyName(cs.callee) });
			}
			callEdges.push({ source: sourceId, target: targetId });
		}

		// Phase 2: if graph is small enough, show everything
		if (allNodes.size <= MAX_VISIBLE_NODES) {
			const nodes = Array.from(allNodes.values());
			const nodeIds = new Set(nodes.map(n => n.id));
			const links: GraphLink[] = callEdges
				.filter(e => nodeIds.has(e.source) && nodeIds.has(e.target))
				.map(e => ({ source: e.source, target: e.target, type: 'call' as const }));

			const { importNodes, importLinks } = buildImportData(data, nodes);
			return { nodes, links, importNodes, importLinks };
		}

		// Phase 3: large graph — keep only security-relevant subgraph
		// Seed: tool handlers + dangerous + network + file-io
		const seedIds = new Set<string>();
		for (const [id, node] of allNodes) {
			if (node.type !== 'regular') seedIds.add(id);
		}

		// Build adjacency for 1-hop neighbor expansion
		const adj = new Map<string, Set<string>>();
		for (const e of callEdges) {
			if (!adj.has(e.source)) adj.set(e.source, new Set());
			if (!adj.has(e.target)) adj.set(e.target, new Set());
			adj.get(e.source)!.add(e.target);
			adj.get(e.target)!.add(e.source);
		}

		// Expand to 1-hop neighbors of seeds
		const visibleIds = new Set(seedIds);
		for (const seed of seedIds) {
			const neighbors = adj.get(seed);
			if (!neighbors) continue;
			for (const n of neighbors) {
				visibleIds.add(n);
				if (visibleIds.size >= MAX_VISIBLE_NODES) break;
			}
			if (visibleIds.size >= MAX_VISIBLE_NODES) break;
		}

		const nodes: GraphNode[] = [];
		for (const id of visibleIds) {
			const node = allNodes.get(id);
			if (node) nodes.push(node);
		}

		const links: GraphLink[] = callEdges
			.filter(e => visibleIds.has(e.source) && visibleIds.has(e.target))
			.map(e => ({ source: e.source, target: e.target, type: 'call' as const }));

		const { importNodes, importLinks } = buildImportData(data, nodes);
		return { nodes, links, importNodes, importLinks };
	}

	function buildImportData(data: CodeGraphData, nodes: GraphNode[]) {
		const importNodes: GraphNode[] = [];
		const importLinks: GraphLink[] = [];
		const importIds = new Set<string>();
		const importEdgeKeys = new Set<string>();

		for (const imp of data.imports) {
			const impId = `imp:${imp.module}`;
			if (!importIds.has(impId)) {
				importNodes.push({ id: impId, label: imp.module, type: 'import' });
				importIds.add(impId);
			}
			const fileFunc = nodes.find(n => n.file === imp.file);
			if (fileFunc) {
				const ek = `${fileFunc.id}->${impId}`;
				if (!importEdgeKeys.has(ek)) {
					importEdgeKeys.add(ek);
					importLinks.push({ source: fileFunc.id, target: impId, type: 'import' });
				}
			}
		}

		return { importNodes, importLinks };
	}

	let _dagre: typeof import('@dagrejs/dagre').default | null = null;

	async function loadDagre() {
		if (!_dagre) {
			const mod = await import('@dagrejs/dagre');
			_dagre = mod.default;
		}
		return _dagre;
	}

	async function computeDagreLayout(nodes: GraphNode[], links: GraphLink[]): Promise<{ nodes: GraphNode[]; edgeWaypoints: EdgeWaypoints[] }> {
		const dagre = await loadDagre();
		const g = new dagre.graphlib.Graph();
		g.setDefaultEdgeLabel(() => ({}));
		g.setGraph({
			rankdir: 'TB',
			ranksep: 80,
			nodesep: 30,
			edgesep: 10,
			marginx: 40,
			marginy: 40,
		});

		for (const node of nodes) {
			const labelWidth = Math.max(node.label.length * 7, 40);
			const w = labelWidth + 20;
			const baseSize = NODE_SIZES[node.type] || 5;
			const h = baseSize * 6 + 16;
			g.setNode(node.id, { width: w, height: h });
		}

		for (const link of links) {
			const src = typeof link.source === 'string' ? link.source : (link.source as any).id;
			const tgt = typeof link.target === 'string' ? link.target : (link.target as any).id;
			if (g.hasNode(src) && g.hasNode(tgt)) {
				g.setEdge(src, tgt);
			}
		}

		dagre.layout(g);

		const positionedNodes = nodes.map(node => {
			const dagreNode = g.node(node.id);
			if (dagreNode) {
				return { ...node, x: dagreNode.x, y: dagreNode.y };
			}
			return node;
		});

		const edgeWaypoints: EdgeWaypoints[] = [];
		for (const link of links) {
			const src = typeof link.source === 'string' ? link.source : (link.source as any).id;
			const tgt = typeof link.target === 'string' ? link.target : (link.target as any).id;
			const edgeData = g.edge(src, tgt);
			if (edgeData?.points) {
				edgeWaypoints.push({
					source: src,
					target: tgt,
					points: edgeData.points,
					type: link.type,
				});
			}
		}

		return { nodes: positionedNodes, edgeWaypoints };
	}

	let graphData = $derived(buildGraphData(codeGraph));
	let totalFunctions = $derived(codeGraph.functions.length);
	let isFiltered = $derived(graphData.nodes.length < totalFunctions);
	let stats = $derived({
		nodes: graphData.nodes.length + graphData.importNodes.length,
		edges: graphData.links.length + graphData.importLinks.length,
	});

	let highlightedNodeIds = $derived(new Set(
		(highlightedNodes ?? []).map(name => `fn:${name}`)
	));
	let hasExternalHighlight = $derived(highlightedNodeIds.size > 0);

	function getActiveData() {
		const allNodes = showImports
			? [...graphData.nodes, ...graphData.importNodes]
			: graphData.nodes;
		const allLinks = showImports
			? [...graphData.links, ...graphData.importLinks]
			: graphData.links;
		return { nodes: allNodes, links: allLinks };
	}

	function isNodeDimmed(n: GraphNode): boolean {
		if (highlightedNodeId && highlightedNodeId !== n.id && !neighborSet.has(n.id)) {
			return true;
		}
		if (hasExternalHighlight && !highlightedNodeIds.has(n.id)) {
			for (const hid of highlightedNodeIds) {
				if (adjacency.get(hid)?.has(n.id)) return false;
			}
			return true;
		}
		if (hoveredNodeId && hoveredNodeId !== n.id && !neighborSet.has(n.id)) {
			return true;
		}
		return false;
	}

	function isNodeHighlighted(n: GraphNode): boolean {
		return highlightedNodeId === n.id || highlightedNodeIds.has(n.id);
	}

	function getNodeColor(n: GraphNode): string {
		if (isNodeDimmed(n)) return '#1e293b';
		return NODE_COLORS[n.type] || '#475569';
	}

	function getNodeSize(n: GraphNode): number {
		return Math.sqrt(NODE_SIZES[n.type] || 5) * 4;
	}

	// Search functions
	function updateSearch(query: string) {
		searchQuery = query;
		if (!query.trim()) {
			searchResults = [];
			searchOpen = false;
			searchSelectedIdx = -1;
			return;
		}
		const q = query.toLowerCase();
		searchResults = graphData.nodes
			.filter(n => n.label.toLowerCase().includes(q))
			.slice(0, 8);
		searchOpen = searchResults.length > 0;
		searchSelectedIdx = searchResults.length > 0 ? 0 : -1;
	}

	function selectSearchResult(node: GraphNode) {
		if (!graph) return;
		searchOpen = false;
		searchQuery = node.label;
		focusOnNode(node.id);
	}

	function focusOnNode(nodeId: string) {
		if (!graph) return;
		const data = graph.graphData();
		const node = data.nodes.find((n: any) => n.id === nodeId);
		if (!node || node.x == null) return;
		highlightedNodeId = nodeId;
		neighborSet = adjacency.get(nodeId) || new Set();
		graph.centerAt(node.x, node.y, 800);
		graph.zoom(2.5, 800);
	}

	function clearHighlight() {
		highlightedNodeId = null;
		neighborSet = new Set();
	}

	function handleSearchKeydown(e: KeyboardEvent) {
		if (!searchOpen || searchResults.length === 0) return;
		if (e.key === 'ArrowDown') {
			e.preventDefault();
			searchSelectedIdx = (searchSelectedIdx + 1) % searchResults.length;
		} else if (e.key === 'ArrowUp') {
			e.preventDefault();
			searchSelectedIdx = (searchSelectedIdx - 1 + searchResults.length) % searchResults.length;
		} else if (e.key === 'Enter') {
			e.preventDefault();
			if (searchSelectedIdx >= 0 && searchSelectedIdx < searchResults.length) {
				selectSearchResult(searchResults[searchSelectedIdx]);
			}
		} else if (e.key === 'Escape') {
			searchOpen = false;
		}
	}

	// Zoom & fit on highlighted nodes from chat
	$effect(() => {
		if (!graph || !hasExternalHighlight) return;
		const data = graph.graphData();
		const matchedNodes = data.nodes.filter((n: any) => highlightedNodeIds.has(n.id));
		if (matchedNodes.length === 0) return;
		if (matchedNodes.length === 1) {
			const n = matchedNodes[0];
			if (n.x != null) {
				graph.centerAt(n.x, n.y, 800);
				graph.zoom(2.0, 800);
			}
		} else {
			let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
			for (const n of matchedNodes) {
				if (n.x == null) continue;
				minX = Math.min(minX, n.x);
				maxX = Math.max(maxX, n.x);
				minY = Math.min(minY, n.y);
				maxY = Math.max(maxY, n.y);
			}
			const cx = (minX + maxX) / 2;
			const cy = (minY + maxY) / 2;
			graph.centerAt(cx, cy, 800);
		}
	});

	$effect(() => {
		if (!container) return;

		let g: any = null;
		let ro: ResizeObserver | null = null;

		(async () => {
			try {
				const ForceGraph = (await import('force-graph')).default;

				const rawData = getActiveData();
				adjacency = buildAdjacency(rawData.links);

				// Create plain copies to avoid Svelte proxy reactivity issues
				const plainNodes = rawData.nodes.map(n => ({ ...n }));
				const plainLinks = rawData.links.map(l => ({ ...l }));

				// Compute hierarchical layout with dagre
				const layout = await computeDagreLayout(plainNodes, plainLinks);
				const wpMap = new Map<string, EdgeWaypoints>();
				for (const ew of layout.edgeWaypoints) {
					wpMap.set(`${ew.source}->${ew.target}`, ew);
				}
				edgeWaypointMap = wpMap;

				// Apply fixed positions from dagre
				for (const node of plainNodes) {
					const positioned = layout.nodes.find(n => n.id === node.id);
					if (positioned) {
						(node as any).fx = positioned.x;
						(node as any).fy = positioned.y;
						node.x = positioned.x;
						node.y = positioned.y;
					}
				}

				const graphInput = { nodes: plainNodes, links: plainLinks };

				g = new ForceGraph(container)
					.graphData(graphInput)
					.nodeId('id')
					.nodeLabel('')
					.nodeVal((node: any) => NODE_SIZES[(node as GraphNode).type] || 5)
					.nodeCanvasObjectMode(() => 'replace')
					.nodeCanvasObject((node: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
						const n = node as GraphNode;
						const x = node.x as number;
						const y = node.y as number;
						if (x == null || y == null) return;
						const size = getNodeSize(n);
						const color = getNodeColor(n);
						const dimmed = isNodeDimmed(n);
						const highlighted = isNodeHighlighted(n);
						const isHovered = hoveredNodeId === n.id;
						const isImportant = n.type === 'tool-handler' || n.type === 'dangerous';

						// LOD: zoomed out — just a dot
						if (globalScale < 0.15) {
							ctx.beginPath();
							ctx.arc(x, y, dimmed ? 1.5 : (isImportant ? 4 : 2.5), 0, 2 * Math.PI);
							ctx.fillStyle = dimmed ? '#1e293b' : color;
							ctx.fill();
							return;
						}

						// Glow for important/highlighted nodes
						if ((isImportant || highlighted) && !dimmed && globalScale > 0.2) {
							ctx.shadowBlur = highlighted ? 18 : 12;
							ctx.shadowColor = highlighted ? '#6366f1' : (color + '80');
						}

						ctx.beginPath();

						if (n.type === 'dangerous' || n.type === 'network' || n.type === 'file-io') {
							// Diamond
							ctx.moveTo(x, y - size);
							ctx.lineTo(x + size, y);
							ctx.lineTo(x, y + size);
							ctx.lineTo(x - size, y);
							ctx.closePath();
						} else if (n.type === 'import') {
							ctx.arc(x, y, size * 0.7, 0, 2 * Math.PI);
						} else {
							// Rounded rect
							const w = size * 2;
							const h = size * 1.3;
							const r = 3;
							ctx.moveTo(x - w / 2 + r, y - h / 2);
							ctx.lineTo(x + w / 2 - r, y - h / 2);
							ctx.quadraticCurveTo(x + w / 2, y - h / 2, x + w / 2, y - h / 2 + r);
							ctx.lineTo(x + w / 2, y + h / 2 - r);
							ctx.quadraticCurveTo(x + w / 2, y + h / 2, x + w / 2 - r, y + h / 2);
							ctx.lineTo(x - w / 2 + r, y + h / 2);
							ctx.quadraticCurveTo(x - w / 2, y + h / 2, x - w / 2, y + h / 2 - r);
							ctx.lineTo(x - w / 2, y - h / 2 + r);
							ctx.quadraticCurveTo(x - w / 2, y - h / 2, x - w / 2 + r, y - h / 2);
							ctx.closePath();
						}

						// Gradient fill for important nodes
						if ((n.type === 'tool-handler' || n.type === 'dangerous') && globalScale > 0.3 && !dimmed) {
							const grad = ctx.createRadialGradient(x, y, 0, x, y, size * 1.2);
							grad.addColorStop(0, NODE_COLORS_LIGHT[n.type]);
							grad.addColorStop(1, color);
							ctx.fillStyle = grad;
						} else {
							ctx.fillStyle = color;
						}
						ctx.fill();

						// Reset shadow
						ctx.shadowBlur = 0;
						ctx.shadowColor = 'transparent';

						// Stroke for hovered/highlighted/tool-handler
						if (isHovered || highlighted || n.type === 'tool-handler') {
							ctx.strokeStyle = isHovered ? '#60a5fa' : (highlighted ? '#a5b4fc' : '#6366f180');
							ctx.lineWidth = isHovered ? 2 : (highlighted ? 2 : 1.5);
							ctx.stroke();
						}

						// Highlight ring for highlighted nodes
						if (highlighted && !dimmed) {
							ctx.beginPath();
							ctx.arc(x, y, size + 4, 0, 2 * Math.PI);
							ctx.strokeStyle = 'rgba(99,102,241,0.5)';
							ctx.lineWidth = 1.5;
							ctx.stroke();
						}

						// Label rendering — more visible with dagre layout
						const showLabel = globalScale > 0.5
							|| (globalScale > 0.2 && (isImportant || isHovered || highlighted))
							|| isHovered || highlighted;

						if (showLabel) {
							const fontSize = Math.max(12 / globalScale, 4);
							const label = n.label.length > 28 ? n.label.slice(0, 26) + '..' : n.label;
							ctx.font = `${fontSize}px "IBM Plex Mono", monospace`;
							const tw = ctx.measureText(label).width;

							// Label pill background
							const px = 3 / globalScale;
							const py = 1.5 / globalScale;
							const lx = x - tw / 2 - px;
							const ly = y + size + 3 / globalScale;
							const lw = tw + px * 2;
							const lh = fontSize + py * 2;
							const lr = 2 / globalScale;

							ctx.fillStyle = 'rgba(11,15,25,0.8)';
							ctx.beginPath();
							ctx.moveTo(lx + lr, ly);
							ctx.lineTo(lx + lw - lr, ly);
							ctx.quadraticCurveTo(lx + lw, ly, lx + lw, ly + lr);
							ctx.lineTo(lx + lw, ly + lh - lr);
							ctx.quadraticCurveTo(lx + lw, ly + lh, lx + lw - lr, ly + lh);
							ctx.lineTo(lx + lr, ly + lh);
							ctx.quadraticCurveTo(lx, ly + lh, lx, ly + lh - lr);
							ctx.lineTo(lx, ly + lr);
							ctx.quadraticCurveTo(lx, ly, lx + lr, ly);
							ctx.closePath();
							ctx.fill();

							ctx.textAlign = 'center';
							ctx.textBaseline = 'top';
							ctx.fillStyle = isHovered || highlighted ? '#e2e8f0' : '#94a3b8';
							ctx.fillText(label, x, ly + py);

							// File path subtitle at high zoom
							if (globalScale > 1.2 && n.file) {
								const subSize = fontSize * 0.75;
								ctx.font = `${subSize}px "IBM Plex Mono", monospace`;
								ctx.fillStyle = '#475569';
								const parts = n.file.split('/');
								const shortFile = parts.length > 2
									? '.../' + parts.slice(-2).join('/')
									: n.file;
								ctx.fillText(shortFile, x, ly + lh + 2 / globalScale);
							}
						}
					})
					.linkCanvasObjectMode(() => 'replace')
					.linkCanvasObject((link: any, ctx: CanvasRenderingContext2D, globalScale: number) => {
						const src = link.source;
						const tgt = link.target;
						if (!src || !tgt || src.x == null || tgt.x == null) return;

						const isImport = link.type === 'import';
						const srcId = src.id ?? src;
						const tgtId = tgt.id ?? tgt;

						const isHoveredEdge = hoveredNodeId && (srcId === hoveredNodeId || tgtId === hoveredNodeId);
						const isHighlightedEdge = highlightedNodeId && (srcId === highlightedNodeId || tgtId === highlightedNodeId);
						const isExternalHighlightEdge = hasExternalHighlight && (highlightedNodeIds.has(srcId) || highlightedNodeIds.has(tgtId));
						const active = isHoveredEdge || isHighlightedEdge || isExternalHighlightEdge;

						let dimmed = false;
						if (hoveredNodeId && !isHoveredEdge) dimmed = true;
						if (highlightedNodeId && !isHighlightedEdge) dimmed = true;
						if (hasExternalHighlight && !isExternalHighlightEdge) dimmed = true;

						// Get dagre waypoints for smooth curves
						const waypoints = edgeWaypointMap.get(`${srcId}->${tgtId}`);

						ctx.beginPath();
						if (isImport) ctx.setLineDash([4, 4]);

						if (waypoints && waypoints.points.length >= 2) {
							const pts = waypoints.points;
							ctx.moveTo(pts[0].x, pts[0].y);

							if (pts.length === 2) {
								ctx.lineTo(pts[1].x, pts[1].y);
							} else if (pts.length === 3) {
								ctx.quadraticCurveTo(pts[1].x, pts[1].y, pts[2].x, pts[2].y);
							} else {
								for (let i = 1; i < pts.length - 2; i++) {
									const xc = (pts[i].x + pts[i + 1].x) / 2;
									const yc = (pts[i].y + pts[i + 1].y) / 2;
									ctx.quadraticCurveTo(pts[i].x, pts[i].y, xc, yc);
								}
								const last = pts[pts.length - 1];
								const secondLast = pts[pts.length - 2];
								ctx.quadraticCurveTo(secondLast.x, secondLast.y, last.x, last.y);
							}
						} else {
							ctx.moveTo(src.x, src.y);
							ctx.lineTo(tgt.x, tgt.y);
						}

						if (dimmed) {
							ctx.strokeStyle = '#0f172a';
							ctx.lineWidth = 0.3;
						} else if (active) {
							ctx.strokeStyle = '#60a5fa';
							ctx.lineWidth = isHoveredEdge ? 2.5 : 1.8;
						} else {
							ctx.strokeStyle = isImport ? '#1e293b60' : '#475569';
							ctx.lineWidth = isImport ? 0.5 : 1;
						}

						ctx.stroke();
						ctx.setLineDash([]);

						// Arrow head — always render for call edges
						if (!isImport && !dimmed && globalScale > 0.15) {
							const endPt = waypoints && waypoints.points.length >= 2
								? waypoints.points[waypoints.points.length - 1]
								: { x: tgt.x, y: tgt.y };
							const prevPt = waypoints && waypoints.points.length >= 2
								? waypoints.points[waypoints.points.length - 2]
								: { x: src.x, y: src.y };

							const dx = endPt.x - prevPt.x;
							const dy = endPt.y - prevPt.y;
							const len = Math.sqrt(dx * dx + dy * dy);
							if (len < 1) return;
							const ux = dx / len;
							const uy = dy / len;

							const arrowLen = Math.max(5 / globalScale, 3);

							ctx.beginPath();
							ctx.moveTo(endPt.x, endPt.y);
							ctx.lineTo(endPt.x - ux * arrowLen - uy * arrowLen * 0.5, endPt.y - uy * arrowLen + ux * arrowLen * 0.5);
							ctx.lineTo(endPt.x - ux * arrowLen + uy * arrowLen * 0.5, endPt.y - uy * arrowLen - ux * arrowLen * 0.5);
							ctx.closePath();
							ctx.fillStyle = active ? '#60a5fa' : '#475569';
							ctx.fill();
						}
					})
					.nodePointerAreaPaint((node: any, color: string, ctx: CanvasRenderingContext2D) => {
						const n = node as GraphNode;
						const size = getNodeSize(n) + 4;
						ctx.beginPath();
						ctx.arc(node.x, node.y, size, 0, 2 * Math.PI);
						ctx.fillStyle = color;
						ctx.fill();
					})
					.backgroundColor('#0b0f19')
					.width(container.clientWidth || 600)
					.height(container.clientHeight || 500)
					.onNodeClick((node: any) => {
						const n = node as GraphNode;
						if (n.type === 'import') return;
						highlightedNodeId = n.id;
						neighborSet = adjacency.get(n.id) || new Set();
						onNodeClick(n.label);
					})
					.onNodeHover((node: any) => {
						if (node) {
							hoveredNodeId = node.id;
							if (!highlightedNodeId) {
								neighborSet = adjacency.get(node.id) || new Set();
							}
						} else {
							hoveredNodeId = null;
							if (!highlightedNodeId) {
								neighborSet = new Set();
							}
						}
						if (container) container.style.cursor = node ? 'pointer' : 'default';
					})
					.onBackgroundClick(() => {
						clearHighlight();
					})
					.cooldownTicks(0);

				// Disable all forces — dagre positions are authoritative
				g.d3Force('link', null);
				g.d3Force('charge', null);
				g.d3Force('center', null);

				// Fit to view since positions are pre-computed
				setTimeout(() => {
					if (g) g.zoomToFit(300, 40);
				}, 100);

				// Resize observer
				ro = new ResizeObserver(() => {
					if (g && container) {
						g.width(container.clientWidth).height(container.clientHeight);
					}
				});
				ro.observe(container);

				graph = g;

				// Escape key handler
				const handleKey = (e: KeyboardEvent) => {
					if (e.key === 'Escape') {
						clearHighlight();
						searchOpen = false;
					}
				};
				document.addEventListener('keydown', handleKey);
				(g as any).__keyCleanup = () => {
					document.removeEventListener('keydown', handleKey);
				};

			} catch (err) {
				console.error('CodeGraphVisual: failed to initialize', err);
				initError = err instanceof Error ? err.message : String(err);
			}
		})();

		return () => {
			if (ro) ro.disconnect();
			if (g) {
				(g as any).__keyCleanup?.();
				g.pauseAnimation();
				g._destructor?.();
			}
		};
	});

	async function toggleImports() {
		if (!graph) return;
		showImports = !showImports;
		const rawData = getActiveData();
		adjacency = buildAdjacency(rawData.links);

		// Create plain copies to avoid Svelte proxy issues
		const plainNodes = rawData.nodes.map(n => ({ ...n }));
		const plainLinks = rawData.links.map(l => ({ ...l }));

		// Re-compute dagre layout for new data
		const layout = await computeDagreLayout(plainNodes, plainLinks);
		const wpMap = new Map<string, EdgeWaypoints>();
		for (const ew of layout.edgeWaypoints) {
			wpMap.set(`${ew.source}->${ew.target}`, ew);
		}
		edgeWaypointMap = wpMap;

		for (const node of plainNodes) {
			const positioned = layout.nodes.find(n => n.id === node.id);
			if (positioned) {
				(node as any).fx = positioned.x;
				(node as any).fy = positioned.y;
				node.x = positioned.x;
				node.y = positioned.y;
			}
		}

		graph.graphData({ nodes: plainNodes, links: plainLinks });
		setTimeout(() => {
			if (graph) graph.zoomToFit(300, 40);
		}, 100);
	}

	function zoomIn() { if (graph) graph.zoom(graph.zoom() * 1.4, 200); }
	function zoomOut() { if (graph) graph.zoom(graph.zoom() / 1.4, 200); }
	function fitGraph() { if (graph) graph.zoomToFit(300, 40); }
</script>

<div class="graph-visual-container">
	<!-- Toolbar -->
	<div class="graph-toolbar">
		<!-- Search input -->
		<div class="graph-toolbar-group graph-search-group">
			<div class="graph-search-wrap">
				<svg class="graph-search-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
					<circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/>
				</svg>
				<input
					class="graph-search-input"
					type="text"
					placeholder="Search functions..."
					value={searchQuery}
					oninput={(e) => updateSearch(e.currentTarget.value)}
					onkeydown={handleSearchKeydown}
					onfocus={() => { if (searchResults.length > 0) searchOpen = true; }}
					onblur={() => { setTimeout(() => { searchOpen = false; }, 150); }}
				/>
			</div>
			{#if searchOpen && searchResults.length > 0}
				<div class="graph-search-dropdown">
					{#each searchResults as result, i}
						<button
							class="graph-search-result"
							class:graph-search-result-active={i === searchSelectedIdx}
							onmousedown={() => selectSearchResult(result)}
						>
							<span class="graph-search-result-dot" style="background: {NODE_COLORS[result.type]}"></span>
							<span class="graph-search-result-label">{result.label}</span>
							{#if result.file}
								<span class="graph-search-result-file">{result.file.split('/').pop()}</span>
							{/if}
						</button>
					{/each}
				</div>
			{/if}
		</div>

		<div class="graph-toolbar-sep"></div>

		<div class="graph-toolbar-group">
			<span class="graph-toolbar-label">FILTER</span>
			<button
				class="graph-toolbar-btn"
				class:graph-toolbar-btn-active={showImports}
				onclick={toggleImports}
			>Imports</button>
		</div>

		<div class="graph-toolbar-sep"></div>

		<div class="graph-toolbar-group">
			<button class="graph-toolbar-btn" onclick={zoomIn} aria-label="Zoom in">+</button>
			<button class="graph-toolbar-btn" onclick={zoomOut} aria-label="Zoom out">-</button>
			<button class="graph-toolbar-btn" onclick={fitGraph}>Fit</button>
		</div>
	</div>

	<!-- Graph canvas -->
	<div class="graph-canvas-wrap">
		<div class="graph-canvas" bind:this={container}></div>

		{#if initError}
			<div class="graph-error">
				<span>Graph failed to load: {initError}</span>
			</div>
		{/if}

		<!-- Floating stats badge (bottom-right) -->
		<div class="graph-stats-badge">
			{stats.nodes} nodes &middot; {stats.edges} edges{#if isFiltered} &middot; filtered from {totalFunctions}{/if}
		</div>

		<!-- Floating legend (bottom-left) -->
		<div class="graph-legend-float">
			<span class="graph-legend-dot" style="background: #6366f1"></span><span>Tool</span>
			<span class="graph-legend-dot" style="background: #475569"></span><span>Fn</span>
			<span class="graph-legend-dot graph-legend-diamond" style="background: #ef4444"></span><span>Danger</span>
			<span class="graph-legend-dot graph-legend-diamond" style="background: #f97316"></span><span>Net</span>
			<span class="graph-legend-dot graph-legend-diamond" style="background: #eab308"></span><span>I/O</span>
			<span class="graph-legend-dot" style="background: #334155"></span><span>Import</span>
		</div>
	</div>
</div>

<style>
	.graph-visual-container {
		display: flex;
		flex-direction: column;
		flex: 1;
		min-height: 0;
	}

	/* ── Toolbar ── */
	.graph-toolbar {
		display: flex;
		align-items: center;
		gap: 8px;
		padding: 8px 12px;
		background: var(--color-bg);
		border-bottom: 1px solid var(--color-edge);
		font-family: var(--font-mono);
		font-size: 11px;
	}
	.graph-toolbar-group {
		display: flex;
		align-items: center;
		gap: 4px;
	}
	.graph-toolbar-label {
		font-size: 10px;
		font-weight: 600;
		color: var(--color-t4);
		letter-spacing: 0.05em;
		margin-right: 4px;
	}
	.graph-toolbar-btn {
		padding: 4px 10px;
		border-radius: 4px;
		border: 1px solid var(--color-edge);
		background: var(--color-bg-raised);
		color: var(--color-t3);
		cursor: pointer;
		font-family: var(--font-mono);
		font-size: 11px;
		transition: all 0.12s;
	}
	.graph-toolbar-btn:hover {
		border-color: var(--color-blue);
		color: var(--color-t1);
	}
	.graph-toolbar-btn-active {
		background: var(--color-blue);
		border-color: var(--color-blue);
		color: white;
	}
	.graph-toolbar-sep {
		width: 1px;
		height: 18px;
		background: var(--color-edge);
	}

	/* ── Search ── */
	.graph-search-group {
		position: relative;
		flex: 1;
		max-width: 260px;
	}
	.graph-search-wrap {
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 3px 8px;
		border-radius: 4px;
		border: 1px solid var(--color-edge);
		background: var(--color-bg-raised);
		transition: border-color 0.12s;
	}
	.graph-search-wrap:focus-within {
		border-color: var(--color-blue);
	}
	.graph-search-icon {
		color: var(--color-t4);
		flex-shrink: 0;
	}
	.graph-search-input {
		flex: 1;
		border: none;
		outline: none;
		background: transparent;
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-t1);
		padding: 2px 0;
	}
	.graph-search-input::placeholder {
		color: var(--color-t4);
	}
	.graph-search-dropdown {
		position: absolute;
		top: 100%;
		left: 0;
		right: 0;
		margin-top: 4px;
		background: var(--color-bg-raised);
		border: 1px solid var(--color-edge);
		border-radius: 6px;
		overflow: hidden;
		z-index: 20;
		box-shadow: 0 8px 24px rgba(0,0,0,0.4);
	}
	.graph-search-result {
		display: flex;
		align-items: center;
		gap: 8px;
		width: 100%;
		padding: 6px 10px;
		border: none;
		background: transparent;
		cursor: pointer;
		font-family: var(--font-mono);
		font-size: 11px;
		color: var(--color-t2);
		text-align: left;
		transition: background 0.08s;
	}
	.graph-search-result:hover,
	.graph-search-result-active {
		background: color-mix(in srgb, var(--color-blue) 10%, transparent);
		color: var(--color-t1);
	}
	.graph-search-result-dot {
		width: 6px;
		height: 6px;
		border-radius: 50%;
		flex-shrink: 0;
	}
	.graph-search-result-label {
		flex: 1;
		min-width: 0;
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.graph-search-result-file {
		font-size: 10px;
		color: var(--color-t4);
		flex-shrink: 0;
	}

	/* ── Canvas ── */
	.graph-canvas-wrap {
		flex: 1;
		min-height: 0;
		position: relative;
	}
	.graph-canvas {
		width: 100%;
		height: 100%;
	}

	.graph-error {
		position: absolute;
		top: 50%;
		left: 50%;
		transform: translate(-50%, -50%);
		padding: 12px 20px;
		background: #1e1215;
		border: 1px solid #f43f5e40;
		border-radius: 6px;
		font-family: var(--font-mono);
		font-size: 12px;
		color: #f43f5e;
	}

	/* ── Floating stats badge ── */
	.graph-stats-badge {
		position: absolute;
		bottom: 10px;
		right: 10px;
		padding: 4px 10px;
		border-radius: 4px;
		background: rgba(11, 15, 25, 0.8);
		border: 1px solid var(--color-edge);
		font-family: var(--font-mono);
		font-size: 10px;
		color: var(--color-t4);
		pointer-events: none;
		z-index: 10;
	}

	/* ── Floating legend ── */
	.graph-legend-float {
		position: absolute;
		bottom: 10px;
		left: 10px;
		display: flex;
		align-items: center;
		gap: 6px;
		padding: 5px 10px;
		border-radius: 4px;
		background: rgba(11, 15, 25, 0.8);
		border: 1px solid var(--color-edge);
		font-family: var(--font-mono);
		font-size: 9px;
		color: var(--color-t4);
		pointer-events: none;
		z-index: 10;
	}
	.graph-legend-dot {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		flex-shrink: 0;
		margin-left: 4px;
	}
	.graph-legend-dot:first-child {
		margin-left: 0;
	}
	.graph-legend-diamond {
		border-radius: 1px;
		transform: rotate(45deg);
		width: 6px;
		height: 6px;
	}
</style>
