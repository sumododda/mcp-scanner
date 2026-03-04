const API_BASE = 'http://localhost:8000';

const API_KEY_STORAGE_KEY = 'mcp_scanner_api_key';

export function getApiKey(): string {
	return localStorage.getItem(API_KEY_STORAGE_KEY) ?? '';
}

export function setApiKey(key: string): void {
	if (key) {
		localStorage.setItem(API_KEY_STORAGE_KEY, key);
	} else {
		localStorage.removeItem(API_KEY_STORAGE_KEY);
	}
}

function authHeaders(): Record<string, string> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	const key = getApiKey();
	if (key) {
		headers['Authorization'] = `Bearer ${key}`;
	}
	return headers;
}

export interface Finding {
	id: string;
	checker: string;
	severity: 'critical' | 'high' | 'medium' | 'low';
	title: string;
	description: string;
	evidence: string;
	location: string;
	remediation: string;
	cwe_id?: string;
	llm_analysis?: string;
	source_file?: string;
	source_line?: number;
	dismissed_as?: string;
	dismissed_reason?: string;
}

export interface SecurityQuestion {
	id: string;
	question: string;
	answer: string;
	status: 'clear' | 'issue' | 'skipped';
	items_checked: number;
	items_checked_label: string;
	finding_ids: string[];
	severity: 'critical' | 'high' | 'medium' | 'low' | null;
	detail?: string;
}

export interface CheckerDetail {
	id: string;
	description: string;
	status: string;
	items_checked: number;
	findings_count: number;
	checks: string[];
	error?: string;
	security_questions?: SecurityQuestion[];
}

export interface ScanSummary {
	total: number;
	by_severity: Record<string, number>;
	by_checker: Record<string, number>;
	checker_details?: CheckerDetail[];
}

export interface ToolParam {
	name: string;
	type: string;
	description: string;
	required: boolean;
}

export interface ToolSnapshot {
	server_name: string;
	tool_name: string;
	description: string;
	parameters: ToolParam[];
	parameter_count: number;
}

export interface PromptArgument {
	name: string;
	description: string;
	required: boolean;
}

export interface Prompt {
	name: string;
	title?: string;
	description: string;
	arguments: PromptArgument[];
	argument_count: number;
}

export interface Resource {
	name: string;
	title?: string;
	uri: string;
	description: string;
	mime_type?: string;
	size?: number;
}

export interface ServerOverview {
	name: string;
	tools: ToolSnapshot[];
	tool_count: number;
	prompts: Prompt[];
	prompt_count: number;
	resources: Resource[];
	resource_count: number;
}

export interface CodeGraphStats {
	total_functions: number;
	total_imports: number;
	total_call_sites: number;
	tool_handlers: number;
	dangerous_calls: number;
	network_calls: number;
	file_access_calls: number;
}

export interface CodeGraphFunction {
	name: string;
	file: string;
	line: number;
	params: string[];
	is_tool_handler: boolean;
	docstring: string | null;
	body_text: string;
}

export interface CodeGraphImport {
	module: string;
	names: string[];
	file: string;
}

export interface CodeGraphCallSite {
	callee: string;
	file: string;
	line: number;
	parent: string | null;
	args: string;
}

export interface CodeGraphData {
	functions: CodeGraphFunction[];
	imports: CodeGraphImport[];
	call_sites: CodeGraphCallSite[];
	tool_handlers: string[];
	stats: CodeGraphStats;
}

export interface ScanResult {
	id: string;
	status: string;
	created_at: string;
	overall_score: number | null;
	grade: string | null;
	repo_url?: string | null;
	commit_hash?: string | null;
	summary: ScanSummary | null;
	findings: Finding[];
	error_message?: string;
	servers?: ServerOverview[];
	code_graph?: CodeGraphData | null;
}

export interface ScanOptions {
	llm_judge_enabled?: boolean;
}

export async function startScan(repoUrl: string, options?: ScanOptions): Promise<ScanResult> {
	const resp = await fetch(`${API_BASE}/api/scan`, {
		method: 'POST',
		headers: authHeaders(),
		body: JSON.stringify({ repo_url: repoUrl, ...options })
	});
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

export interface ScanListItem {
	id: string;
	status: string;
	created_at: string;
	overall_score: number | null;
	grade: string | null;
	repo_url?: string | null;
	commit_hash?: string | null;
	summary: ScanSummary | null;
}

export interface PaginatedScans {
	scans: ScanListItem[];
	total: number;
	page: number;
	per_page: number;
}

export async function getScan(scanId: string): Promise<ScanResult> {
	const resp = await fetch(`${API_BASE}/api/scan/${scanId}`, { headers: authHeaders() });
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

/** @deprecated Use getScan instead */
export const getScanStatus = getScan;

export async function getHistory(page = 1, perPage = 20): Promise<PaginatedScans> {
	const resp = await fetch(`${API_BASE}/api/history?page=${page}&per_page=${perPage}`, { headers: authHeaders() });
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

export async function deleteScan(scanId: string): Promise<void> {
	const resp = await fetch(`${API_BASE}/api/scan/${scanId}`, { method: 'DELETE', headers: authHeaders() });
	if (!resp.ok) throw new Error(await resp.text());
}

export async function dismissFinding(
	findingId: string,
	dismissedAs: string,
	reason: string
): Promise<Finding> {
	const resp = await fetch(`${API_BASE}/api/finding/${findingId}/dismiss`, {
		method: 'PATCH',
		headers: authHeaders(),
		body: JSON.stringify({ dismissed_as: dismissedAs, reason })
	});
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

export async function restoreFinding(findingId: string): Promise<Finding> {
	const resp = await fetch(`${API_BASE}/api/finding/${findingId}/dismiss`, {
		method: 'DELETE',
		headers: authHeaders()
	});
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

export interface ScannerSettings {
	openrouter_api_key: string;
	openrouter_model: string;
	llm_judge_enabled: boolean;
}

export async function getSettings(): Promise<ScannerSettings> {
	const resp = await fetch(`${API_BASE}/api/settings`, { headers: authHeaders() });
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

export async function updateSettings(updates: Partial<ScannerSettings>): Promise<ScannerSettings> {
	const resp = await fetch(`${API_BASE}/api/settings`, {
		method: 'PUT',
		headers: authHeaders(),
		body: JSON.stringify(updates)
	});
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

// ── Triage Chat ──

export interface TriageChatMessage {
	role: 'user' | 'assistant';
	content: string;
}

export function streamTriageChat(
	findingId: string,
	message: string,
	history: TriageChatMessage[],
	onToken: (token: string) => void,
	onDone: () => void,
	onError: (error: string) => void
): AbortController {
	const controller = new AbortController();

	(async () => {
		try {
			const resp = await fetch(`${API_BASE}/api/finding/${findingId}/triage`, {
				method: 'POST',
				headers: authHeaders(),
				body: JSON.stringify({ message, history }),
				signal: controller.signal
			});

			if (!resp.ok) {
				const text = await resp.text();
				onError(`${resp.status}: ${text}`);
				return;
			}

			const reader = resp.body!.getReader();
			const decoder = new TextDecoder();
			let buffer = '';

			while (true) {
				const { done, value } = await reader.read();
				if (done) break;

				buffer += decoder.decode(value, { stream: true });
				const lines = buffer.split('\n');
				buffer = lines.pop() || '';

				for (const line of lines) {
					if (!line.startsWith('data: ')) continue;
					const payload = line.slice(6);
					if (payload === '[DONE]') {
						onDone();
						return;
					}
					try {
						const data = JSON.parse(payload);
						if (data.error) {
							onError(data.error);
							return;
						}
						if (data.token) onToken(data.token);
					} catch {
						// ignore malformed chunks
					}
				}
			}
			onDone();
		} catch (err: unknown) {
			if (err instanceof DOMException && err.name === 'AbortError') return;
			onError(err instanceof Error ? err.message : 'Unknown error');
		}
	})();

	return controller;
}

// ── Code Graph Chat ──

export function streamCodeGraphChat(
	scanId: string,
	message: string,
	history: TriageChatMessage[],
	onToken: (token: string) => void,
	onDone: () => void,
	onError: (error: string) => void
): AbortController {
	const controller = new AbortController();

	(async () => {
		try {
			const resp = await fetch(`${API_BASE}/api/scan/${scanId}/graph/chat`, {
				method: 'POST',
				headers: authHeaders(),
				body: JSON.stringify({ message, history }),
				signal: controller.signal
			});

			if (!resp.ok) {
				const text = await resp.text();
				onError(`${resp.status}: ${text}`);
				return;
			}

			const reader = resp.body!.getReader();
			const decoder = new TextDecoder();
			let buffer = '';

			while (true) {
				const { done, value } = await reader.read();
				if (done) break;

				buffer += decoder.decode(value, { stream: true });
				const lines = buffer.split('\n');
				buffer = lines.pop() || '';

				for (const line of lines) {
					if (!line.startsWith('data: ')) continue;
					const payload = line.slice(6);
					if (payload === '[DONE]') {
						onDone();
						return;
					}
					try {
						const data = JSON.parse(payload);
						if (data.error) {
							onError(data.error);
							return;
						}
						if (data.token) onToken(data.token);
					} catch {
						// ignore malformed chunks
					}
				}
			}
			onDone();
		} catch (err: unknown) {
			if (err instanceof DOMException && err.name === 'AbortError') return;
			onError(err instanceof Error ? err.message : 'Unknown error');
		}
	})();

	return controller;
}

// ── SBOM ──

export interface SbomVulnerability {
	id: string;
	summary: string;
	aliases: string[];
	purl: string;
	fixed_version: string | null;
}

export interface SbomEntry {
	id: string;
	scan_id: string;
	server_name: string;
	package_name: string;
	package_version: string;
	format: string;
	sbom_data: Record<string, unknown>;
	dependency_count: number;
	vulnerability_count: number;
	vulnerabilities: SbomVulnerability[];
}

export async function getScanSbom(scanId: string): Promise<SbomEntry[]> {
	const resp = await fetch(`${API_BASE}/api/scan/${scanId}/sbom`, { headers: authHeaders() });
	if (!resp.ok) throw new Error(await resp.text());
	return resp.json();
}

