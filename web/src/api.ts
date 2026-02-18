const API = '/api/v1';

export interface Event {
    timestamp: string;
    type: string;
    pid: number;
    comm: string;
    node: string;
    namespace: string;
    pod: string;
    labels: Record<string, string>;
    numerics: Record<string, number>;
}

export interface Overview {
    total_events: number;
    tcp_events: number;
    dns_events: number;
    oom_events: number;
    drop_events: number;
    avg_latency_sec: number;
    window: string;
}

export interface MetricPoint {
    time: string;
    count: number;
    avg_latency: number;
    p99_latency: number;
}

export interface TopologyItem {
    namespace: string;
    pod: string;
    node: string;
    count: number;
}

export async function fetchOverview(): Promise<Overview> {
    const r = await fetch(`${API}/metrics/overview`);
    return r.json();
}

export async function fetchEvents(params: {
    limit?: number;
    offset?: number;
    type?: string;
    namespace?: string;
    since?: string;
}): Promise<{ events: Event[]; limit: number; offset: number }> {
    const q = new URLSearchParams();
    if (params.limit) q.set('limit', String(params.limit));
    if (params.offset) q.set('offset', String(params.offset));
    if (params.type) q.set('type', params.type);
    if (params.namespace) q.set('namespace', params.namespace);
    if (params.since) q.set('since', params.since);
    const r = await fetch(`${API}/events?${q}`);
    return r.json();
}

export async function fetchEventTypes(): Promise<{ types: { type: string; count: number }[] }> {
    const r = await fetch(`${API}/events/types`);
    return r.json();
}

export async function fetchMetrics(type: string, window = '1h'): Promise<{ series: MetricPoint[] }> {
    const r = await fetch(`${API}/metrics/${type}?window=${window}`);
    return r.json();
}

export async function fetchTopology(): Promise<{ topology: TopologyItem[] }> {
    const r = await fetch(`${API}/topology`);
    return r.json();
}

export function connectWebSocket(onMessage: (event: Event) => void): WebSocket {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${proto}//${window.location.host}/ws/events`);
    ws.onmessage = (e) => {
        try {
            onMessage(JSON.parse(e.data));
        } catch { /* ignore */ }
    };
    return ws;
}
