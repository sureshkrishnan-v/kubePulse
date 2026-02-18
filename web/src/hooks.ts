import { useState, useEffect, useCallback, useRef } from 'react';

export function usePolling<T>(fetcher: () => Promise<T>, intervalMs = 5000) {
    const [data, setData] = useState<T | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const poll = useCallback(async () => {
        try {
            const result = await fetcher();
            setData(result);
            setError(null);
        } catch (e) {
            setError(e instanceof Error ? e.message : 'fetch failed');
        } finally {
            setLoading(false);
        }
    }, [fetcher]);

    useEffect(() => {
        poll();
        const id = setInterval(poll, intervalMs);
        return () => clearInterval(id);
    }, [poll, intervalMs]);

    return { data, loading, error, refetch: poll };
}

export function useWebSocket<T>(url: string) {
    const [messages, setMessages] = useState<T[]>([]);
    const wsRef = useRef<WebSocket | null>(null);

    useEffect(() => {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const ws = new WebSocket(`${proto}//${window.location.host}${url}`);
        wsRef.current = ws;

        ws.onmessage = (e) => {
            try {
                const msg = JSON.parse(e.data) as T;
                setMessages((prev) => [msg, ...prev].slice(0, 100));
            } catch { /* ignore */ }
        };

        return () => ws.close();
    }, [url]);

    return messages;
}
