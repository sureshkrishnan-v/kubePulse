import { useState, useCallback } from 'react';
import { Activity, Wifi, Shield, AlertTriangle, Zap, Clock, ChevronLeft, ChevronRight } from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts';
import { fetchOverview, fetchEvents, fetchMetrics, fetchTopology } from './api';
import type { Overview, Event, MetricPoint, TopologyItem } from './api';
import { usePolling } from './hooks';
import './index.css';

// ─── Stat Card ──────────────────────────────────────────────────
function StatCard({ label, value, icon: Icon, color }: {
  label: string; value: string | number; icon: React.ElementType; color: string;
}) {
  return (
    <div className="glass stat-card p-5 flex items-center gap-4">
      <div className={`p-3 rounded-xl ${color}`}>
        <Icon className="w-6 h-6 text-white" />
      </div>
      <div>
        <p className="text-sm text-[var(--text-muted)]">{label}</p>
        <p className="text-2xl font-bold tracking-tight">{typeof value === 'number' ? value.toLocaleString() : value}</p>
      </div>
    </div>
  );
}

// ─── Overview Dashboard ─────────────────────────────────────────
function OverviewSection({ data }: { data: Overview }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-6 gap-4">
      <StatCard label="Total Events" value={data.total_events} icon={Activity} color="bg-indigo-600" />
      <StatCard label="TCP Events" value={data.tcp_events} icon={Wifi} color="bg-blue-600" />
      <StatCard label="DNS Events" value={data.dns_events} icon={Shield} color="bg-emerald-600" />
      <StatCard label="OOM Kills" value={data.oom_events} icon={AlertTriangle} color="bg-red-600" />
      <StatCard label="Packet Drops" value={data.drop_events} icon={Zap} color="bg-amber-600" />
      <StatCard label="Avg Latency" value={`${(data.avg_latency_sec * 1000).toFixed(2)}ms`} icon={Clock} color="bg-purple-600" />
    </div>
  );
}

// ─── Metrics Chart ──────────────────────────────────────────────
function MetricsChart({ type }: { type: string }) {
  const fetcher = useCallback(() => fetchMetrics(type), [type]);
  const { data } = usePolling(fetcher, 10000);

  const series = data?.series ?? [];
  const formatted = series.map((p: MetricPoint) => ({
    ...p,
    time: new Date(p.time).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    avg_ms: p.avg_latency * 1000,
    p99_ms: p.p99_latency * 1000,
  }));

  return (
    <div className="glass p-5">
      <h3 className="text-lg font-semibold mb-4 capitalize">{type} Metrics</h3>
      <div className="h-64">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={formatted}>
            <defs>
              <linearGradient id="grad1" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#6366f1" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#6366f1" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="grad2" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ef4444" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#ef4444" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(99,102,241,0.1)" />
            <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} />
            <YAxis stroke="#94a3b8" fontSize={12} />
            <Tooltip
              contentStyle={{ background: '#1e293b', border: '1px solid rgba(99,102,241,0.3)', borderRadius: 8, color: '#e2e8f0' }}
            />
            <Area type="monotone" dataKey="count" stroke="#6366f1" fill="url(#grad1)" strokeWidth={2} name="Count" />
            <Area type="monotone" dataKey="p99_ms" stroke="#ef4444" fill="url(#grad2)" strokeWidth={2} name="P99 (ms)" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}

// ─── Events Table ───────────────────────────────────────────────
function EventsTable() {
  const [page, setPage] = useState(0);
  const [typeFilter, setTypeFilter] = useState('');
  const limit = 50;

  const fetcher = useCallback(
    () => fetchEvents({ limit, offset: page * limit, type: typeFilter || undefined }),
    [page, typeFilter]
  );
  const { data, loading } = usePolling(fetcher, 5000);

  const events: Event[] = data?.events ?? [];

  const typeColors: Record<string, string> = {
    tcp: 'bg-blue-500/20 text-blue-400',
    dns: 'bg-emerald-500/20 text-emerald-400',
    oom: 'bg-red-500/20 text-red-400',
    drop: 'bg-amber-500/20 text-amber-400',
    exec: 'bg-purple-500/20 text-purple-400',
    fileio: 'bg-cyan-500/20 text-cyan-400',
    retransmit: 'bg-orange-500/20 text-orange-400',
    rst: 'bg-rose-500/20 text-rose-400',
  };

  return (
    <div className="glass p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold">Events</h3>
        <div className="flex items-center gap-3">
          <select
            value={typeFilter}
            onChange={(e) => { setTypeFilter(e.target.value); setPage(0); }}
            className="bg-[var(--bg-card)] border border-[var(--border)] rounded-lg px-3 py-1.5 text-sm text-[var(--text-primary)] focus:outline-none focus:border-[var(--accent)]"
          >
            <option value="">All Types</option>
            {['tcp', 'dns', 'oom', 'drop', 'exec', 'fileio', 'retransmit', 'rst'].map(t => (
              <option key={t} value={t}>{t.toUpperCase()}</option>
            ))}
          </select>
          <div className="flex items-center gap-1">
            <button onClick={() => setPage(Math.max(0, page - 1))} disabled={page === 0}
              className="p-1.5 rounded-lg hover:bg-[var(--bg-card-hover)] disabled:opacity-30 transition">
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="text-sm text-[var(--text-muted)] min-w-[3rem] text-center">
              {page + 1}
            </span>
            <button onClick={() => setPage(page + 1)} disabled={events.length < limit}
              className="p-1.5 rounded-lg hover:bg-[var(--bg-card-hover)] disabled:opacity-30 transition">
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-[var(--text-muted)] border-b border-[var(--border)]">
              <th className="pb-3 pr-4">Time</th>
              <th className="pb-3 pr-4">Type</th>
              <th className="pb-3 pr-4">Comm</th>
              <th className="pb-3 pr-4">PID</th>
              <th className="pb-3 pr-4">Namespace</th>
              <th className="pb-3 pr-4">Pod</th>
              <th className="pb-3">Details</th>
            </tr>
          </thead>
          <tbody>
            {loading && events.length === 0 ? (
              <tr><td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">Loading...</td></tr>
            ) : events.length === 0 ? (
              <tr><td colSpan={7} className="py-8 text-center text-[var(--text-muted)]">No events yet</td></tr>
            ) : events.map((evt, i) => (
              <tr key={i} className="event-row border-b border-[var(--border)]">
                <td className="py-2.5 pr-4 font-mono text-xs text-[var(--text-muted)]">
                  {new Date(evt.timestamp).toLocaleTimeString()}
                </td>
                <td className="py-2.5 pr-4">
                  <span className={`px-2 py-0.5 rounded-md text-xs font-medium ${typeColors[evt.type] ?? 'bg-gray-500/20 text-gray-400'}`}>
                    {evt.type}
                  </span>
                </td>
                <td className="py-2.5 pr-4 font-mono">{evt.comm}</td>
                <td className="py-2.5 pr-4 font-mono text-[var(--text-muted)]">{evt.pid}</td>
                <td className="py-2.5 pr-4">{evt.namespace || '—'}</td>
                <td className="py-2.5 pr-4 max-w-[200px] truncate">{evt.pod || '—'}</td>
                <td className="py-2.5 text-xs text-[var(--text-muted)]">
                  {Object.entries(evt.labels || {}).map(([k, v]) => `${k}=${v}`).join(' ')}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ─── Topology ───────────────────────────────────────────────────
function TopologyView() {
  const fetcher = useCallback(() => fetchTopology(), []);
  const { data } = usePolling(fetcher, 15000);
  const items: TopologyItem[] = data?.topology ?? [];

  const grouped = items.reduce<Record<string, TopologyItem[]>>((acc, item) => {
    (acc[item.namespace] = acc[item.namespace] || []).push(item);
    return acc;
  }, {});

  return (
    <div className="glass p-5">
      <h3 className="text-lg font-semibold mb-4">Topology</h3>
      {Object.keys(grouped).length === 0 ? (
        <p className="text-[var(--text-muted)] text-sm">No topology data yet</p>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {Object.entries(grouped).map(([ns, pods]) => (
            <div key={ns} className="bg-[var(--bg-card)] rounded-lg p-3 border border-[var(--border)]">
              <div className="flex items-center gap-2 mb-2">
                <div className="w-2 h-2 rounded-full bg-indigo-500" />
                <span className="text-sm font-medium">{ns}</span>
                <span className="text-xs text-[var(--text-muted)] ml-auto">
                  {pods.reduce((s, p) => s + p.count, 0).toLocaleString()} events
                </span>
              </div>
              <div className="space-y-1">
                {pods.slice(0, 5).map((p, i) => (
                  <div key={i} className="flex items-center justify-between text-xs">
                    <span className="truncate max-w-[60%] text-[var(--text-muted)]">{p.pod}</span>
                    <span className="font-mono">{p.count.toLocaleString()}</span>
                  </div>
                ))}
                {pods.length > 5 && (
                  <p className="text-xs text-[var(--text-muted)]">+{pods.length - 5} more</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Main App ───────────────────────────────────────────────────
type Tab = 'overview' | 'events' | 'metrics' | 'topology';

export default function App() {
  const [tab, setTab] = useState<Tab>('overview');
  const [metricType, setMetricType] = useState('tcp');

  const overviewFetcher = useCallback(() => fetchOverview(), []);
  const { data: overview } = usePolling(overviewFetcher, 5000);

  const tabs: { id: Tab; label: string }[] = [
    { id: 'overview', label: 'Overview' },
    { id: 'events', label: 'Events' },
    { id: 'metrics', label: 'Metrics' },
    { id: 'topology', label: 'Topology' },
  ];

  return (
    <div className="min-h-screen">
      {/* Header */}
      <header className="sticky top-0 z-50 glass border-b border-[var(--border)] px-6 py-3 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-600 flex items-center justify-center">
            <Activity className="w-5 h-5 text-white" />
          </div>
          <h1 className="text-xl font-bold bg-gradient-to-r from-indigo-400 to-purple-400 bg-clip-text text-transparent">
            KubePulse
          </h1>
        </div>

        <nav className="flex items-center gap-1 bg-[var(--bg-card)] rounded-xl p-1">
          {tabs.map(({ id, label }) => (
            <button
              key={id}
              onClick={() => setTab(id)}
              className={`px-4 py-1.5 rounded-lg text-sm font-medium transition-all
                ${tab === id
                  ? 'bg-indigo-600 text-white shadow-lg shadow-indigo-500/25'
                  : 'text-[var(--text-muted)] hover:text-[var(--text-primary)]'
                }`}
            >
              {label}
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span className="text-xs text-[var(--text-muted)]">Live</span>
        </div>
      </header>

      {/* Content */}
      <main className="max-w-[1600px] mx-auto p-6 space-y-6">
        {tab === 'overview' && (
          <>
            {overview && <OverviewSection data={overview} />}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <MetricsChart type="tcp" />
              <MetricsChart type="dns" />
            </div>
            <EventsTable />
          </>
        )}

        {tab === 'events' && <EventsTable />}

        {tab === 'metrics' && (
          <div className="space-y-6">
            <div className="flex gap-2">
              {['tcp', 'dns', 'oom', 'drop', 'exec', 'fileio', 'retransmit', 'rst'].map(t => (
                <button
                  key={t}
                  onClick={() => setMetricType(t)}
                  className={`px-3 py-1.5 rounded-lg text-sm font-medium transition
                    ${metricType === t
                      ? 'bg-indigo-600 text-white'
                      : 'glass text-[var(--text-muted)] hover:text-white'
                    }`}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>
            <MetricsChart type={metricType} />
          </div>
        )}

        {tab === 'topology' && <TopologyView />}
      </main>
    </div>
  );
}
