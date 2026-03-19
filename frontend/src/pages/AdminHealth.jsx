import { useState, useEffect, useCallback, useRef } from 'react'
import { adminAPI } from '../services/api'
import Layout from '../components/Layout'
import {
    Database, Zap, Terminal, Activity, Layers,
    AlertTriangle, RefreshCw, CheckCircle, XCircle,
    Cpu, MemoryStick
} from 'lucide-react'
import {
    Chart as ChartJS,
    CategoryScale,
    LinearScale,
    PointElement,
    LineElement,
    Title,
    Tooltip,
    Legend,
    Filler,
} from 'chart.js'
import { Line } from 'react-chartjs-2'

ChartJS.register(
    CategoryScale, LinearScale, PointElement, LineElement,
    Title, Tooltip, Legend, Filler
)

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtTime(iso) {
    const d = new Date(iso)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

// ── Status Card ─────────────────────────────────────────────────────────────

function StatusCard({ icon: Icon, label, value, ok, subtitle }) {
    const isBoolean = typeof ok === 'boolean'
    const statusColor = isBoolean
        ? (ok ? 'text-emerald-400' : 'text-red-400')
        : 'text-netrix-accent'
    const borderColor = isBoolean
        ? (ok ? 'border-emerald-500/20' : 'border-red-500/20')
        : 'border-netrix-accent/20'
    const bgColor = isBoolean
        ? (ok ? 'from-emerald-500/5 to-emerald-600/5' : 'from-red-500/5 to-red-600/5')
        : 'from-netrix-accent/5 to-blue-600/5'

    return (
        <div className={`rounded-xl border ${borderColor} bg-gradient-to-br ${bgColor} p-5 flex flex-col gap-3`}>
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <Icon className={`w-5 h-5 ${statusColor}`} />
                    <span className="text-sm font-medium text-netrix-muted">{label}</span>
                </div>
                {isBoolean && (
                    ok
                        ? <CheckCircle className="w-4 h-4 text-emerald-400" />
                        : <XCircle className="w-4 h-4 text-red-400" />
                )}
            </div>
            <div className={`text-2xl font-bold ${statusColor}`}>
                {isBoolean ? (ok ? 'Online' : 'Offline') : value}
            </div>
            {subtitle && <p className="text-xs text-netrix-muted">{subtitle}</p>}
        </div>
    )
}

// ── Line Chart ──────────────────────────────────────────────────────────────

function MetricLineChart({ points, label, dataKey, color }) {
    const labels = points.map(p => fmtTime(p.recorded_at))
    const data = points.map(p => parseFloat(p[dataKey].toFixed(1)))

    const chartData = {
        labels,
        datasets: [
            {
                label,
                data,
                borderColor: color,
                backgroundColor: color + '18',
                fill: true,
                tension: 0.3,
                pointRadius: points.length > 50 ? 0 : 3,
                pointHoverRadius: 5,
                borderWidth: 2,
            },
        ],
    }

    const options = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: { display: false },
            tooltip: {
                backgroundColor: '#1a1f2e',
                borderColor: '#2a3040',
                borderWidth: 1,
                callbacks: {
                    label: ctx => `${ctx.parsed.y.toFixed(1)}%`,
                },
            },
        },
        scales: {
            x: {
                ticks: {
                    color: '#6b7280',
                    maxTicksLimit: 8,
                    font: { size: 11 },
                },
                grid: { color: '#2a304020' },
            },
            y: {
                min: 0,
                max: 100,
                ticks: {
                    color: '#6b7280',
                    callback: v => `${v}%`,
                    font: { size: 11 },
                },
                grid: { color: '#2a304040' },
            },
        },
    }

    return (
        <div className="h-56">
            {points.length === 0
                ? <div className="h-full flex items-center justify-center text-netrix-muted text-sm">
                    No data collected yet — metrics are stored every 5 minutes.
                  </div>
                : <Line data={chartData} options={options} />
            }
        </div>
    )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function AdminHealth() {
    const [health, setHealth] = useState(null)
    const [metrics, setMetrics] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [lastRefresh, setLastRefresh] = useState(null)
    const intervalRef = useRef(null)

    const fetchData = useCallback(async () => {
        try {
            const [hRes, mRes] = await Promise.all([
                adminAPI.health(),
                adminAPI.metrics(24),
            ])
            setHealth(hRes.data)
            setMetrics(mRes.data)
            setLastRefresh(new Date())
            setError(null)
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load health data.')
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => {
        fetchData()
        intervalRef.current = setInterval(fetchData, 30_000)
        return () => clearInterval(intervalRef.current)
    }, [fetchData])

    return (
        <Layout>
            <div className="max-w-6xl mx-auto space-y-6">

                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text">System Health</h1>
                        <p className="text-sm text-netrix-muted mt-0.5">
                            Live service status and resource utilisation
                        </p>
                    </div>
                    <div className="flex items-center gap-3">
                        {lastRefresh && (
                            <span className="text-xs text-netrix-muted">
                                Refreshed {lastRefresh.toLocaleTimeString()} · auto-refresh 30s
                            </span>
                        )}
                        <button
                            onClick={fetchData}
                            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-netrix-accent/10 text-netrix-accent hover:bg-netrix-accent/20 transition-colors text-sm font-medium"
                        >
                            <RefreshCw className="w-4 h-4" />
                            Refresh
                        </button>
                    </div>
                </div>

                {/* Error */}
                {error && (
                    <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                        <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                        {error}
                    </div>
                )}

                {/* Status Cards */}
                {loading ? (
                    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-3 gap-4">
                        {Array.from({ length: 6 }).map((_, i) => (
                            <div key={i} className="h-32 rounded-xl bg-netrix-card/60 animate-pulse" />
                        ))}
                    </div>
                ) : health && (
                    <div className="grid grid-cols-2 sm:grid-cols-3 gap-4">
                        <StatusCard
                            icon={Database}
                            label="MySQL"
                            ok={health.mysql_status}
                            subtitle="Primary database"
                        />
                        <StatusCard
                            icon={Zap}
                            label="Redis"
                            ok={health.redis_status}
                            subtitle="Cache & queue"
                        />
                        <StatusCard
                            icon={Terminal}
                            label="Nmap"
                            ok={health.nmap_status}
                            subtitle="Scan engine"
                        />
                        <StatusCard
                            icon={Activity}
                            label="Active Scans"
                            value={health.active_scans}
                            subtitle="Currently running"
                        />
                        <StatusCard
                            icon={Layers}
                            label="Queue Depth"
                            value={health.queue_depth}
                            subtitle="Tasks waiting in Redis"
                        />
                        <StatusCard
                            icon={AlertTriangle}
                            label="Failed (24h)"
                            value={health.failed_scans_24h}
                            subtitle="Scans failed in last 24 hours"
                        />
                    </div>
                )}

                {/* Charts */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                    <div className="rounded-xl border border-netrix-border/50 bg-netrix-card/80 p-5">
                        <div className="flex items-center gap-2 mb-4">
                            <Cpu className="w-4 h-4 text-netrix-accent" />
                            <h2 className="text-sm font-semibold text-netrix-text">CPU Usage — last 24h</h2>
                        </div>
                        {metrics
                            ? <MetricLineChart
                                points={metrics.points}
                                label="CPU %"
                                dataKey="cpu_percent"
                                color="#06b6d4"
                              />
                            : <div className="h-56 flex items-center justify-center">
                                <div className="w-8 h-8 border-2 border-netrix-accent border-t-transparent rounded-full animate-spin" />
                              </div>
                        }
                    </div>

                    <div className="rounded-xl border border-netrix-border/50 bg-netrix-card/80 p-5">
                        <div className="flex items-center gap-2 mb-4">
                            <MemoryStick className="w-4 h-4 text-purple-400" />
                            <h2 className="text-sm font-semibold text-netrix-text">Memory Usage — last 24h</h2>
                        </div>
                        {metrics
                            ? <MetricLineChart
                                points={metrics.points}
                                label="Memory %"
                                dataKey="memory_percent"
                                color="#a855f7"
                              />
                            : <div className="h-56 flex items-center justify-center">
                                <div className="w-8 h-8 border-2 border-purple-400 border-t-transparent rounded-full animate-spin" />
                              </div>
                        }
                    </div>
                </div>

            </div>
        </Layout>
    )
}
