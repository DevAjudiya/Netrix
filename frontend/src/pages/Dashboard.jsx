import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDispatch, useSelector } from 'react-redux'
import AdminSummary from '../components/AdminSummary'
import { setStats, setRecentScans, setVulnChart, setDashLoading } from '../store'
import { dashboardAPI } from '../services/api'
import { Pie } from 'react-chartjs-2'
import {
    Chart as ChartJS,
    ArcElement,
    Tooltip,
    Legend
} from 'chart.js'
import {
    Scan, Globe, Bug, AlertTriangle,
    Plus, ArrowRight, Clock, Target
} from 'lucide-react'
import Layout from '../components/Layout'
import LoadingSpinner from '../components/LoadingSpinner'
import VulnBadge from '../components/VulnBadge'
import { formatDateIST } from '../utils/formatDate'

ChartJS.register(ArcElement, Tooltip, Legend)

const statCards = [
    { key: 'total_scans', label: 'Total Scans', icon: Scan, color: 'from-blue-500 to-blue-600', shadow: 'shadow-blue-500/20' },
    { key: 'total_hosts', label: 'Hosts Discovered', icon: Globe, color: 'from-emerald-500 to-emerald-600', shadow: 'shadow-emerald-500/20' },
    { key: 'total_vulnerabilities', label: 'Vulnerabilities', icon: Bug, color: 'from-orange-500 to-orange-600', shadow: 'shadow-orange-500/20' },
    { key: 'critical_vulnerabilities', label: 'Critical Vulns', icon: AlertTriangle, color: 'from-red-500 to-red-600', shadow: 'shadow-red-500/20' },
]

export default function Dashboard() {
    const navigate = useNavigate()
    const dispatch = useDispatch()
    const { stats, recentScans, vulnChart, loading } = useSelector(s => s.dashboard)
    const { user } = useSelector(s => s.auth)
    const isAdmin = user?.role === 'admin'
    const [fetchError, setFetchError] = useState(null)

    useEffect(() => {
        const fetchData = async () => {
            dispatch(setDashLoading(true))
            setFetchError(null)
            try {
                const [statsRes, scansRes, chartRes] = await Promise.allSettled([
                    dashboardAPI.stats(),
                    dashboardAPI.recentScans(),
                    dashboardAPI.vulnChart()
                ])
                if (statsRes.status === 'fulfilled') dispatch(setStats(statsRes.value.data))
                if (scansRes.status === 'fulfilled')
                    dispatch(setRecentScans(scansRes.value.data?.recent_scans || []))
                if (chartRes.status === 'fulfilled') {
                    // API returns { data: [{label, value, color}, ...] }
                    // Normalise to { critical, high, medium, low, info }
                    const chartData = chartRes.value.data?.data || []
                    const chartMap = {}
                    chartData.forEach(d => { chartMap[d.label.toLowerCase()] = d.value })
                    dispatch(setVulnChart(chartMap))
                }
            } catch (err) {
                setFetchError('Failed to load dashboard data')
            } finally {
                dispatch(setDashLoading(false))
            }
        }
        fetchData()
    }, [dispatch])

    const formatDate = formatDateIST

    const statusColor = (status) => {
        const map = {
            completed: 'text-green-400 bg-green-400/10',
            running: 'text-cyan-400 bg-cyan-400/10',
            pending: 'text-yellow-400 bg-yellow-400/10',
            failed: 'text-red-400 bg-red-400/10'
        }
        return map[status] || 'text-gray-400 bg-gray-400/10'
    }

    const pieData = {
        labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
        datasets: [{
            data: vulnChart
                ? [vulnChart.critical || 0, vulnChart.high || 0, vulnChart.medium || 0, vulnChart.low || 0, vulnChart.info || 0]
                : [0, 0, 0, 0, 0],
            backgroundColor: [
                'rgba(220, 38, 38, 0.8)',
                'rgba(234, 88, 12, 0.8)',
                'rgba(202, 138, 4, 0.8)',
                'rgba(22, 163, 74, 0.8)',
                'rgba(59, 130, 246, 0.8)'
            ],
            borderColor: [
                'rgba(220, 38, 38, 1)',
                'rgba(234, 88, 12, 1)',
                'rgba(202, 138, 4, 1)',
                'rgba(22, 163, 74, 1)',
                'rgba(59, 130, 246, 1)'
            ],
            borderWidth: 2,
            hoverOffset: 6
        }]
    }

    const pieOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                position: 'bottom',
                labels: {
                    color: '#94A3B8',
                    padding: 16,
                    usePointStyle: true,
                    pointStyleWidth: 8,
                    font: { size: 12, family: 'Inter' }
                }
            },
            tooltip: {
                backgroundColor: '#1E293B',
                titleColor: '#E2E8F0',
                bodyColor: '#94A3B8',
                borderColor: '#334155',
                borderWidth: 1,
                cornerRadius: 8,
                padding: 12,
                titleFont: { family: 'Inter', weight: '600' },
                bodyFont: { family: 'Inter' }
            }
        }
    }

    if (loading) {
        return (
            <Layout>
                <div className="flex items-center justify-center h-[60vh]">
                    <LoadingSpinner size="lg" text="Loading dashboard..." />
                </div>
            </Layout>
        )
    }

    return (
        <Layout>
            <div className="animate-fade-in">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text">Dashboard</h1>
                        <p className="text-sm text-netrix-muted mt-0.5">Welcome to your security overview</p>
                    </div>
                    <button
                        onClick={() => navigate('/scan/new')}
                        className="btn-primary flex items-center gap-2"
                    >
                        <Plus className="w-4 h-4" />
                        New Scan
                    </button>
                </div>

                {fetchError && (
                    <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                        {fetchError}
                    </div>
                )}

                {/* Stats Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                    {statCards.map(({ key, label, icon: Icon, color, shadow }, i) => (
                        <div
                            key={key}
                            className="glass-card p-5 animate-slide-up"
                            style={{ animationDelay: `${i * 80}ms` }}
                        >
                            <div className="flex items-center justify-between mb-3">
                                <div className={`p-2.5 rounded-xl bg-gradient-to-br ${color} shadow-lg ${shadow}`}>
                                    <Icon className="w-5 h-5 text-white" />
                                </div>
                            </div>
                            <p className="text-2xl font-bold text-netrix-text">
                                {stats?.[key] ?? '—'}
                            </p>
                            <p className="text-xs text-netrix-muted mt-1">{label}</p>
                        </div>
                    ))}
                </div>

                {/* Admin Summary Widget */}
                {isAdmin && <AdminSummary />}

                {/* Charts & Recent */}
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-6 mt-6">
                    {/* Pie Chart */}
                    <div className="lg:col-span-2 glass-card p-6">
                        <h2 className="text-lg font-semibold text-netrix-text mb-4 flex items-center gap-2">
                            <Bug className="w-5 h-5 text-netrix-accent" />
                            Vulnerability Distribution
                        </h2>
                        <div className="h-64">
                            {vulnChart && (vulnChart.critical || vulnChart.high || vulnChart.medium || vulnChart.low || vulnChart.info)
                                ? <Pie data={pieData} options={pieOptions} />
                                : (
                                    <div className="flex flex-col items-center justify-center h-full text-netrix-muted">
                                        <Bug className="w-10 h-10 mb-2 opacity-30" />
                                        <p className="text-sm">No vulnerability data yet</p>
                                    </div>
                                )
                            }
                        </div>
                    </div>

                    {/* Recent Scans */}
                    <div className="lg:col-span-3 glass-card p-6">
                        <div className="flex items-center justify-between mb-4">
                            <h2 className="text-lg font-semibold text-netrix-text flex items-center gap-2">
                                <Scan className="w-5 h-5 text-netrix-accent" />
                                Recent Scans
                            </h2>
                            <button
                                onClick={() => navigate('/history')}
                                className="text-xs text-netrix-accent hover:text-cyan-300 flex items-center gap-1 transition-colors"
                            >
                                View all <ArrowRight className="w-3 h-3" />
                            </button>
                        </div>

                        {recentScans && recentScans.length > 0 ? (
                            <div className="overflow-x-auto">
                                <table className="w-full table-dark">
                                    <thead>
                                        <tr>
                                            <th>Target</th>
                                            <th>Type</th>
                                            <th>Status</th>
                                            <th>Date</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {recentScans.slice(0, 5).map((scan) => (
                                            <tr
                                                key={scan.id}
                                                className="cursor-pointer"
                                                onClick={() => navigate(`/scan/${scan.id}`)}
                                            >
                                                <td>
                                                    <div className="flex items-center gap-2">
                                                        <Target className="w-3.5 h-3.5 text-netrix-muted" />
                                                        <span className="font-medium">{scan.target}</span>
                                                    </div>
                                                </td>
                                                <td className="text-netrix-muted capitalize">{scan.scan_type || 'quick'}</td>
                                                <td>
                                                    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${statusColor(scan.status)}`}>
                                                        {scan.status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />}
                                                        {scan.status}
                                                    </span>
                                                </td>
                                                <td className="text-netrix-muted">
                                                    <div className="flex items-center gap-1">
                                                        <Clock className="w-3 h-3" />
                                                        {formatDate(scan.created_at)}
                                                    </div>
                                                </td>
                                                <td>
                                                    <ArrowRight className="w-4 h-4 text-netrix-muted hover:text-netrix-accent transition-colors" />
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        ) : (
                            <div className="flex flex-col items-center justify-center py-12 text-netrix-muted">
                                <Scan className="w-10 h-10 mb-2 opacity-30" />
                                <p className="text-sm">No scans yet</p>
                                <button
                                    onClick={() => navigate('/scan/new')}
                                    className="mt-3 text-xs text-netrix-accent hover:text-cyan-300 flex items-center gap-1"
                                >
                                    <Plus className="w-3 h-3" /> Launch your first scan
                                </button>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </Layout>
    )
}
