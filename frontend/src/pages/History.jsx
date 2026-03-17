import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { scansAPI } from '../services/api'
import {
    History as HistoryIcon, Search, Filter, Trash2,
    Target, Clock, ChevronDown, ChevronUp, ArrowRight,
    AlertTriangle, X, Wifi
} from 'lucide-react'
import Layout from '../components/Layout'
import LoadingSpinner from '../components/LoadingSpinner'
import VulnBadge from '../components/VulnBadge'

export default function History() {
    const navigate = useNavigate()
    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [search, setSearch] = useState('')
    const [statusFilter, setStatusFilter] = useState('all')
    const [typeFilter, setTypeFilter] = useState('all')
    const [sortField, setSortField] = useState('created_at')
    const [sortDir, setSortDir] = useState('desc')
    const [compareIds, setCompareIds] = useState([])
    const [deleting, setDeleting] = useState(null)

    const fetchScans = async () => {
        setLoading(true)
        try {
            const params = {}
            if (statusFilter !== 'all') params.status = statusFilter
            if (typeFilter !== 'all') params.scan_type = typeFilter
            const res = await scansAPI.list(params)
            setScans(Array.isArray(res.data) ? res.data : res.data?.items || res.data?.scans || [])
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load scan history')
        } finally {
            setLoading(false)
        }
    }

    useEffect(() => { fetchScans() }, [statusFilter, typeFilter])

    const handleSort = (field) => {
        if (sortField === field) {
            setSortDir(d => d === 'asc' ? 'desc' : 'asc')
        } else {
            setSortField(field)
            setSortDir('desc')
        }
    }

    const handleDelete = async (scanId, e) => {
        e.stopPropagation()
        if (!confirm('Delete this scan and all its data?')) return
        setDeleting(scanId)
        try {
            await scansAPI.delete(scanId)
            await fetchScans()
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to delete scan')
        } finally {
            setDeleting(null)
        }
    }

    const toggleCompare = (scanId, e) => {
        e.stopPropagation()
        setCompareIds(prev => {
            if (prev.includes(scanId)) return prev.filter(id => id !== scanId)
            if (prev.length >= 2) return [prev[1], scanId]
            return [...prev, scanId]
        })
    }

    const formatDate = (dateStr) => {
        if (!dateStr) return '—'
        return new Date(dateStr).toLocaleDateString('en-US', {
            month: 'short', day: 'numeric', year: 'numeric',
            hour: '2-digit', minute: '2-digit'
        })
    }

    const statusColor = (status) => {
        const m = {
            completed: 'text-green-400 bg-green-400/10',
            running: 'text-cyan-400 bg-cyan-400/10',
            pending: 'text-yellow-400 bg-yellow-400/10',
            failed: 'text-red-400 bg-red-400/10',
            cancelled: 'text-gray-400 bg-gray-400/10'
        }
        return m[status] || 'text-gray-400 bg-gray-400/10'
    }

    const sortedScans = [...scans]
        .filter(scan => {
            if (!search) return true
            const s = search.toLowerCase()
            return (
                scan.target?.toLowerCase().includes(s) ||
                scan.scan_id?.toLowerCase().includes(s) ||
                scan.scan_type?.toLowerCase().includes(s)
            )
        })
        .sort((a, b) => {
            const aVal = a[sortField] ?? ''
            const bVal = b[sortField] ?? ''
            if (sortField === 'created_at') {
                return sortDir === 'asc'
                    ? new Date(aVal) - new Date(bVal)
                    : new Date(bVal) - new Date(aVal)
            }
            const aStr = String(aVal).toLowerCase()
            const bStr = String(bVal).toLowerCase()
            return sortDir === 'asc' ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr)
        })

    const SortIcon = ({ field }) => {
        if (sortField !== field) return null
        return sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
    }

    return (
        <Layout>
            <div className="animate-fade-in">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text flex items-center gap-2">
                            <HistoryIcon className="w-6 h-6 text-netrix-accent" />
                            Scan History
                        </h1>
                        <p className="text-sm text-netrix-muted mt-0.5">
                            {scans.length} total scans recorded
                        </p>
                    </div>
                    {compareIds.length === 2 && (
                        <button
                            onClick={() => {
                                const params = new URLSearchParams({ a: compareIds[0], b: compareIds[1] })
                                alert(`Compare scans: ${compareIds[0]} vs ${compareIds[1]}\n(Comparison view coming soon)`)
                            }}
                            className="btn-primary flex items-center gap-2"
                        >
                            Compare ({compareIds.length}/2)
                        </button>
                    )}
                </div>

                {/* Filters */}
                <div className="flex flex-col sm:flex-row gap-3 mb-6">
                    <div className="flex items-center bg-netrix-bg border border-netrix-border rounded-lg focus-within:border-netrix-accent focus-within:ring-1 focus-within:ring-netrix-accent/30 transition-all duration-200 flex-1">
                        <span className="flex items-center justify-center w-10 shrink-0 text-netrix-muted/50">
                            <Search className="w-4 h-4" />
                        </span>
                        <input
                            type="text"
                            placeholder="Search by target, scan ID..."
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            className="w-full bg-transparent py-3 pr-4 text-netrix-text placeholder-netrix-muted/50 focus:outline-none"
                            autoComplete="off"
                        />
                    </div>

                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="input-dark w-auto"
                    >
                        <option value="all">All Status</option>
                        <option value="completed">Completed</option>
                        <option value="running">Running</option>
                        <option value="pending">Pending</option>
                        <option value="failed">Failed</option>
                    </select>

                    <select
                        value={typeFilter}
                        onChange={(e) => setTypeFilter(e.target.value)}
                        className="input-dark w-auto"
                    >
                        <option value="all">All Types</option>
                        <option value="quick">Quick</option>
                        <option value="stealth">Stealth</option>
                        <option value="full">Full</option>
                        <option value="aggressive">Aggressive</option>
                        <option value="vulnerability">Vulnerability</option>
                    </select>
                </div>

                {error && (
                    <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 flex-shrink-0" /> {error}
                    </div>
                )}

                {loading ? (
                    <div className="flex justify-center py-20">
                        <LoadingSpinner size="lg" text="Loading scan history..." />
                    </div>
                ) : sortedScans.length > 0 ? (
                    <div className="glass-card overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full table-dark">
                                <thead>
                                    <tr>
                                        <th className="w-8">
                                            <span className="sr-only">Compare</span>
                                        </th>
                                        <th className="cursor-pointer" onClick={() => handleSort('target')}>
                                            <span className="flex items-center gap-1">Target <SortIcon field="target" /></span>
                                        </th>
                                        <th className="cursor-pointer" onClick={() => handleSort('scan_type')}>
                                            <span className="flex items-center gap-1">Type <SortIcon field="scan_type" /></span>
                                        </th>
                                        <th className="cursor-pointer" onClick={() => handleSort('status')}>
                                            <span className="flex items-center gap-1">Status <SortIcon field="status" /></span>
                                        </th>
                                        <th className="cursor-pointer" onClick={() => handleSort('created_at')}>
                                            <span className="flex items-center gap-1">Date <SortIcon field="created_at" /></span>
                                        </th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {sortedScans.map(scan => (
                                        <tr
                                            key={scan.id}
                                            className="cursor-pointer"
                                            onClick={() => navigate(`/scan/${scan.id}`)}
                                        >
                                            <td onClick={(e) => e.stopPropagation()}>
                                                <input
                                                    type="checkbox"
                                                    checked={compareIds.includes(scan.id)}
                                                    onChange={(e) => toggleCompare(scan.id, e)}
                                                    className="w-4 h-4 rounded border-netrix-border bg-netrix-bg text-netrix-accent focus:ring-netrix-accent/30 cursor-pointer"
                                                />
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-2">
                                                    <Target className="w-4 h-4 text-netrix-muted" />
                                                    <div>
                                                        <span className="font-medium">{scan.target}</span>
                                                        <span className="block text-xs text-netrix-muted font-mono">{scan.scan_id}</span>
                                                    </div>
                                                </div>
                                            </td>
                                            <td>
                                                <span className="inline-flex items-center gap-1 text-xs text-netrix-muted capitalize">
                                                    <Wifi className="w-3 h-3" /> {scan.scan_type || 'quick'}
                                                </span>
                                            </td>
                                            <td>
                                                <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium ${statusColor(scan.status)}`}>
                                                    {scan.status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />}
                                                    {scan.status}
                                                </span>
                                            </td>
                                            <td className="text-netrix-muted text-sm">
                                                <div className="flex items-center gap-1">
                                                    <Clock className="w-3 h-3" />
                                                    {formatDate(scan.created_at)}
                                                </div>
                                            </td>
                                            <td>
                                                <div className="flex items-center gap-1">
                                                    <button
                                                        onClick={(e) => { e.stopPropagation(); navigate(`/scan/${scan.id}`) }}
                                                        className="p-2 rounded-lg hover:bg-netrix-accent/10 text-netrix-muted hover:text-netrix-accent transition-all"
                                                        title="View results"
                                                    >
                                                        <ArrowRight className="w-4 h-4" />
                                                    </button>
                                                    <button
                                                        onClick={(e) => handleDelete(scan.id, e)}
                                                        disabled={deleting === scan.id}
                                                        className="p-2 rounded-lg hover:bg-red-500/10 text-netrix-muted hover:text-red-400 transition-all"
                                                        title="Delete"
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ) : (
                    <div className="glass-card p-16 flex flex-col items-center justify-center text-netrix-muted">
                        <HistoryIcon className="w-12 h-12 mb-3 opacity-30" />
                        <p className="text-sm">No scans found</p>
                        {(search || statusFilter !== 'all' || typeFilter !== 'all') && (
                            <button
                                onClick={() => { setSearch(''); setStatusFilter('all'); setTypeFilter('all') }}
                                className="mt-3 text-xs text-netrix-accent hover:text-cyan-300 flex items-center gap-1"
                            >
                                <X className="w-3 h-3" /> Clear filters
                            </button>
                        )}
                    </div>
                )}
            </div>
        </Layout>
    )
}
