// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect, useCallback } from 'react'
import {
    ClipboardList, Filter, Download, ChevronLeft, ChevronRight,
    RefreshCw, X, Calendar, User, Tag, Wifi, ChevronDown,
    ChevronRight as ChevronRightSm, AlertTriangle, Check
} from 'lucide-react'
import Layout from '../components/Layout'
import { adminAPI } from '../services/api'
import { formatDateIST } from '../utils/formatDate'

// ── Constants ─────────────────────────────────────────────────────────────

const ALL_ACTIONS = [
    'login', 'logout', 'login_failed',
    'scan_start', 'scan_delete',
    'report_download',
    'user_ban', 'role_change', 'password_reset',
    'cve_sync',
]

const ACTION_META = {
    login:           { label: 'Login',           color: 'bg-blue-500/15 text-blue-400 border-blue-500/30' },
    logout:          { label: 'Logout',           color: 'bg-slate-500/15 text-slate-400 border-slate-500/30' },
    login_failed:    { label: 'Login Failed',     color: 'bg-red-500/15 text-red-400 border-red-500/30' },
    scan_start:      { label: 'Scan Start',       color: 'bg-purple-500/15 text-purple-400 border-purple-500/30' },
    scan_delete:     { label: 'Scan Delete',      color: 'bg-orange-500/15 text-orange-400 border-orange-500/30' },
    report_download: { label: 'Report Download',  color: 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30' },
    user_ban:        { label: 'User Ban',         color: 'bg-red-600/15 text-red-400 border-red-600/30' },
    role_change:     { label: 'Role Change',      color: 'bg-amber-500/15 text-amber-400 border-amber-500/30' },
    password_reset:  { label: 'Password Reset',   color: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
    cve_sync:        { label: 'CVE Sync',         color: 'bg-green-500/15 text-green-400 border-green-500/30' },
}

const PAGE_SIZE = 50

// ── Action Badge ──────────────────────────────────────────────────────────

function ActionBadge({ action }) {
    const meta = ACTION_META[action] ?? { label: action, color: 'bg-gray-500/15 text-gray-400 border-gray-500/30' }
    return (
        <span className={`px-2 py-0.5 rounded text-xs font-semibold border whitespace-nowrap ${meta.color}`}>
            {meta.label}
        </span>
    )
}

// ── Details Cell ──────────────────────────────────────────────────────────

function DetailsCell({ details }) {
    const [open, setOpen] = useState(false)
    if (!details || Object.keys(details).length === 0) {
        return <span className="text-netrix-muted text-xs">—</span>
    }
    return (
        <div>
            <button
                onClick={() => setOpen(o => !o)}
                className="flex items-center gap-1 text-xs text-netrix-muted hover:text-netrix-accent transition-colors"
            >
                {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRightSm className="w-3 h-3" />}
                Details
            </button>
            {open && (
                <pre className="mt-1.5 p-2 rounded bg-netrix-bg border border-netrix-border text-[11px] text-netrix-text font-mono overflow-x-auto max-w-xs whitespace-pre-wrap break-all">
                    {JSON.stringify(details, null, 2)}
                </pre>
            )}
        </div>
    )
}

// ── CSV Export ────────────────────────────────────────────────────────────

function exportCSV(logs) {
    const headers = ['ID', 'Timestamp', 'Username', 'Email', 'Action', 'IP Address', 'Details']
    const rows = logs.map(l => [
        l.id,
        l.created_at,
        l.username ?? '',
        l.email ?? '',
        l.action,
        l.ip_address ?? '',
        l.details ? JSON.stringify(l.details) : '',
    ])
    const csv = [headers, ...rows]
        .map(row => row.map(v => `"${String(v).replace(/"/g, '""')}"`).join(','))
        .join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit_logs_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function AdminLogs() {
    // ── Data state ─────────────────────────────────────────────────
    const [logs, setLogs] = useState([])
    const [total, setTotal] = useState(0)
    const [totalPages, setTotalPages] = useState(1)
    const [page, setPage] = useState(1)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')

    // ── Filter state ───────────────────────────────────────────────
    const [users, setUsers] = useState([])
    const [filterUserId, setFilterUserId] = useState('')
    const [filterAction, setFilterAction] = useState('')
    const [filterIp, setFilterIp] = useState('')
    const [filterDateFrom, setFilterDateFrom] = useState('')
    const [filterDateTo, setFilterDateTo] = useState('')
    const [filtersOpen, setFiltersOpen] = useState(true)
    const [applied, setApplied] = useState({})

    // ── Fetch users for dropdown ───────────────────────────────────
    useEffect(() => {
        adminAPI.listUsers({ page: 1, page_size: 200 })
            .then(r => setUsers(r.data.users ?? []))
            .catch(() => {})
    }, [])

    // ── Fetch logs ─────────────────────────────────────────────────
    const fetchLogs = useCallback(async () => {
        setLoading(true)
        setError('')
        try {
            const params = { page, page_size: PAGE_SIZE }
            if (applied.userId)   params.user_id    = applied.userId
            if (applied.action)   params.action      = applied.action
            if (applied.ip)       params.ip_address  = applied.ip
            if (applied.dateFrom) params.date_from   = applied.dateFrom
            if (applied.dateTo)   params.date_to     = applied.dateTo

            const res = await adminAPI.listLogs(params)
            const data = res.data
            setLogs(data.logs)
            setTotal(data.total)
            setTotalPages(data.total_pages)
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load audit logs.')
        } finally {
            setLoading(false)
        }
    }, [page, applied])

    useEffect(() => { fetchLogs() }, [fetchLogs])

    // ── Apply / reset ──────────────────────────────────────────────
    const applyFilters = () => {
        setPage(1)
        setApplied({
            userId:   filterUserId || undefined,
            action:   filterAction || undefined,
            ip:       filterIp.trim() || undefined,
            dateFrom: filterDateFrom || undefined,
            dateTo:   filterDateTo || undefined,
        })
    }

    const resetFilters = () => {
        setFilterUserId(''); setFilterAction(''); setFilterIp('')
        setFilterDateFrom(''); setFilterDateTo('')
        setPage(1); setApplied({})
    }

    const activeCount = Object.values(applied).filter(Boolean).length

    // ── Render ─────────────────────────────────────────────────────
    return (
        <Layout>
            <div className="p-6 space-y-5 max-w-7xl mx-auto">

                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text">Audit Logs</h1>
                        <p className="text-netrix-muted text-sm mt-1">Immutable record of all sensitive platform events.</p>
                    </div>
                    <div className="flex gap-2">
                        <button
                            onClick={() => exportCSV(logs)}
                            disabled={logs.length === 0}
                            className="flex items-center gap-2 px-3 py-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-accent hover:border-netrix-accent/50 transition-all text-sm disabled:opacity-40 disabled:cursor-not-allowed"
                            title="Export current page to CSV"
                        >
                            <Download className="w-4 h-4" />
                            Export CSV
                        </button>
                        <button
                            onClick={fetchLogs}
                            className="p-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-accent hover:border-netrix-accent/50 transition-all"
                            title="Refresh"
                        >
                            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                        </button>
                    </div>
                </div>

                {/* Filter Panel */}
                <div className="bg-netrix-card border border-netrix-border/50 rounded-2xl overflow-hidden">
                    <button
                        onClick={() => setFiltersOpen(o => !o)}
                        className="w-full flex items-center justify-between px-5 py-3.5 hover:bg-netrix-bg/30 transition-colors"
                    >
                        <div className="flex items-center gap-2 text-netrix-text font-medium text-sm">
                            <Filter className="w-4 h-4 text-netrix-muted" />
                            Filters
                            {activeCount > 0 && (
                                <span className="ml-1 px-1.5 py-0.5 rounded-full bg-netrix-accent text-white text-[10px] font-bold">
                                    {activeCount}
                                </span>
                            )}
                        </div>
                        <span className="text-netrix-muted text-xs">{filtersOpen ? '▲' : '▼'}</span>
                    </button>

                    {filtersOpen && (
                        <div className="px-5 pb-5 space-y-4 border-t border-netrix-border/40">
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 pt-4">
                                {/* User */}
                                <div>
                                    <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                        <User className="w-3 h-3" /> User
                                    </label>
                                    <select
                                        value={filterUserId}
                                        onChange={e => setFilterUserId(e.target.value)}
                                        className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-sm text-netrix-text focus:outline-none focus:border-netrix-accent"
                                    >
                                        <option value="">All users</option>
                                        {users.map(u => (
                                            <option key={u.id} value={u.id}>{u.username}</option>
                                        ))}
                                    </select>
                                </div>

                                {/* Action */}
                                <div>
                                    <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                        <Tag className="w-3 h-3" /> Action
                                    </label>
                                    <select
                                        value={filterAction}
                                        onChange={e => setFilterAction(e.target.value)}
                                        className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-sm text-netrix-text focus:outline-none focus:border-netrix-accent"
                                    >
                                        <option value="">All actions</option>
                                        {ALL_ACTIONS.map(a => (
                                            <option key={a} value={a}>{ACTION_META[a]?.label ?? a}</option>
                                        ))}
                                    </select>
                                </div>

                                {/* IP */}
                                <div>
                                    <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                        <Wifi className="w-3 h-3" /> IP Address
                                    </label>
                                    <input
                                        type="text"
                                        value={filterIp}
                                        onChange={e => setFilterIp(e.target.value)}
                                        placeholder="192.168.1…"
                                        className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-sm text-netrix-text placeholder:text-netrix-muted focus:outline-none focus:border-netrix-accent"
                                    />
                                </div>

                                {/* Date from */}
                                <div>
                                    <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                        <Calendar className="w-3 h-3" /> From Date
                                    </label>
                                    <input
                                        type="date"
                                        value={filterDateFrom}
                                        onChange={e => setFilterDateFrom(e.target.value)}
                                        className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-sm text-netrix-text focus:outline-none focus:border-netrix-accent"
                                    />
                                </div>

                                {/* Date to */}
                                <div>
                                    <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                        <Calendar className="w-3 h-3" /> To Date
                                    </label>
                                    <input
                                        type="date"
                                        value={filterDateTo}
                                        onChange={e => setFilterDateTo(e.target.value)}
                                        className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-sm text-netrix-text focus:outline-none focus:border-netrix-accent"
                                    />
                                </div>
                            </div>

                            <div className="flex gap-2">
                                <button
                                    onClick={applyFilters}
                                    className="px-4 py-2 bg-netrix-accent text-white rounded-lg text-sm font-medium hover:bg-netrix-accent/90 transition-all"
                                >
                                    Apply Filters
                                </button>
                                {activeCount > 0 && (
                                    <button
                                        onClick={resetFilters}
                                        className="px-4 py-2 border border-netrix-border text-netrix-muted rounded-lg text-sm hover:text-netrix-text hover:border-netrix-accent/50 transition-all flex items-center gap-1.5"
                                    >
                                        <X className="w-3.5 h-3.5" /> Clear
                                    </button>
                                )}
                            </div>
                        </div>
                    )}
                </div>

                {/* Error */}
                {error && (
                    <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}
                        <button onClick={() => setError('')} className="ml-auto"><X className="w-4 h-4" /></button>
                    </div>
                )}

                {/* Table */}
                <div className="bg-netrix-card border border-netrix-border/50 rounded-2xl overflow-hidden">
                    <div className="px-5 py-3.5 border-b border-netrix-border/50 flex items-center justify-between">
                        <span className="text-netrix-text font-medium text-sm flex items-center gap-2">
                            <ClipboardList className="w-4 h-4 text-netrix-muted" />
                            Audit Events
                        </span>
                        <span className="text-xs text-netrix-muted">{total} total</span>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-netrix-border/50 bg-netrix-bg/40">
                                    {['Timestamp', 'User', 'Action', 'IP Address', 'Details'].map(h => (
                                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-netrix-muted uppercase tracking-wider whitespace-nowrap">
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-netrix-border/30">
                                {loading ? (
                                    <tr>
                                        <td colSpan={5} className="px-4 py-12 text-center text-netrix-muted text-sm">
                                            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2" />
                                            Loading audit logs…
                                        </td>
                                    </tr>
                                ) : logs.length === 0 ? (
                                    <tr>
                                        <td colSpan={5} className="px-4 py-12 text-center text-netrix-muted text-sm">
                                            No audit events match the current filters.
                                        </td>
                                    </tr>
                                ) : logs.map(log => (
                                    <tr key={log.id} className="hover:bg-netrix-bg/30 transition-colors">
                                        <td className="px-4 py-3 text-netrix-muted text-xs whitespace-nowrap font-mono">
                                            {formatDateIST(log.created_at)}
                                        </td>
                                        <td className="px-4 py-3">
                                            {log.username ? (
                                                <>
                                                    <div className="text-sm text-netrix-text font-medium leading-tight">{log.username}</div>
                                                    <div className="text-[11px] text-netrix-muted">{log.email}</div>
                                                </>
                                            ) : (
                                                <span className="text-netrix-muted text-xs italic">anonymous</span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3">
                                            <ActionBadge action={log.action} />
                                        </td>
                                        <td className="px-4 py-3 text-netrix-muted text-xs font-mono whitespace-nowrap">
                                            {log.ip_address ?? '—'}
                                        </td>
                                        <td className="px-4 py-3">
                                            <DetailsCell details={log.details} />
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Pagination */}
                    {totalPages > 1 && (
                        <div className="p-4 border-t border-netrix-border/50 flex items-center justify-between">
                            <span className="text-xs text-netrix-muted">Page {page} of {totalPages} · {total} events</span>
                            <div className="flex gap-2">
                                <button
                                    onClick={() => setPage(p => Math.max(1, p - 1))}
                                    disabled={page === 1}
                                    className="p-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text hover:border-netrix-accent/50 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    <ChevronLeft className="w-4 h-4" />
                                </button>
                                <button
                                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                                    disabled={page === totalPages}
                                    className="p-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text hover:border-netrix-accent/50 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </Layout>
    )
}
