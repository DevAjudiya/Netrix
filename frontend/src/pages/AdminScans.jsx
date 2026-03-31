// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect, useCallback, useRef } from 'react'
import {
    Scan, Filter, Trash2, StopCircle, RefreshCw,
    ChevronLeft, ChevronRight, AlertTriangle, X,
    Calendar, User, Tag, Activity, Check, Eye,
    Server, Globe, Shield, ChevronDown, ChevronUp,
    Monitor, Cpu, Network
} from 'lucide-react'
import Layout from '../components/Layout'
import { adminAPI } from '../services/api'
import { formatDateIST } from '../utils/formatDate'

// ── Constants ─────────────────────────────────────────────────────────────

const STATUSES = ['pending', 'running', 'completed', 'failed']
const SCAN_TYPES = ['quick', 'stealth', 'full', 'aggressive', 'vulnerability', 'custom']
const PAGE_SIZE = 20

// ── Status Badge ──────────────────────────────────────────────────────────

function StatusBadge({ status }) {
    const map = {
        running:   'bg-blue-500/15 text-blue-400 border-blue-500/30',
        completed: 'bg-green-500/15 text-green-400 border-green-500/30',
        failed:    'bg-red-500/15 text-red-400 border-red-500/30',
        pending:   'bg-gray-500/15 text-gray-400 border-gray-500/30',
    }
    return (
        <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${map[status] ?? 'bg-gray-500/15 text-gray-400 border-gray-500/30'}`}>
            {status}
        </span>
    )
}

// ── Scan Type Badge ───────────────────────────────────────────────────────

function TypeBadge({ type }) {
    return (
        <span className="px-2 py-0.5 rounded text-xs font-medium bg-netrix-bg border border-netrix-border text-netrix-muted capitalize">
            {type}
        </span>
    )
}

// ── Progress Bar ──────────────────────────────────────────────────────────

function ProgressBar({ value, status }) {
    const color = status === 'completed' ? 'bg-green-500'
        : status === 'failed' ? 'bg-red-500'
        : status === 'running' ? 'bg-blue-500'
        : 'bg-yellow-500'
    return (
        <div className="flex items-center gap-2 min-w-[80px]">
            <div className="flex-1 h-1.5 bg-netrix-bg rounded-full overflow-hidden">
                <div
                    className={`h-full rounded-full transition-all ${color}`}
                    style={{ width: `${Math.min(100, value ?? 0)}%` }}
                />
            </div>
            <span className="text-[11px] text-netrix-muted tabular-nums w-7 text-right">{value ?? 0}%</span>
        </div>
    )
}

// ── Multi-select Status Chips ─────────────────────────────────────────────

function StatusFilter({ selected, onChange }) {
    const colors = {
        pending:   'border-gray-500/40 text-gray-400 bg-gray-500/10',
        running:   'border-blue-500/40 text-blue-400 bg-blue-500/10',
        completed: 'border-green-500/40 text-green-400 bg-green-500/10',
        failed:    'border-red-500/40 text-red-400 bg-red-500/10',
    }
    const toggle = (s) => onChange(
        selected.includes(s) ? selected.filter(x => x !== s) : [...selected, s]
    )
    return (
        <div className="flex flex-wrap gap-1.5">
            {STATUSES.map(s => (
                <button
                    key={s}
                    onClick={() => toggle(s)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-medium border transition-all
                        ${selected.includes(s)
                            ? colors[s]
                            : 'border-netrix-border text-netrix-muted hover:border-netrix-accent/50 hover:text-netrix-text'
                        }`}
                >
                    {selected.includes(s) && <Check className="w-3 h-3 inline mr-1" />}
                    {s}
                </button>
            ))}
        </div>
    )
}

// ── Confirm Dialog ────────────────────────────────────────────────────────

function ConfirmDialog({ title, body, confirmLabel, confirmClass, onConfirm, onCancel, loading }) {
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-netrix-card border border-netrix-border rounded-2xl w-full max-w-sm shadow-2xl p-6 space-y-4">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-red-500/15 flex items-center justify-center">
                        <AlertTriangle className="w-5 h-5 text-red-400" />
                    </div>
                    <h2 className="text-netrix-text font-semibold">{title}</h2>
                </div>
                <p className="text-netrix-muted text-sm">{body}</p>
                <div className="flex gap-3">
                    <button onClick={onCancel} className="flex-1 px-4 py-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text transition-all text-sm">
                        Cancel
                    </button>
                    <button
                        onClick={onConfirm}
                        disabled={loading}
                        className={`flex-1 px-4 py-2 rounded-lg text-white font-medium transition-all text-sm disabled:opacity-50 flex items-center justify-center gap-2 ${confirmClass}`}
                    >
                        {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : null}
                        {loading ? 'Processing…' : confirmLabel}
                    </button>
                </div>
            </div>
        </div>
    )
}

// ── Severity badge ────────────────────────────────────────────────────────

function SevBadge({ severity }) {
    const map = {
        critical: 'bg-red-500/15 text-red-400 border-red-500/30',
        high:     'bg-orange-500/15 text-orange-400 border-orange-500/30',
        medium:   'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
        low:      'bg-blue-500/15 text-blue-400 border-blue-500/30',
        info:     'bg-gray-500/15 text-gray-400 border-gray-500/30',
    }
    return (
        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border uppercase ${map[severity] ?? map.info}`}>
            {severity}
        </span>
    )
}

// ── Host Card ─────────────────────────────────────────────────────────────

function HostCard({ host }) {
    const [open, setOpen] = useState(false)
    return (
        <div className="border border-netrix-border/50 rounded-xl overflow-hidden">
            <button
                onClick={() => setOpen(o => !o)}
                className="w-full flex items-center justify-between px-4 py-3 hover:bg-netrix-bg/30 transition-colors text-left"
            >
                <div className="flex items-center gap-3">
                    <div className="w-8 h-8 rounded-lg bg-netrix-accent/10 flex items-center justify-center">
                        <Monitor className="w-4 h-4 text-netrix-accent" />
                    </div>
                    <div>
                        <div className="text-sm font-mono text-netrix-text font-medium">{host.ip_address}</div>
                        {host.hostname && <div className="text-[11px] text-netrix-muted">{host.hostname}</div>}
                    </div>
                    {host.os_name && (
                        <div className="flex items-center gap-1 text-[11px] text-netrix-muted bg-netrix-bg px-2 py-0.5 rounded border border-netrix-border">
                            <Cpu className="w-3 h-3" />{host.os_name}
                        </div>
                    )}
                    <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded border ${host.status === 'up' ? 'bg-green-500/15 text-green-400 border-green-500/30' : 'bg-gray-500/15 text-gray-400 border-gray-500/30'}`}>
                        {host.status}
                    </span>
                </div>
                <div className="flex items-center gap-3 text-xs text-netrix-muted">
                    <span className="flex items-center gap-1"><Network className="w-3 h-3" />{host.ports?.length ?? 0} ports</span>
                    <span className="flex items-center gap-1"><Shield className="w-3 h-3" />{host.vulnerabilities?.length ?? 0} vulns</span>
                    {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                </div>
            </button>

            {open && (
                <div className="border-t border-netrix-border/40 bg-netrix-bg/20">
                    {/* Ports */}
                    {host.ports?.length > 0 && (
                        <div className="p-4 space-y-2">
                            <div className="text-xs font-semibold text-netrix-muted uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                <Network className="w-3 h-3" /> Open Ports
                            </div>
                            <div className="overflow-x-auto">
                                <table className="w-full text-xs">
                                    <thead>
                                        <tr className="text-netrix-muted border-b border-netrix-border/40">
                                            {['Port', 'Proto', 'State', 'Service', 'Product / Version'].map(h => (
                                                <th key={h} className="pb-1.5 pr-4 text-left font-medium">{h}</th>
                                            ))}
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-netrix-border/20">
                                        {host.ports.map(p => {
                                            const sv = [p.product, p.version, p.extra_info].filter(Boolean).join(' ') || '—'
                                            return (
                                            <tr key={p.id} className="text-netrix-text">
                                                <td className="py-1.5 pr-4 font-mono text-netrix-accent font-medium">{p.port_number}</td>
                                                <td className="py-1.5 pr-4 text-netrix-muted">{p.protocol}</td>
                                                <td className="py-1.5 pr-4">
                                                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${p.state === 'open' ? 'bg-green-500/15 text-green-400 border-green-500/30' : 'bg-gray-500/15 text-gray-400 border-gray-500/30'}`}>
                                                        {p.state}
                                                    </span>
                                                </td>
                                                <td className="py-1.5 pr-4">{p.service_name || '—'}</td>
                                                <td className="py-1.5 text-netrix-muted">{sv}</td>
                                            </tr>
                                            )
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    )}
                    {/* Vulnerabilities */}
                    {host.vulnerabilities?.length > 0 && (
                        <div className="px-4 pb-4 space-y-2 border-t border-netrix-border/30">
                            <div className="text-xs font-semibold text-netrix-muted uppercase tracking-wider mt-3 mb-2 flex items-center gap-1.5">
                                <Shield className="w-3 h-3" /> Vulnerabilities
                            </div>
                            <div className="space-y-2">
                                {host.vulnerabilities.map(v => (
                                    <div key={v.id} className="flex items-start gap-3 p-3 bg-netrix-bg rounded-lg border border-netrix-border/40">
                                        <SevBadge severity={v.severity} />
                                        <div className="flex-1 min-w-0">
                                            <div className="text-xs text-netrix-text font-medium truncate">{v.cve_id || v.name}</div>
                                            {v.description && <div className="text-[11px] text-netrix-muted mt-0.5 line-clamp-2">{v.description}</div>}
                                        </div>
                                        {v.cvss_score != null && (
                                            <span className="text-xs font-mono text-netrix-muted shrink-0">CVSS {v.cvss_score}</span>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}
                    {(!host.ports?.length && !host.vulnerabilities?.length) && (
                        <div className="px-4 py-3 text-xs text-netrix-muted">No ports or vulnerabilities recorded.</div>
                    )}
                </div>
            )}
        </div>
    )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function AdminScans() {
    // ── Data state ─────────────────────────────────────────────────
    const [scans, setScans] = useState([])
    const [total, setTotal] = useState(0)
    const [totalPages, setTotalPages] = useState(1)
    const [page, setPage] = useState(1)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')

    // ── Filter state ───────────────────────────────────────────────
    const [users, setUsers] = useState([])           // [{id, username}]
    const [filterUserId, setFilterUserId] = useState('')
    const [filterStatuses, setFilterStatuses] = useState([])
    const [filterType, setFilterType] = useState('')
    const [filterDateFrom, setFilterDateFrom] = useState('')
    const [filterDateTo, setFilterDateTo] = useState('')
    const [filtersOpen, setFiltersOpen] = useState(true)

    // Applied filters (committed on Apply)
    const [appliedFilters, setAppliedFilters] = useState({})

    // ── Action state ───────────────────────────────────────────────
    const [deleteTarget, setDeleteTarget] = useState(null)
    const [stopTarget, setStopTarget] = useState(null)
    const [actionLoading, setActionLoading] = useState(false)

    // ── Inline expanded rows ───────────────────────────────────────
    // expandedRows: Set of scan_id strings currently expanded
    // detailCache:  { [scan_id]: { data, loading, error } }
    const [expandedRows, setExpandedRows] = useState(new Set())
    const [detailCache, setDetailCache] = useState({})

    // ── Fetch users for dropdown ───────────────────────────────────
    useEffect(() => {
        adminAPI.listUsers({ page: 1, page_size: 200 })
            .then(res => setUsers(res.data.users ?? []))
            .catch(() => {})
    }, [])

    // ── Fetch scans ────────────────────────────────────────────────
    const fetchScans = useCallback(async () => {
        setLoading(true)
        setError('')
        try {
            const params = { page, page_size: PAGE_SIZE }
            if (appliedFilters.userId)    params.user_id = appliedFilters.userId
            if (appliedFilters.statuses?.length) params.status = appliedFilters.statuses.join(',')
            if (appliedFilters.type)      params.scan_type = appliedFilters.type
            if (appliedFilters.dateFrom)  params.date_from = appliedFilters.dateFrom
            if (appliedFilters.dateTo)    params.date_to = appliedFilters.dateTo

            const res = await adminAPI.listScans(params)
            const data = res.data
            setScans(data.scans)
            setTotal(data.total)
            setTotalPages(data.total_pages)
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load scans.')
        } finally {
            setLoading(false)
        }
    }, [page, appliedFilters])

    useEffect(() => { fetchScans() }, [fetchScans])

    // ── Apply / reset filters ──────────────────────────────────────
    const applyFilters = () => {
        setPage(1)
        setAppliedFilters({
            userId:   filterUserId || undefined,
            statuses: filterStatuses.length ? filterStatuses : undefined,
            type:     filterType || undefined,
            dateFrom: filterDateFrom || undefined,
            dateTo:   filterDateTo || undefined,
        })
    }

    const resetFilters = () => {
        setFilterUserId('')
        setFilterStatuses([])
        setFilterType('')
        setFilterDateFrom('')
        setFilterDateTo('')
        setPage(1)
        setAppliedFilters({})
    }

    const activeFilterCount = Object.values(appliedFilters).filter(Boolean).length

    // ── Delete action ──────────────────────────────────────────────
    const handleDelete = async () => {
        setActionLoading(true)
        try {
            await adminAPI.deleteScan(deleteTarget.id)
            setDeleteTarget(null)
            fetchScans()
        } catch (err) {
            setError(err.response?.data?.detail || 'Delete failed.')
            setDeleteTarget(null)
        } finally {
            setActionLoading(false)
        }
    }

    // ── Toggle inline detail row ───────────────────────────────────
    const toggleDetail = async (scan) => {
        const sid = scan.scan_id
        setExpandedRows(prev => {
            const next = new Set(prev)
            if (next.has(sid)) { next.delete(sid); return next }
            next.add(sid)
            return next
        })
        // fetch only if not cached yet
        if (detailCache[sid]) return
        setDetailCache(prev => ({ ...prev, [sid]: { data: null, loading: true, error: '' } }))
        try {
            const res = await adminAPI.getScanDetails(sid)
            setDetailCache(prev => ({ ...prev, [sid]: { data: res.data, loading: false, error: '' } }))
        } catch (err) {
            const msg = err.response?.data?.detail || 'Failed to load scan details.'
            setDetailCache(prev => ({ ...prev, [sid]: { data: null, loading: false, error: msg } }))
        }
    }

    // ── Stop action ────────────────────────────────────────────────
    const handleStop = async () => {
        setActionLoading(true)
        try {
            await adminAPI.stopScan(stopTarget.id)
            setStopTarget(null)
            fetchScans()
        } catch (err) {
            setError(err.response?.data?.detail || 'Stop failed.')
            setStopTarget(null)
        } finally {
            setActionLoading(false)
        }
    }

    // ── Render ─────────────────────────────────────────────────────
    return (
        <Layout>
            <div className="p-6 space-y-5 max-w-7xl mx-auto">

                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text">Scan Oversight</h1>
                        <p className="text-netrix-muted text-sm mt-1">Monitor, stop, and delete scans across all users.</p>
                    </div>
                    <button
                        onClick={fetchScans}
                        className="p-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-accent hover:border-netrix-accent/50 transition-all"
                        title="Refresh"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                </div>

                {/* Filter Panel */}
                <div className="bg-netrix-card border border-netrix-border/50 rounded-2xl overflow-hidden">
                    <button
                        onClick={() => setFiltersOpen(o => !o)}
                        className="w-full flex items-center justify-between px-5 py-3.5 text-left hover:bg-netrix-bg/30 transition-colors"
                    >
                        <div className="flex items-center gap-2 text-netrix-text font-medium text-sm">
                            <Filter className="w-4 h-4 text-netrix-muted" />
                            Filters
                            {activeFilterCount > 0 && (
                                <span className="ml-1 px-1.5 py-0.5 rounded-full bg-netrix-accent text-white text-[10px] font-bold">
                                    {activeFilterCount}
                                </span>
                            )}
                        </div>
                        <span className="text-netrix-muted text-xs">{filtersOpen ? '▲' : '▼'}</span>
                    </button>

                    {filtersOpen && (
                        <div className="px-5 pb-5 space-y-4 border-t border-netrix-border/40">
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 pt-4">
                                {/* Username / User dropdown */}
                                <div>
                                    <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                        <User className="w-3 h-3" /> Username
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

                                {/* Scan type */}
                                <div>
                                    <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                        <Tag className="w-3 h-3" /> Scan Type
                                    </label>
                                    <select
                                        value={filterType}
                                        onChange={e => setFilterType(e.target.value)}
                                        className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-sm text-netrix-text focus:outline-none focus:border-netrix-accent"
                                    >
                                        <option value="">All types</option>
                                        {SCAN_TYPES.map(t => (
                                            <option key={t} value={t} className="capitalize">{t}</option>
                                        ))}
                                    </select>
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

                            {/* Status multi-select */}
                            <div>
                                <label className="block text-xs text-netrix-muted mb-1.5 flex items-center gap-1.5">
                                    <Activity className="w-3 h-3" /> Status
                                </label>
                                <StatusFilter selected={filterStatuses} onChange={setFilterStatuses} />
                            </div>

                            {/* Action buttons */}
                            <div className="flex gap-2 pt-1">
                                <button
                                    onClick={applyFilters}
                                    className="px-4 py-2 bg-netrix-accent text-white rounded-lg text-sm font-medium hover:bg-netrix-accent/90 transition-all"
                                >
                                    Apply Filters
                                </button>
                                {activeFilterCount > 0 && (
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
                            <Scan className="w-4 h-4 text-netrix-muted" />
                            All Scans
                        </span>
                        <span className="text-xs text-netrix-muted">{total} total</span>
                    </div>

                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-netrix-border/50 bg-netrix-bg/40">
                                    {['Scan ID', 'Target', 'User', 'Type', 'Status', 'Progress', 'Started', 'Actions'].map(h => (
                                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-netrix-muted uppercase tracking-wider whitespace-nowrap">
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-netrix-border/30">
                                {loading ? (
                                    <tr>
                                        <td colSpan={8} className="px-4 py-12 text-center text-netrix-muted text-sm">
                                            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2" />
                                            Loading scans…
                                        </td>
                                    </tr>
                                ) : scans.length === 0 ? (
                                    <tr>
                                        <td colSpan={8} className="px-4 py-12 text-center text-netrix-muted text-sm">
                                            No scans match the current filters.
                                        </td>
                                    </tr>
                                ) : scans.map(scan => {
                                    const isExpanded = expandedRows.has(scan.scan_id)
                                    const cache = detailCache[scan.scan_id]
                                    return (
                                        <>
                                        <tr
                                            key={scan.id}
                                            className={`transition-colors cursor-pointer
                                                ${isExpanded ? 'bg-netrix-accent/[0.04] border-l-2 border-l-netrix-accent' : 'hover:bg-netrix-bg/30'}
                                                ${scan.status === 'running' ? 'bg-blue-500/[0.03]' : ''}
                                            `}
                                        >
                                            <td className="px-4 py-3">
                                                <span className="font-mono text-xs text-netrix-accent">{scan.scan_id}</span>
                                            </td>
                                            <td className="px-4 py-3 text-netrix-text text-sm max-w-[180px] truncate" title={scan.target}>
                                                {scan.target}
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="text-sm text-netrix-text font-medium leading-tight">{scan.username}</div>
                                                <div className="text-[11px] text-netrix-muted">{scan.email}</div>
                                            </td>
                                            <td className="px-4 py-3"><TypeBadge type={scan.scan_type} /></td>
                                            <td className="px-4 py-3"><StatusBadge status={scan.status} /></td>
                                            <td className="px-4 py-3 w-32">
                                                <ProgressBar value={scan.progress} status={scan.status} />
                                            </td>
                                            <td className="px-4 py-3 text-netrix-muted text-xs whitespace-nowrap">
                                                {scan.started_at ? formatDateIST(scan.started_at) : '—'}
                                            </td>
                                            <td className="px-4 py-3">
                                                <div className="flex items-center gap-1">
                                                    {/* Expand / collapse detail */}
                                                    <button
                                                        onClick={() => toggleDetail(scan)}
                                                        title={isExpanded ? 'Collapse details' : 'View scan details'}
                                                        className={`p-1.5 rounded-lg transition-all ${isExpanded ? 'text-netrix-accent bg-netrix-accent/10' : 'text-netrix-muted hover:text-netrix-accent hover:bg-netrix-accent/10'}`}
                                                    >
                                                        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                                    </button>
                                                    {/* Stop — only for running/pending */}
                                                    {(scan.status === 'running' || scan.status === 'pending') && (
                                                        <button
                                                            onClick={() => setStopTarget(scan)}
                                                            title="Force stop"
                                                            className="p-1.5 rounded-lg text-netrix-muted hover:text-blue-400 hover:bg-blue-400/10 transition-all"
                                                        >
                                                            <StopCircle className="w-4 h-4" />
                                                        </button>
                                                    )}
                                                    {/* Delete */}
                                                    <button
                                                        onClick={() => setDeleteTarget(scan)}
                                                        title="Delete scan"
                                                        className="p-1.5 rounded-lg text-netrix-muted hover:text-red-400 hover:bg-red-400/10 transition-all"
                                                    >
                                                        <Trash2 className="w-4 h-4" />
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>

                                        {/* ── Inline detail row ── */}
                                        {isExpanded && (
                                            <tr key={`${scan.id}-detail`} className="bg-netrix-bg/40 border-l-2 border-l-netrix-accent">
                                                <td colSpan={8} className="px-6 py-5">
                                                    {cache?.loading && (
                                                        <div className="flex items-center gap-2 text-netrix-muted text-sm py-4">
                                                            <RefreshCw className="w-4 h-4 animate-spin" /> Loading details…
                                                        </div>
                                                    )}
                                                    {cache?.error && (
                                                        <div className="flex items-center gap-2 text-red-400 text-sm py-2">
                                                            <AlertTriangle className="w-4 h-4" />{cache.error}
                                                        </div>
                                                    )}
                                                    {cache?.data && (
                                                        <div className="space-y-4">
                                                            {/* Summary stats */}
                                                            <div className="flex items-center gap-6 text-sm">
                                                                <span className="flex items-center gap-1.5 text-netrix-muted">
                                                                    <Server className="w-3.5 h-3.5" />
                                                                    <span className="font-semibold text-netrix-text">{cache.data.total_hosts}</span> hosts
                                                                </span>
                                                                <span className="flex items-center gap-1.5 text-netrix-muted">
                                                                    <Globe className="w-3.5 h-3.5" />
                                                                    <span className="font-semibold text-netrix-text">{cache.data.total_ports}</span> open ports
                                                                </span>
                                                                <span className="flex items-center gap-1.5 text-netrix-muted">
                                                                    <Shield className="w-3.5 h-3.5" />
                                                                    <span className="font-semibold text-netrix-text">{cache.data.total_vulnerabilities}</span> vulnerabilities
                                                                </span>
                                                            </div>

                                                            {/* Host cards */}
                                                            {cache.data.hosts.length === 0 ? (
                                                                <p className="text-netrix-muted text-sm">No hosts discovered yet.</p>
                                                            ) : (
                                                                <div className="space-y-3">
                                                                    {cache.data.hosts.map(host => (
                                                                        <HostCard key={host.id} host={host} />
                                                                    ))}
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                </td>
                                            </tr>
                                        )}
                                        </>
                                    )
                                })}
                            </tbody>
                        </table>
                    </div>

                    {/* Pagination */}
                    {totalPages > 1 && (
                        <div className="p-4 border-t border-netrix-border/50 flex items-center justify-between">
                            <span className="text-xs text-netrix-muted">Page {page} of {totalPages}</span>
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

            {/* Delete Confirm */}
            {deleteTarget && (
                <ConfirmDialog
                    title="Delete Scan"
                    body={<>Delete scan <strong className="text-netrix-text font-mono">{deleteTarget.scan_id}</strong> owned by <strong className="text-netrix-text">{deleteTarget.username}</strong>? This will cascade-delete all hosts, ports, vulnerabilities, and reports. This cannot be undone.</>}
                    confirmLabel="Delete"
                    confirmClass="bg-red-500 hover:bg-red-600"
                    loading={actionLoading}
                    onConfirm={handleDelete}
                    onCancel={() => setDeleteTarget(null)}
                />
            )}

            {/* Stop Confirm */}
            {stopTarget && (
                <ConfirmDialog
                    title="Force Stop Scan"
                    body={<>Force-stop scan <strong className="text-netrix-text font-mono">{stopTarget.scan_id}</strong>? The scan will be marked as failed immediately. The underlying nmap process may continue briefly until the OS reclaims it.</>}
                    confirmLabel="Force Stop"
                    confirmClass="bg-blue-600 hover:bg-blue-700"
                    loading={actionLoading}
                    onConfirm={handleStop}
                    onCancel={() => setStopTarget(null)}
                />
            )}

        </Layout>
    )
}
