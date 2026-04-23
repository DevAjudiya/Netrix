// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect, useCallback, useRef } from 'react'
import { adminAPI } from '../services/api'
import Layout from '../components/Layout'
import {
    ShieldCheck, RefreshCw, Database, Clock,
    Plus, AlertTriangle, CheckCircle, XCircle,
    Play, Loader2, RotateCcw, Wifi, WifiOff,
    Search, ChevronLeft, ChevronRight, X,
    ExternalLink, Shield, Info, Tag, FileText
} from 'lucide-react'

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtDateTime(iso) {
    if (!iso) return 'Never'
    return new Date(iso).toLocaleString([], {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit'
    })
}

function fmtRelative(iso) {
    if (!iso) return ''
    const secs = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
    if (secs < 10) return 'just now'
    if (secs < 60) return `${secs}s ago`
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`
    return `${Math.floor(secs / 3600)}h ago`
}

const SEV_STYLES = {
    critical: 'bg-red-500/15 text-red-400 border border-red-500/30',
    high:     'bg-orange-500/15 text-orange-400 border border-orange-500/30',
    medium:   'bg-amber-500/15 text-amber-400 border border-amber-500/30',
    low:      'bg-blue-500/15 text-blue-400 border border-blue-500/30',
    info:     'bg-slate-500/15 text-slate-400 border border-slate-500/30',
}

function SeverityBadge({ severity }) {
    const s = (severity || 'info').toLowerCase()
    return (
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide ${SEV_STYLES[s] || SEV_STYLES.info}`}>
            {s}
        </span>
    )
}

function ScoreBar({ score }) {
    const pct = Math.min(100, (score / 10) * 100)
    const color = score >= 9 ? 'bg-red-500' : score >= 7 ? 'bg-orange-500' : score >= 4 ? 'bg-amber-500' : 'bg-blue-500'
    return (
        <div className="flex items-center gap-2">
            <span className="text-sm font-bold text-netrix-text w-8 shrink-0">{score.toFixed(1)}</span>
            <div className="flex-1 h-1.5 bg-netrix-border rounded-full overflow-hidden">
                <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
            </div>
        </div>
    )
}

// ── Stat Card ──────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, accent = 'cyan' }) {
    const colors = {
        cyan:   'text-netrix-accent border-netrix-accent/20 from-netrix-accent/5 to-blue-600/5',
        green:  'text-emerald-400 border-emerald-500/20 from-emerald-500/5 to-emerald-600/5',
        red:    'text-red-400 border-red-500/20 from-red-500/5 to-red-600/5',
        purple: 'text-purple-400 border-purple-500/20 from-purple-500/5 to-purple-600/5',
        amber:  'text-amber-400 border-amber-500/20 from-amber-500/5 to-amber-600/5',
    }
    const cls = colors[accent] || colors.cyan
    return (
        <div className={`rounded-xl border bg-gradient-to-br p-5 flex flex-col gap-2 ${cls}`}>
            <div className="flex items-center gap-2">
                <Icon className={`w-4 h-4 ${cls.split(' ')[0]}`} />
                <span className="text-xs font-medium text-netrix-muted uppercase tracking-wide">{label}</span>
            </div>
            <div className={`text-2xl font-bold ${cls.split(' ')[0]}`}>{value}</div>
            {sub && <p className="text-xs text-netrix-muted">{sub}</p>}
        </div>
    )
}

// ── Log Line ───────────────────────────────────────────────────────────────

function LogLine({ type, msg }) {
    const color = type === 'success' ? 'text-emerald-400' : type === 'error' ? 'text-red-400' : 'text-netrix-muted'
    const prefix = type === 'success' ? '✓' : type === 'error' ? '✗' : '›'
    return (
        <p className={`text-xs font-mono ${color}`}>{prefix} {msg}</p>
    )
}

// ── CVE Detail Modal ───────────────────────────────────────────────────────

function CVEModal({ cve, onClose }) {
    if (!cve) return null
    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
            <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
            <div className="relative w-full max-w-2xl max-h-[85vh] overflow-y-auto rounded-2xl border border-netrix-border bg-netrix-card shadow-2xl shadow-black/40 flex flex-col">
                {/* Header */}
                <div className="sticky top-0 bg-netrix-card border-b border-netrix-border px-6 py-4 flex items-start justify-between gap-4 z-10">
                    <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-base font-bold text-netrix-accent">{cve.cve_id}</span>
                            <SeverityBadge severity={cve.severity} />
                        </div>
                        <p className="text-xs text-netrix-muted mt-1 leading-relaxed line-clamp-2">{cve.title.replace(cve.cve_id + ' — ', '')}</p>
                    </div>
                    <button onClick={onClose} className="shrink-0 p-1.5 rounded-lg hover:bg-netrix-border/50 text-netrix-muted hover:text-netrix-text transition-colors">
                        <X className="w-4 h-4" />
                    </button>
                </div>

                <div className="p-6 space-y-5">
                    {/* Score */}
                    <div className="grid grid-cols-2 gap-4">
                        <div className="rounded-xl bg-netrix-bg border border-netrix-border/50 p-4">
                            <p className="text-xs text-netrix-muted mb-2 uppercase tracking-wide font-medium">CVSS Score</p>
                            <ScoreBar score={cve.cvss_score} />
                        </div>
                        <div className="rounded-xl bg-netrix-bg border border-netrix-border/50 p-4">
                            <p className="text-xs text-netrix-muted mb-2 uppercase tracking-wide font-medium">Published</p>
                            <p className="text-sm font-semibold text-netrix-text">{cve.published_date || '—'}</p>
                        </div>
                    </div>

                    {/* CVSS Vector */}
                    {cve.cvss_vector && (
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <Tag className="w-3.5 h-3.5 text-netrix-muted" />
                                <p className="text-xs font-medium text-netrix-muted uppercase tracking-wide">CVSS Vector</p>
                            </div>
                            <code className="block text-xs font-mono text-netrix-accent bg-netrix-bg border border-netrix-border/50 px-3 py-2 rounded-lg break-all">
                                {cve.cvss_vector}
                            </code>
                        </div>
                    )}

                    {/* Description */}
                    <div>
                        <div className="flex items-center gap-2 mb-2">
                            <FileText className="w-3.5 h-3.5 text-netrix-muted" />
                            <p className="text-xs font-medium text-netrix-muted uppercase tracking-wide">Description</p>
                        </div>
                        <p className="text-sm text-netrix-text leading-relaxed">{cve.description || 'No description available.'}</p>
                    </div>

                    {/* Affected Products */}
                    {cve.affected?.length > 0 && (
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <Shield className="w-3.5 h-3.5 text-netrix-muted" />
                                <p className="text-xs font-medium text-netrix-muted uppercase tracking-wide">Affected Products</p>
                            </div>
                            <div className="flex flex-wrap gap-1.5">
                                {cve.affected.map((p, i) => (
                                    <span key={i} className="inline-flex items-center px-2.5 py-1 rounded-lg bg-netrix-bg border border-netrix-border/50 text-xs text-netrix-text font-mono">
                                        {p}
                                    </span>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Remediation */}
                    {cve.remediation && (
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                                <p className="text-xs font-medium text-netrix-muted uppercase tracking-wide">Remediation</p>
                            </div>
                            <p className="text-sm text-netrix-text leading-relaxed bg-emerald-500/5 border border-emerald-500/20 rounded-lg px-4 py-3">
                                {cve.remediation}
                            </p>
                        </div>
                    )}

                    {/* References */}
                    {cve.references?.length > 0 && (
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <ExternalLink className="w-3.5 h-3.5 text-netrix-muted" />
                                <p className="text-xs font-medium text-netrix-muted uppercase tracking-wide">References</p>
                            </div>
                            <div className="space-y-1.5">
                                {cve.references.map((url, i) => (
                                    <a
                                        key={i}
                                        href={url}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-2 text-xs text-netrix-accent hover:text-cyan-300 transition-colors truncate group"
                                    >
                                        <ExternalLink className="w-3 h-3 shrink-0 opacity-60 group-hover:opacity-100" />
                                        <span className="truncate">{url}</span>
                                    </a>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    )
}

// ── CVE Browser ────────────────────────────────────────────────────────────

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low']
const PAGE_SIZE = 25

function CVEBrowser() {
    const [cves, setCves] = useState([])
    const [total, setTotal] = useState(0)
    const [totalPages, setTotalPages] = useState(1)
    const [page, setPage] = useState(1)
    const [search, setSearch] = useState('')
    const [severity, setSeverity] = useState('')
    const [loading, setLoading] = useState(true)
    const [selected, setSelected] = useState(null)
    const searchTimer = useRef(null)

    const load = useCallback(async (p, q, sev) => {
        setLoading(true)
        try {
            const params = { page: p, page_size: PAGE_SIZE }
            if (q) params.search = q
            if (sev) params.severity = sev
            const res = await adminAPI.cveList(params)
            setCves(res.data.cves)
            setTotal(res.data.total)
            setTotalPages(res.data.total_pages)
        } catch {
            setCves([])
        } finally {
            setLoading(false)
        }
    }, [])

    useEffect(() => { load(page, search, severity) }, [page, severity])

    const handleSearch = (val) => {
        setSearch(val)
        clearTimeout(searchTimer.current)
        searchTimer.current = setTimeout(() => {
            setPage(1)
            load(1, val, severity)
        }, 350)
    }

    const handleSeverity = (val) => {
        setSeverity(val)
        setPage(1)
    }

    return (
        <>
            <div className="rounded-xl border border-netrix-border/50 bg-netrix-card/80 overflow-hidden">
                {/* Browser header */}
                <div className="p-4 border-b border-netrix-border/50 flex flex-wrap items-center gap-3">
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                        <Database className="w-4 h-4 text-netrix-accent shrink-0" />
                        <h2 className="text-sm font-semibold text-netrix-text">CVE Database Browser</h2>
                        <span className="text-xs text-netrix-muted">({total.toLocaleString()} entries)</span>
                    </div>

                    {/* Severity filter */}
                    <select
                        value={severity}
                        onChange={e => handleSeverity(e.target.value)}
                        className="text-xs bg-netrix-bg border border-netrix-border rounded-lg px-2.5 py-1.5 text-netrix-text focus:outline-none focus:border-netrix-accent"
                    >
                        <option value="">All severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>

                    {/* Search */}
                    <div className="flex items-center gap-2 bg-netrix-bg border border-netrix-border rounded-lg px-2.5 py-1.5 focus-within:border-netrix-accent transition-colors">
                        <Search className="w-3.5 h-3.5 text-netrix-muted shrink-0" />
                        <input
                            type="text"
                            value={search}
                            onChange={e => handleSearch(e.target.value)}
                            placeholder="Search CVE ID, description…"
                            className="bg-transparent text-xs text-netrix-text placeholder-netrix-muted/60 focus:outline-none w-44"
                        />
                        {search && (
                            <button onClick={() => handleSearch('')} className="text-netrix-muted hover:text-netrix-text">
                                <X className="w-3 h-3" />
                            </button>
                        )}
                    </div>
                </div>

                {/* Table */}
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-netrix-border/50 bg-netrix-bg/40">
                                <th className="text-left px-4 py-2.5 text-xs font-medium text-netrix-muted uppercase tracking-wide w-36">CVE ID</th>
                                <th className="text-left px-4 py-2.5 text-xs font-medium text-netrix-muted uppercase tracking-wide w-24">Severity</th>
                                <th className="text-left px-4 py-2.5 text-xs font-medium text-netrix-muted uppercase tracking-wide w-36">CVSS Score</th>
                                <th className="text-left px-4 py-2.5 text-xs font-medium text-netrix-muted uppercase tracking-wide w-28">Published</th>
                                <th className="text-left px-4 py-2.5 text-xs font-medium text-netrix-muted uppercase tracking-wide">Affected</th>
                            </tr>
                        </thead>
                        <tbody>
                            {loading ? (
                                Array.from({ length: 8 }).map((_, i) => (
                                    <tr key={i} className="border-b border-netrix-border/30">
                                        {Array.from({ length: 5 }).map((_, j) => (
                                            <td key={j} className="px-4 py-3">
                                                <div className="h-4 rounded bg-netrix-border/40 animate-pulse" />
                                            </td>
                                        ))}
                                    </tr>
                                ))
                            ) : cves.length === 0 ? (
                                <tr>
                                    <td colSpan={5} className="px-4 py-12 text-center text-netrix-muted text-sm">
                                        No CVEs match your filters.
                                    </td>
                                </tr>
                            ) : cves.map(cve => (
                                <tr
                                    key={cve.cve_id}
                                    onClick={() => setSelected(cve)}
                                    className="border-b border-netrix-border/30 hover:bg-netrix-accent/5 cursor-pointer transition-colors group"
                                >
                                    <td className="px-4 py-3">
                                        <span className="font-mono text-xs font-semibold text-netrix-accent group-hover:text-cyan-300 transition-colors">
                                            {cve.cve_id}
                                        </span>
                                    </td>
                                    <td className="px-4 py-3">
                                        <SeverityBadge severity={cve.severity} />
                                    </td>
                                    <td className="px-4 py-3 w-36">
                                        <ScoreBar score={cve.cvss_score} />
                                    </td>
                                    <td className="px-4 py-3 text-xs text-netrix-muted whitespace-nowrap">
                                        {cve.published_date || '—'}
                                    </td>
                                    <td className="px-4 py-3 text-xs text-netrix-muted max-w-xs truncate">
                                        {cve.affected?.length > 0
                                            ? cve.affected.slice(0, 2).join(', ') + (cve.affected.length > 2 ? ` +${cve.affected.length - 2} more` : '')
                                            : '—'}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="px-4 py-3 border-t border-netrix-border/50 flex items-center justify-between">
                        <p className="text-xs text-netrix-muted">
                            Page {page} of {totalPages} — {total.toLocaleString()} total
                        </p>
                        <div className="flex items-center gap-1">
                            <button
                                onClick={() => setPage(p => Math.max(1, p - 1))}
                                disabled={page === 1}
                                className="p-1.5 rounded-lg hover:bg-netrix-border/50 text-netrix-muted hover:text-netrix-text disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                            >
                                <ChevronLeft className="w-4 h-4" />
                            </button>
                            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                                const start = Math.max(1, Math.min(page - 2, totalPages - 4))
                                const p = start + i
                                return (
                                    <button
                                        key={p}
                                        onClick={() => setPage(p)}
                                        className={`w-7 h-7 rounded-lg text-xs font-medium transition-colors ${
                                            p === page
                                                ? 'bg-netrix-accent text-white'
                                                : 'hover:bg-netrix-border/50 text-netrix-muted hover:text-netrix-text'
                                        }`}
                                    >
                                        {p}
                                    </button>
                                )
                            })}
                            <button
                                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                                disabled={page === totalPages}
                                className="p-1.5 rounded-lg hover:bg-netrix-border/50 text-netrix-muted hover:text-netrix-text disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
                            >
                                <ChevronRight className="w-4 h-4" />
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {selected && <CVEModal cve={selected} onClose={() => setSelected(null)} />}
        </>
    )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function AdminCVE() {
    const [status, setStatus] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [log, setLog] = useState([])
    const [syncing, setSyncing] = useState(false)
    const [rematching, setRematching] = useState(false)
    const intervalRef = useRef(null)
    const pollRef = useRef(null)

    const addLog = (type, msg) =>
        setLog(prev => [{ type, msg, ts: Date.now() }, ...prev].slice(0, 20))

    const fetchStatus = useCallback(async (quiet = false, force = false) => {
        try {
            const res = await adminAPI.cveStatus(force)
            setStatus(res.data)
            setError(null)
            if (syncing && !res.data.sync_in_progress) {
                setSyncing(false)
                addLog('success', `Sync complete — ${res.data.cves_added_last_sync} CVE(s) added. Total: ${res.data.total_cves}`)
            }
        } catch (err) {
            if (!quiet) setError(err.response?.data?.detail || 'Failed to load CVE status.')
        } finally {
            if (!quiet) setLoading(false)
        }
    }, [syncing])

    useEffect(() => {
        fetchStatus()
        intervalRef.current = setInterval(() => fetchStatus(true), 30_000)
        return () => clearInterval(intervalRef.current)
    }, [fetchStatus])

    // Fast-poll while background NVD check is in progress
    useEffect(() => {
        if (status?.nvd_check_pending) {
            const t = setInterval(() => fetchStatus(true), 4_000)
            return () => clearInterval(t)
        }
    }, [status?.nvd_check_pending, fetchStatus])

    useEffect(() => {
        if (status?.sync_in_progress) {
            pollRef.current = setInterval(() => fetchStatus(true), 4_000)
        } else {
            clearInterval(pollRef.current)
        }
        return () => clearInterval(pollRef.current)
    }, [status?.sync_in_progress, fetchStatus])

    const handleSync = async () => {
        setSyncing(true)
        addLog('info', 'Requesting NVD sync…')
        try {
            await adminAPI.cveSync()
            addLog('info', 'Sync started in background — polling for completion…')
            await fetchStatus(true)
        } catch (err) {
            const msg = err.response?.data?.detail || 'Sync request failed.'
            addLog('error', msg)
            setSyncing(false)
        }
    }

    const handleRematch = async () => {
        setRematching(true)
        addLog('info', 'Requesting CVE rematch across all scan data…')
        try {
            await adminAPI.cveRematch()
            addLog('success', 'Rematch task queued — check server logs for completion counts.')
        } catch (err) {
            addLog('error', err.response?.data?.detail || 'Rematch request failed.')
        } finally {
            setRematching(false)
        }
    }

    const syncInProgress = status?.sync_in_progress || syncing

    return (
        <Layout>
            <div className="max-w-5xl mx-auto space-y-6">

                {/* Header */}
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text">CVE Control</h1>
                        <p className="text-sm text-netrix-muted mt-0.5">
                            Manage the offline CVE database and NVD synchronisation
                        </p>
                    </div>
                    <button
                        onClick={() => fetchStatus(false, true)}
                        className="flex items-center gap-2 px-3 py-2 rounded-lg bg-netrix-accent/10 text-netrix-accent hover:bg-netrix-accent/20 transition-colors text-sm font-medium"
                    >
                        <RefreshCw className="w-4 h-4" />
                        Refresh
                    </button>
                </div>

                {/* Error */}
                {error && (
                    <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
                        <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                        {error}
                    </div>
                )}

                {/* Stats */}
                {loading ? (
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        {Array.from({ length: 4 }).map((_, i) => (
                            <div key={i} className="h-28 rounded-xl bg-netrix-card/60 animate-pulse" />
                        ))}
                    </div>
                ) : status && (
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                        <StatCard
                            icon={Database}
                            label="Total CVEs"
                            value={status.total_cves.toLocaleString()}
                            sub="Entries in offline DB"
                            accent="cyan"
                        />
                        <StatCard
                            icon={Clock}
                            label="Last Sync"
                            value={status.last_sync ? fmtDateTime(status.last_sync) : 'Never'}
                            sub="NVD synchronisation"
                            accent="purple"
                        />
                        <StatCard
                            icon={Plus}
                            label="Added Last Sync"
                            value={status.cves_added_last_sync}
                            sub="New CVEs from NVD"
                            accent="amber"
                        />
                        <StatCard
                            icon={status.nvd_check_pending ? Loader2 : status.nvd_api_online ? Wifi : WifiOff}
                            label="NVD API"
                            value={status.nvd_check_pending ? 'Checking…' : status.nvd_api_online ? 'Online' : 'Offline'}
                            sub={
                                status.nvd_check_pending
                                    ? 'Pinging services.nvd.nist.gov'
                                    : status.nvd_api_online
                                        ? `Online · checked ${fmtRelative(status.nvd_last_checked)}`
                                        : `Offline DB active${status.nvd_last_checked ? ' · checked ' + fmtRelative(status.nvd_last_checked) : ''}`
                            }
                            accent={status.nvd_check_pending ? 'amber' : status.nvd_api_online ? 'green' : 'red'}
                        />
                    </div>
                )}

                {/* Actions */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    {/* Sync Now */}
                    <div className="rounded-xl border border-netrix-border/50 bg-netrix-card/80 p-5 space-y-4">
                        <div className="flex items-start gap-3">
                            <div className="p-2 rounded-lg bg-netrix-accent/10">
                                <RefreshCw className="w-5 h-5 text-netrix-accent" />
                            </div>
                            <div>
                                <h2 className="text-sm font-semibold text-netrix-text">Sync Now</h2>
                                <p className="text-xs text-netrix-muted mt-0.5 leading-relaxed">
                                    Fetch CVEs modified since the last sync from the NVD API and
                                    merge them into the offline database.
                                </p>
                            </div>
                        </div>

                        {syncInProgress && (
                            <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs">
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                Sync in progress — polling every 4s…
                            </div>
                        )}

                        <button
                            onClick={handleSync}
                            disabled={syncInProgress}
                            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-netrix-accent text-white text-sm font-medium hover:bg-netrix-accent/80 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                            {syncInProgress
                                ? <><Loader2 className="w-4 h-4 animate-spin" />Syncing…</>
                                : <><Play className="w-4 h-4" />Start Sync</>
                            }
                        </button>
                    </div>

                    {/* Re-match */}
                    <div className="rounded-xl border border-netrix-border/50 bg-netrix-card/80 p-5 space-y-4">
                        <div className="flex items-start gap-3">
                            <div className="p-2 rounded-lg bg-purple-500/10">
                                <RotateCcw className="w-5 h-5 text-purple-400" />
                            </div>
                            <div>
                                <h2 className="text-sm font-semibold text-netrix-text">Re-match All Scans</h2>
                                <p className="text-xs text-netrix-muted mt-0.5 leading-relaxed">
                                    Re-run CVE matching against every port in the database.
                                    Inserts newly discovered vulnerabilities for existing scan data.
                                </p>
                            </div>
                        </div>

                        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-400 text-xs">
                            <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                            <span>Matches against the offline DB first. NVD API is only queried for services with no offline results.</span>
                        </div>

                        <button
                            onClick={handleRematch}
                            disabled={rematching || syncInProgress}
                            className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-purple-600 text-white text-sm font-medium hover:bg-purple-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                        >
                            {rematching
                                ? <><Loader2 className="w-4 h-4 animate-spin" />Queuing…</>
                                : <><RotateCcw className="w-4 h-4" />Re-match All Scans</>
                            }
                        </button>
                    </div>
                </div>

                {/* Activity Log */}
                {log.length > 0 && (
                    <div className="rounded-xl border border-netrix-border/50 bg-netrix-card/80 p-5">
                        <div className="flex items-center gap-2 mb-3">
                            <ShieldCheck className="w-4 h-4 text-netrix-accent" />
                            <h2 className="text-sm font-semibold text-netrix-text">Activity Log</h2>
                        </div>
                        <div className="space-y-1 max-h-48 overflow-y-auto">
                            {log.map(entry => (
                                <LogLine key={entry.ts} type={entry.type} msg={entry.msg} />
                            ))}
                        </div>
                    </div>
                )}

                {/* CVE Database Browser */}
                <CVEBrowser />

            </div>
        </Layout>
    )
}
