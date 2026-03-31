// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect } from 'react'
import { vulnsAPI } from '../services/api'
import {
    Bug, Search, Filter, X, ExternalLink,
    Shield, AlertTriangle, ChevronDown, ChevronUp
} from 'lucide-react'
import Layout from '../components/Layout'
import LoadingSpinner from '../components/LoadingSpinner'
import VulnBadge from '../components/VulnBadge'

export default function Vulnerabilities() {
    const [vulns, setVulns] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [search, setSearch] = useState('')
    const [severityFilter, setSeverityFilter] = useState('all')
    const [sortField, setSortField] = useState('cvss_score')
    const [sortDir, setSortDir] = useState('desc')
    const [selectedVuln, setSelectedVuln] = useState(null)

    useEffect(() => {
        const loadVulns = async () => {
            setLoading(true)
            try {
                const params = { page_size: 500, page: 1 }
                if (severityFilter !== 'all') params.severity = severityFilter
                if (search) params.search = search
                const res = await vulnsAPI.list(params)
                const data = res.data
                let items = Array.isArray(data) ? data : data?.vulnerabilities || data?.items || []

                // Fetch remaining pages if total > 500
                const total = data?.total || items.length
                const totalPages = data?.total_pages || 1
                if (totalPages > 1) {
                    const rest = await Promise.all(
                        Array.from({ length: totalPages - 1 }, (_, i) =>
                            vulnsAPI.list({ ...params, page: i + 2 })
                        )
                    )
                    rest.forEach(r => {
                        const d = r.data
                        items = items.concat(Array.isArray(d) ? d : d?.vulnerabilities || d?.items || [])
                    })
                }
                setVulns(items)
            } catch (err) {
                if (err.response?.status !== 404) {
                    setError('Failed to load vulnerabilities')
                }
                setVulns([])
            } finally {
                setLoading(false)
            }
        }
        loadVulns()
    }, [severityFilter, search])

    const handleSort = (field) => {
        if (sortField === field) {
            setSortDir(d => d === 'asc' ? 'desc' : 'asc')
        } else {
            setSortField(field)
            setSortDir('desc')
        }
    }

    const sortedVulns = [...vulns].sort((a, b) => {
        const aVal = a[sortField] ?? ''
        const bVal = b[sortField] ?? ''
        if (typeof aVal === 'number' && typeof bVal === 'number') {
            return sortDir === 'asc' ? aVal - bVal : bVal - aVal
        }
        const aStr = String(aVal).toLowerCase()
        const bStr = String(bVal).toLowerCase()
        return sortDir === 'asc' ? aStr.localeCompare(bStr) : bStr.localeCompare(aStr)
    })

    const filteredVulns = sortedVulns.filter(v => {
        if (search) {
            const s = search.toLowerCase()
            return (
                v.cve_id?.toLowerCase().includes(s) ||
                v.description?.toLowerCase().includes(s) ||
                v.service?.toLowerCase().includes(s)
            )
        }
        return true
    })

    const SortIcon = ({ field }) => {
        if (sortField !== field) return null
        return sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
    }

    const severityOptions = ['all', 'critical', 'high', 'medium', 'low', 'info']

    return (
        <Layout>
            <div className="animate-fade-in">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text flex items-center gap-2">
                            <Bug className="w-6 h-6 text-netrix-accent" />
                            Vulnerabilities
                        </h1>
                        <p className="text-sm text-netrix-muted mt-0.5">
                            {filteredVulns.length} vulnerabilities found
                        </p>
                    </div>
                </div>

                {/* Filters */}
                <div className="flex flex-col sm:flex-row gap-3 mb-6">
                    <div className="flex items-center bg-netrix-bg border border-netrix-border rounded-lg focus-within:border-netrix-accent focus-within:ring-1 focus-within:ring-netrix-accent/30 transition-all duration-200 flex-1">
                        <span className="flex items-center justify-center w-10 shrink-0 text-netrix-muted/50">
                            <Search className="w-4 h-4" />
                        </span>
                        <input
                            type="text"
                            placeholder="Search by CVE ID, description, or service..."
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            className="w-full bg-transparent py-3 pr-4 text-netrix-text placeholder-netrix-muted/50 focus:outline-none"
                            autoComplete="off"
                        />
                    </div>
                    <div className="flex gap-2 flex-wrap">
                        {severityOptions.map(s => (
                            <button
                                key={s}
                                onClick={() => setSeverityFilter(s)}
                                className={`
                  px-3 py-2 rounded-lg text-xs font-medium capitalize transition-all duration-200 border
                  ${severityFilter === s
                                        ? 'bg-netrix-accent/15 text-netrix-accent border-netrix-accent/30'
                                        : 'bg-netrix-bg/50 text-netrix-muted border-netrix-border/30 hover:border-netrix-border'
                                    }
                `}
                            >
                                {s === 'all' ? 'All' : s}
                            </button>
                        ))}
                    </div>
                </div>

                {error && (
                    <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                        {error}
                    </div>
                )}

                {loading ? (
                    <div className="flex justify-center py-20">
                        <LoadingSpinner size="lg" text="Loading vulnerabilities..." />
                    </div>
                ) : filteredVulns.length > 0 ? (
                    <div className="glass-card overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full table-dark">
                                <thead>
                                    <tr>
                                        <th className="cursor-pointer" onClick={() => handleSort('cve_id')}>
                                            <span className="flex items-center gap-1">CVE ID <SortIcon field="cve_id" /></span>
                                        </th>
                                        <th className="cursor-pointer" onClick={() => handleSort('severity')}>
                                            <span className="flex items-center gap-1">Severity <SortIcon field="severity" /></span>
                                        </th>
                                        <th className="cursor-pointer" onClick={() => handleSort('cvss_score')}>
                                            <span className="flex items-center gap-1">CVSS <SortIcon field="cvss_score" /></span>
                                        </th>
                                        <th>Service</th>
                                        <th>Host</th>
                                        <th></th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {filteredVulns.map((vuln, i) => (
                                        <tr
                                            key={i}
                                            className="cursor-pointer"
                                            onClick={() => setSelectedVuln(vuln)}
                                        >
                                            <td>
                                                <span className="font-mono text-sm font-medium text-netrix-accent">
                                                    {vuln.cve_id || vuln.nse_script_name || '—'}
                                                </span>
                                            </td>
                                            <td><VulnBadge severity={vuln.severity} /></td>
                                            <td>
                                                <span className={`font-mono font-bold text-sm ${(vuln.cvss_score || 0) >= 9 ? 'text-severity-critical' :
                                                    (vuln.cvss_score || 0) >= 7 ? 'text-severity-high' :
                                                        (vuln.cvss_score || 0) >= 4 ? 'text-severity-medium' :
                                                            'text-severity-low'
                                                    }`}>
                                                    {vuln.cvss_score ?? '—'}
                                                </span>
                                            </td>
                                            <td className="text-netrix-muted text-sm">{vuln.service || vuln.affected_service || '—'}</td>
                                            <td className="font-mono text-xs text-netrix-muted">{vuln.host_ip || vuln.ip_address || '—'}</td>
                                            <td>
                                                <ExternalLink className="w-4 h-4 text-netrix-muted hover:text-netrix-accent transition-colors" />
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ) : (
                    <div className="glass-card p-16 flex flex-col items-center justify-center text-netrix-muted">
                        <Shield className="w-12 h-12 mb-3 opacity-30" />
                        <p className="text-sm">No vulnerabilities found</p>
                        {(search || severityFilter !== 'all') && (
                            <button
                                onClick={() => { setSearch(''); setSeverityFilter('all') }}
                                className="mt-3 text-xs text-netrix-accent hover:text-cyan-300 flex items-center gap-1"
                            >
                                <X className="w-3 h-3" /> Clear filters
                            </button>
                        )}
                    </div>
                )}

                {/* Detail Modal */}
                {selectedVuln && (
                    <div className="modal-overlay" onClick={() => setSelectedVuln(null)}>
                        <div
                            className="glass-card w-full max-w-lg mx-4 p-6 max-h-[80vh] overflow-y-auto"
                            onClick={(e) => e.stopPropagation()}
                        >
                            <div className="flex items-start justify-between mb-4">
                                <div>
                                    <h3 className="text-lg font-bold text-netrix-text font-mono">
                                        {selectedVuln.cve_id || selectedVuln.nse_script_name || 'Vulnerability Details'}
                                    </h3>
                                    <VulnBadge severity={selectedVuln.severity} size="md" />
                                </div>
                                <button
                                    onClick={() => setSelectedVuln(null)}
                                    className="p-1 rounded-lg hover:bg-netrix-bg transition-colors"
                                >
                                    <X className="w-5 h-5 text-netrix-muted" />
                                </button>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <label className="text-xs text-netrix-muted uppercase tracking-wider">CVSS Score</label>
                                    <p className={`text-2xl font-bold font-mono ${(selectedVuln.cvss_score || 0) >= 9 ? 'text-severity-critical' :
                                        (selectedVuln.cvss_score || 0) >= 7 ? 'text-severity-high' :
                                            'text-severity-medium'
                                        }`}>
                                        {selectedVuln.cvss_score ?? 'N/A'}
                                    </p>
                                </div>

                                <div>
                                    <label className="text-xs text-netrix-muted uppercase tracking-wider">Description</label>
                                    <p className="text-sm text-netrix-text mt-1 leading-relaxed">
                                        {selectedVuln.description || 'No description available.'}
                                    </p>
                                </div>

                                <div className="grid grid-cols-2 gap-4">
                                    <div>
                                        <label className="text-xs text-netrix-muted uppercase tracking-wider">Affected Service</label>
                                        <p className="text-sm text-netrix-text mt-1">
                                            {selectedVuln.service || selectedVuln.affected_service || '—'}
                                        </p>
                                    </div>
                                    <div>
                                        <label className="text-xs text-netrix-muted uppercase tracking-wider">Host</label>
                                        <p className="text-sm text-netrix-text mt-1 font-mono">
                                            {selectedVuln.host_ip || selectedVuln.ip_address || '—'}
                                        </p>
                                    </div>
                                </div>

                                {selectedVuln.remediation && (
                                    <div>
                                        <label className="text-xs text-netrix-muted uppercase tracking-wider">Remediation</label>
                                        <p className="text-sm text-netrix-text mt-1 leading-relaxed">
                                            {selectedVuln.remediation}
                                        </p>
                                    </div>
                                )}

                                {selectedVuln.cve_id && (
                                    <a
                                        href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="flex items-center gap-2 text-sm text-netrix-accent hover:text-cyan-300 transition-colors mt-4"
                                    >
                                        <ExternalLink className="w-4 h-4" />
                                        View on NVD
                                    </a>
                                )}
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </Layout>
    )
}
