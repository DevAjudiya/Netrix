// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect, Fragment } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { scansAPI, hostsAPI, vulnsAPI, reportsAPI } from '../services/api'
import {
    Monitor, Globe, Shield, Lock, FileText,
    ChevronDown, ChevronUp, ArrowLeft, Download,
    Server, Wifi, Bug, AlertTriangle, CheckCircle2
} from 'lucide-react'
import Layout from '../components/Layout'
import LoadingSpinner from '../components/LoadingSpinner'
import VulnBadge from '../components/VulnBadge'

const tabs = [
    { key: 'hosts', label: 'Hosts', icon: Monitor },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { key: 'ports', label: 'Ports', icon: Lock },
]

export default function ScanResults() {
    const { id } = useParams()
    const navigate = useNavigate()
    const [scan, setScan] = useState(null)
    const [results, setResults] = useState(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [activeTab, setActiveTab] = useState('hosts')
    const [expandedHost, setExpandedHost] = useState(null)
    const [hostPorts, setHostPorts] = useState({})
    const [sortField, setSortField] = useState('ip_address')
    const [sortDir, setSortDir] = useState('asc')
    const [generating, setGenerating] = useState(false)
    const [selectedVuln, setSelectedVuln] = useState(null)

    useEffect(() => {
        loadScanResults()
    }, [id])

    const loadScanResults = async () => {
        setLoading(true)
        setError(null)
        try {
            const [scanRes, resultsRes] = await Promise.all([
                scansAPI.get(id),
                scansAPI.results(id)
            ])
            setScan(scanRes.data)
            setResults(resultsRes.data)
        } catch (err) {
            console.error('Load error:', err)
            if (err.response?.status === 404) {
                setError('Scan not found')
            } else if (err.response?.status === 500) {
                setError(`Server error: ${err.response?.data?.detail || 'Unknown error'}`)
            } else {
                setError('Failed to load scan results')
            }
        } finally {
            setLoading(false)
        }
    }

    const toggleHostPorts = async (hostId) => {
        if (expandedHost === hostId) {
            setExpandedHost(null)
            return
        }
        setExpandedHost(hostId)
        if (!hostPorts[hostId]) {
            try {
                const res = await hostsAPI.ports(hostId)
                setHostPorts(prev => ({ ...prev, [hostId]: res.data }))
            } catch {
                setHostPorts(prev => ({ ...prev, [hostId]: [] }))
            }
        }
    }

    const handleGenerateReport = async () => {
        setGenerating(true)
        try {
            await reportsAPI.generate(parseInt(id), 'pdf', `Scan_${scan?.scan_id || id}_Report`)
            navigate('/reports')
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to generate report')
        } finally {
            setGenerating(false)
        }
    }

    const sortData = (data, field) => {
        if (!Array.isArray(data)) return []
        return [...data].sort((a, b) => {
            const aVal = a[field] || ''
            const bVal = b[field] || ''
            if (sortDir === 'asc') return aVal > bVal ? 1 : -1
            return aVal < bVal ? 1 : -1
        })
    }

    const handleSort = (field) => {
        if (sortField === field) {
            setSortDir(d => d === 'asc' ? 'desc' : 'asc')
        } else {
            setSortField(field)
            setSortDir('asc')
        }
    }

    const SortIcon = ({ field }) => {
        if (sortField !== field) return null
        return sortDir === 'asc' ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />
    }

    const statusColor = (status) => {
        const m = {
            completed: 'text-green-400 bg-green-400/10 border-green-400/30',
            running: 'text-cyan-400 bg-cyan-400/10 border-cyan-400/30',
            pending: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
            failed: 'text-red-400 bg-red-400/10 border-red-400/30'
        }
        return m[status] || 'text-gray-400 bg-gray-400/10 border-gray-400/30'
    }

    if (loading) {
        return (
            <Layout>
                <div className="flex items-center justify-center h-[60vh]">
                    <LoadingSpinner size="lg" text="Loading scan results..." />
                </div>
            </Layout>
        )
    }

    if (error) {
        return (
            <Layout>
                <div className="flex flex-col items-center justify-center h-[60vh] gap-4 text-center">
                    <AlertTriangle className="w-12 h-12 text-red-400 mb-2" />
                    <div className="text-red-400 text-lg mb-2">⚠️ {error}</div>
                    <div className="flex gap-3">
                        <button onClick={() => navigate('/history')} className="btn-secondary px-4 py-2">
                            Back to History
                        </button>
                        <button onClick={loadScanResults} className="btn-primary flex items-center gap-2 px-4 py-2">
                            🔄 Retry
                        </button>
                    </div>
                </div>
            </Layout>
        )
    }

    const hosts = results?.hosts || results?.results?.hosts || []
    const vulns = hosts.flatMap(h => h.vulnerabilities || [])
    const ports = hosts.flatMap(h =>
        (h.ports || []).map(p => ({ ...p, host_ip: h.ip_address }))
    )

    return (
        <Layout>
            <div className="animate-fade-in">
                {/* Header */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                    <div>
                        <button
                            onClick={() => navigate(-1)}
                            className="flex items-center gap-1 text-netrix-muted hover:text-netrix-text text-sm mb-2 transition-colors"
                        >
                            <ArrowLeft className="w-4 h-4" /> Back
                        </button>
                        <h1 className="text-2xl font-bold text-netrix-text">
                            Scan Results
                        </h1>
                        <div className="flex flex-wrap items-center gap-3 mt-2">
                            <span className="text-sm text-netrix-muted font-mono">
                                {scan?.scan_id || `#${id}`}
                            </span>
                            <span className="text-netrix-border">•</span>
                            <span className="text-sm text-netrix-muted flex items-center gap-1">
                                <Globe className="w-3.5 h-3.5" /> {scan?.target}
                            </span>
                            <span className="text-netrix-border">•</span>
                            <span className="text-sm text-netrix-muted capitalize">{scan?.scan_type}</span>
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium border ${statusColor(scan?.status)}`}>
                                {scan?.status === 'completed' && <CheckCircle2 className="w-3 h-3" />}
                                {scan?.status}
                            </span>
                        </div>
                    </div>
                    <button
                        onClick={handleGenerateReport}
                        disabled={generating}
                        className="btn-primary flex items-center gap-2"
                    >
                        {generating ? <LoadingSpinner size="sm" /> : <FileText className="w-4 h-4" />}
                        Generate Report
                    </button>
                </div>

                {/* Tabs */}
                <div className="flex gap-1 p-1 bg-netrix-bg/50 rounded-xl border border-netrix-border/30 mb-6 w-fit">
                    {tabs.map(({ key, label, icon: Icon }) => (
                        <button
                            key={key}
                            onClick={() => setActiveTab(key)}
                            className={`
                flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200
                ${activeTab === key
                                    ? 'bg-netrix-accent/15 text-netrix-accent shadow-sm'
                                    : 'text-netrix-muted hover:text-netrix-text hover:bg-netrix-bg/50'
                                }
              `}
                        >
                            <Icon className="w-4 h-4" />
                            {label}
                        </button>
                    ))}
                </div>

                {/* Tab Content */}
                <div className="glass-card overflow-hidden">
                    {activeTab === 'hosts' && (
                        <div className="overflow-x-auto">
                            {hosts.length > 0 ? (
                                <table className="w-full table-dark">
                                    <thead>
                                        <tr>
                                            <th className="cursor-pointer" onClick={() => handleSort('ip_address')}>
                                                <span className="flex items-center gap-1">IP Address <SortIcon field="ip_address" /></span>
                                            </th>
                                            <th>Hostname</th>
                                            <th>OS</th>
                                            <th className="cursor-pointer" onClick={() => handleSort('open_ports')}>
                                                <span className="flex items-center gap-1">Ports <SortIcon field="open_ports" /></span>
                                            </th>
                                            <th>Risk</th>
                                            <th></th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {sortData(hosts, sortField).map((host) => (
                                            <Fragment key={host.id}>
                                                <tr className="cursor-pointer" onClick={() => toggleHostPorts(host.id)}>
                                                    <td>
                                                        <div className="flex items-center gap-2">
                                                            <Server className="w-4 h-4 text-netrix-muted" />
                                                            <span className="font-mono font-medium">{host.ip_address}</span>
                                                        </div>
                                                    </td>
                                                    <td className="text-netrix-muted">{host.hostname || '—'}</td>
                                                    <td className="text-netrix-muted">{host.os_name || host.os || '—'}</td>
                                                    <td>
                                                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-netrix-accent/10 text-netrix-accent text-xs font-medium">
                                                            <Wifi className="w-3 h-3" />
                                                            {host.open_ports ?? host.port_count ?? host.ports?.length ?? '—'}
                                                        </span>
                                                    </td>
                                                    <td>
                                                        {host.risk_level
                                                            ? <VulnBadge severity={host.risk_level} />
                                                            : <span className="text-netrix-muted text-xs">—</span>
                                                        }
                                                    </td>
                                                    <td>
                                                        {expandedHost === host.id
                                                            ? <ChevronUp className="w-4 h-4 text-netrix-muted" />
                                                            : <ChevronDown className="w-4 h-4 text-netrix-muted" />
                                                        }
                                                    </td>
                                                </tr>
                                                {expandedHost === host.id && (
                                                    <tr>
                                                        <td colSpan={6} className="!p-0">
                                                            <div className="bg-netrix-bg/50 p-4">
                                                                <h4 className="text-sm font-semibold text-netrix-muted mb-2 flex items-center gap-1">
                                                                    <Lock className="w-3.5 h-3.5" /> Open Ports
                                                                </h4>
                                                                {host.ports && host.ports.length > 0 ? (
                                                                    <table className="w-full table-dark">
                                                                        <thead>
                                                                            <tr>
                                                                                <th>Port</th>
                                                                                <th>Protocol</th>
                                                                                <th>Service</th>
                                                                                <th>Product / Version</th>
                                                                                <th>State</th>
                                                                            </tr>
                                                                        </thead>
                                                                        <tbody>
                                                                            {host.ports.map(port => {
                                                                                const sv = [port.product, port.version, port.extra_info].filter(Boolean).join(' ') || '—'
                                                                                return (
                                                                                <tr key={port.id || port.port_number}>
                                                                                    <td>{port.port_number || port.port}</td>
                                                                                    <td>{port.protocol || 'tcp'}</td>
                                                                                    <td>{port.service_name || port.service || 'unknown'}</td>
                                                                                    <td>{sv}</td>
                                                                                    <td>{port.state || 'open'}</td>
                                                                                </tr>
                                                                                )
                                                                            })}
                                                                        </tbody>
                                                                    </table>
                                                                ) : (
                                                                    <p className="text-xs text-netrix-muted">No port details available</p>
                                                                )}
                                                            </div>
                                                        </td>
                                                    </tr>
                                                )}
                                            </Fragment>
                                        ))}
                                    </tbody>
                                </table>
                            ) : (
                                <div className="flex flex-col items-center justify-center py-16 text-netrix-muted">
                                    <Monitor className="w-10 h-10 mb-2 opacity-30" />
                                    <p className="text-sm">No hosts found in this scan</p>
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === 'vulnerabilities' && (
                        <div className="overflow-x-auto">
                            {vulns.length > 0 ? (
                                <table className="w-full table-dark">
                                    <thead>
                                        <tr>
                                            <th>CVE ID</th>
                                            <th>Severity</th>
                                            <th>CVSS</th>
                                            <th>Service</th>
                                            <th>Host</th>
                                            <th>Description</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {vulns.map((vuln, i) => (
                                            <tr key={i} className="cursor-pointer hover:bg-netrix-accent/5" onClick={() => setSelectedVuln(vuln)}>
                                                <td>
                                                    <span className="font-mono text-xs font-medium text-netrix-accent hover:underline">
                                                        {vuln.cve_id || '—'}
                                                    </span>
                                                </td>
                                                <td><VulnBadge severity={vuln.severity} /></td>
                                                <td>
                                                    <span className="font-mono font-semibold">
                                                        {vuln.cvss_score ?? '—'}
                                                    </span>
                                                </td>
                                                <td className="text-netrix-muted">{vuln.service || vuln.affected_service || '—'}</td>
                                                <td className="font-mono text-xs text-netrix-muted">{vuln.host_ip || vuln.ip_address || '—'}</td>
                                                <td>
                                                    <p className="text-xs text-netrix-muted max-w-xs truncate">
                                                        {vuln.description || '—'}
                                                    </p>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            ) : (
                                <div className="flex flex-col items-center justify-center py-16 text-netrix-muted">
                                    <Shield className="w-10 h-10 mb-2 opacity-30" />
                                    <p className="text-sm">No vulnerabilities found</p>
                                </div>
                            )}
                        </div>
                    )}

                    {activeTab === 'ports' && (
                        <div className="overflow-x-auto">
                            {ports.length > 0 ? (
                                <table className="w-full table-dark">
                                    <thead>
                                        <tr>
                                            <th>Port</th>
                                            <th>Protocol</th>
                                            <th>State</th>
                                            <th>Service</th>
                                            <th>Product / Version</th>
                                            <th>Host</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {ports.map((port, i) => {
                                            const product = port.product || ''
                                            const version = port.version || ''
                                            const extraInfo = port.extra_info || ''
                                            const serviceVersion = [product, version, extraInfo].filter(Boolean).join(' ') || '—'
                                            return (
                                            <tr key={i}>
                                                <td>
                                                    <span className="font-mono font-semibold text-netrix-accent">
                                                        {port.port_number || port.port}
                                                    </span>
                                                </td>
                                                <td className="uppercase text-xs text-netrix-muted">{port.protocol || 'tcp'}</td>
                                                <td>
                                                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${port.state === 'open'
                                                            ? 'bg-green-400/10 text-green-400'
                                                            : 'bg-yellow-400/10 text-yellow-400'
                                                        }`}>
                                                        {port.state || 'open'}
                                                    </span>
                                                </td>
                                                <td className="text-netrix-text">{port.service_name || port.service || '—'}</td>
                                                <td className="text-netrix-muted">{serviceVersion}</td>
                                                <td className="font-mono text-xs text-netrix-muted">{port.host_ip || port.ip_address || '—'}</td>
                                            </tr>
                                            )
                                        })}
                                    </tbody>
                                </table>
                            ) : (
                                <div className="flex flex-col items-center justify-center py-16 text-netrix-muted">
                                    <Lock className="w-10 h-10 mb-2 opacity-30" />
                                    <p className="text-sm">No port data available</p>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            </div>

            {/* CVE Detail Modal */}
            {selectedVuln && (
                <div
                    className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm"
                    onClick={() => setSelectedVuln(null)}
                >
                    <div
                        className="glass-card w-full max-w-lg p-6 relative animate-fade-in"
                        onClick={e => e.stopPropagation()}
                    >
                        <button
                            onClick={() => setSelectedVuln(null)}
                            className="absolute top-4 right-4 text-netrix-muted hover:text-netrix-text transition-colors"
                        >
                            ✕
                        </button>
                        <h2 className="text-xl font-bold font-mono text-netrix-text mb-2">
                            {selectedVuln.cve_id}
                        </h2>
                        <div className="mb-4">
                            <VulnBadge severity={selectedVuln.severity} />
                        </div>
                        <div className="mb-4">
                            <p className="text-xs uppercase tracking-widest text-netrix-muted mb-1">CVSS Score</p>
                            <p className="text-2xl font-bold text-netrix-accent font-mono">{selectedVuln.cvss_score ?? '—'}</p>
                        </div>
                        <div className="mb-4">
                            <p className="text-xs uppercase tracking-widest text-netrix-muted mb-1">Description</p>
                            <p className="text-sm text-netrix-text leading-relaxed">{selectedVuln.description || '—'}</p>
                        </div>
                        <div className="grid grid-cols-2 gap-4 mb-4">
                            <div>
                                <p className="text-xs uppercase tracking-widest text-netrix-muted mb-1">Affected Service</p>
                                <p className="text-sm text-netrix-text">{selectedVuln.service || selectedVuln.affected_service || '—'}</p>
                            </div>
                            <div>
                                <p className="text-xs uppercase tracking-widest text-netrix-muted mb-1">Host</p>
                                <p className="text-sm font-mono text-netrix-text">{selectedVuln.host_ip || selectedVuln.ip_address || '—'}</p>
                            </div>
                        </div>
                        {selectedVuln.remediation && (
                            <div className="mb-4">
                                <p className="text-xs uppercase tracking-widest text-netrix-muted mb-1">Remediation</p>
                                <p className="text-sm text-netrix-text leading-relaxed">{selectedVuln.remediation}</p>
                            </div>
                        )}
                        {selectedVuln.cve_id && (
                            <a
                                href={`https://nvd.nist.gov/vuln/detail/${selectedVuln.cve_id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-2 text-sm text-netrix-accent hover:underline mt-1"
                            >
                                <Globe className="w-4 h-4" /> View on NVD
                            </a>
                        )}
                    </div>
                </div>
            )}
        </Layout>
    )
}
