import { useState, useEffect } from 'react'
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

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true)
            try {
                const [scanRes, resultsRes] = await Promise.all([
                    scansAPI.get(id),
                    scansAPI.results(id)
                ])
                setScan(scanRes.data)
                setResults(resultsRes.data)
            } catch (err) {
                setError(err.response?.data?.detail || 'Failed to load scan results')
            } finally {
                setLoading(false)
            }
        }
        fetchData()
    }, [id])

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
                <div className="flex flex-col items-center justify-center h-[60vh] text-center">
                    <AlertTriangle className="w-12 h-12 text-red-400 mb-3" />
                    <p className="text-red-400 mb-4">{error}</p>
                    <button onClick={() => navigate('/history')} className="btn-secondary">
                        Back to History
                    </button>
                </div>
            </Layout>
        )
    }

    const hosts = results?.hosts || results?.results?.hosts || []
    const vulns = results?.vulnerabilities || results?.results?.vulnerabilities || []
    const ports = results?.ports || results?.results?.ports || []

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
                                            <>
                                                <tr key={host.id} className="cursor-pointer" onClick={() => toggleHostPorts(host.id)}>
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
                                                            {host.open_ports ?? host.port_count ?? '—'}
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
                                                    <tr key={`${host.id}-ports`}>
                                                        <td colSpan={6} className="!p-0">
                                                            <div className="bg-netrix-bg/50 p-4">
                                                                <h4 className="text-sm font-semibold text-netrix-muted mb-2 flex items-center gap-1">
                                                                    <Lock className="w-3.5 h-3.5" /> Open Ports
                                                                </h4>
                                                                {hostPorts[host.id] && hostPorts[host.id].length > 0 ? (
                                                                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                                                                        {hostPorts[host.id].map((port, i) => (
                                                                            <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-netrix-card/50 border border-netrix-border/20">
                                                                                <span className="font-mono text-xs text-netrix-accent">{port.port_number || port.port}/{port.protocol || 'tcp'}</span>
                                                                                <span className="text-xs text-netrix-muted">—</span>
                                                                                <span className="text-xs text-netrix-text">{port.service_name || port.service || 'unknown'}</span>
                                                                            </div>
                                                                        ))}
                                                                    </div>
                                                                ) : (
                                                                    <p className="text-xs text-netrix-muted">No port details available</p>
                                                                )}
                                                            </div>
                                                        </td>
                                                    </tr>
                                                )}
                                            </>
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
                                            <tr key={i}>
                                                <td>
                                                    <span className="font-mono text-xs font-medium text-netrix-accent">
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
                                            <th>Version</th>
                                            <th>Host</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {ports.map((port, i) => (
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
                                                <td className="text-netrix-muted text-xs">{port.service_version || port.version || '—'}</td>
                                                <td className="font-mono text-xs text-netrix-muted">{port.host_ip || port.ip_address || '—'}</td>
                                            </tr>
                                        ))}
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
        </Layout>
    )
}
