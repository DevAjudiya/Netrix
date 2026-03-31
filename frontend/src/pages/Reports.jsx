// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect } from 'react'
import { reportsAPI, scansAPI } from '../services/api'
import {
    FileText, Download, Trash2, Plus,
    Loader2, File, FileSpreadsheet, Code,
    Globe, AlertTriangle
} from 'lucide-react'
import Layout from '../components/Layout'
import LoadingSpinner from '../components/LoadingSpinner'
import { formatDateIST } from '../utils/formatDate'

const formatIcons = {
    pdf: FileText,
    json: Code,
    csv: FileSpreadsheet,
    html: Globe
}

export default function Reports() {
    const [reports, setReports] = useState([])
    const [scans, setScans] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState(null)
    const [selectedScan, setSelectedScan] = useState('')
    const [format, setFormat] = useState('pdf')
    const [reportName, setReportName] = useState('')
    const [generating, setGenerating] = useState(false)
    const [downloading, setDownloading] = useState(null)

    const fetchReports = async () => {
        try {
            const res = await reportsAPI.list()
            setReports(Array.isArray(res.data) ? res.data : res.data?.items || res.data?.reports || [])
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load reports')
        }
    }

    useEffect(() => {
        const fetchData = async () => {
            setLoading(true)
            try {
                const [reportsRes, scansRes] = await Promise.all([
                    reportsAPI.list(),
                    scansAPI.list({ status: 'completed' })
                ])
                setReports(Array.isArray(reportsRes.data) ? reportsRes.data : reportsRes.data?.items || reportsRes.data?.reports || [])
                const scanData = Array.isArray(scansRes.data) ? scansRes.data : scansRes.data?.items || scansRes.data?.scans || []
                setScans(scanData)
                if (scanData.length > 0) setSelectedScan(scanData[0].id)
            } catch (err) {
                setError(err.response?.data?.detail || 'Failed to load data')
            } finally {
                setLoading(false)
            }
        }
        fetchData()
    }, [])

    const handleGenerate = async () => {
        if (!selectedScan) return setError('Please select a scan')
        setGenerating(true)
        setError(null)
        try {
            const name = reportName.trim() || `Report_Scan_${selectedScan}`
            await reportsAPI.generate(parseInt(selectedScan), format, name)
            setReportName('')
            await fetchReports()
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to generate report')
        } finally {
            setGenerating(false)
        }
    }

    const mimeTypes = {
        pdf: 'application/pdf',
        json: 'application/json',
        csv: 'text/csv',
        html: 'text/html'
    }

    const handleDownload = async (reportId, reportFileName, reportFormat) => {
        setDownloading(reportId)
        try {
            const res = await reportsAPI.download(reportId)
            const mime = mimeTypes[reportFormat] || 'application/octet-stream'
            const url = window.URL.createObjectURL(new Blob([res.data], { type: mime }))
            const link = document.createElement('a')
            link.href = url
            // Ensure filename has the correct extension
            const baseName = reportFileName || `report_${reportId}`
            const ext = reportFormat ? `.${reportFormat}` : ''
            const hasExt = ext && baseName.toLowerCase().endsWith(ext)
            link.setAttribute('download', hasExt ? baseName : `${baseName}${ext}`)
            document.body.appendChild(link)
            link.click()
            link.remove()
            window.URL.revokeObjectURL(url)
        } catch (err) {
            setError(err.response?.data?.detail || 'Download failed')
        } finally {
            setDownloading(null)
        }
    }

    const handleDelete = async (reportId) => {
        if (!confirm('Delete this report?')) return
        try {
            await reportsAPI.delete(reportId)
            await fetchReports()
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to delete report')
        }
    }

    const formatDate = formatDateIST

    if (loading) {
        return (
            <Layout>
                <div className="flex justify-center h-[60vh] items-center">
                    <LoadingSpinner size="lg" text="Loading reports..." />
                </div>
            </Layout>
        )
    }

    return (
        <Layout>
            <div className="animate-fade-in">
                <div className="mb-6">
                    <h1 className="text-2xl font-bold text-netrix-text flex items-center gap-2">
                        <FileText className="w-6 h-6 text-netrix-accent" />
                        Reports
                    </h1>
                    <p className="text-sm text-netrix-muted mt-0.5">Generate and manage scan reports</p>
                </div>

                {error && (
                    <div className="mb-6 p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                        {error}
                    </div>
                )}

                {/* Generate Section */}
                <div className="glass-card p-6 mb-6">
                    <h2 className="text-lg font-semibold text-netrix-text mb-4 flex items-center gap-2">
                        <Plus className="w-5 h-5 text-netrix-accent" />
                        Generate New Report
                    </h2>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-4">
                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Select Scan</label>
                            <select
                                value={selectedScan}
                                onChange={(e) => setSelectedScan(e.target.value)}
                                className="input-dark"
                                disabled={generating}
                            >
                                <option value="">Select a scan...</option>
                                {scans.map(scan => (
                                    <option key={scan.id} value={scan.id}>
                                        {scan.scan_id || `Scan #${scan.id}`} — {scan.target}
                                    </option>
                                ))}
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Report Name (optional)</label>
                            <input
                                type="text"
                                value={reportName}
                                onChange={(e) => setReportName(e.target.value)}
                                placeholder="e.g. Weekly_Audit_Report"
                                className="input-dark"
                                disabled={generating}
                            />
                        </div>
                    </div>

                    <div className="mb-4">
                        <label className="block text-sm font-medium text-netrix-muted mb-2">Format</label>
                        <div className="flex gap-3">
                            {['pdf', 'json', 'csv', 'html'].map(f => {
                                const Icon = formatIcons[f]
                                return (
                                    <button
                                        key={f}
                                        onClick={() => setFormat(f)}
                                        disabled={generating}
                                        className={`
                      flex items-center gap-2 px-4 py-2.5 rounded-xl border transition-all duration-200
                      ${format === f
                                                ? 'bg-netrix-accent/15 border-netrix-accent/40 text-netrix-accent shadow-lg shadow-netrix-accent/5'
                                                : 'bg-netrix-bg/30 border-netrix-border/30 text-netrix-muted hover:border-netrix-border'
                                            }
                    `}
                                    >
                                        <Icon className="w-4 h-4" />
                                        <span className="text-sm font-medium uppercase">{f}</span>
                                    </button>
                                )
                            })}
                        </div>
                    </div>

                    <button
                        onClick={handleGenerate}
                        disabled={generating || !selectedScan}
                        className="btn-primary flex items-center gap-2"
                    >
                        {generating ? (
                            <>
                                <Loader2 className="w-4 h-4 animate-spin" />
                                Generating...
                            </>
                        ) : (
                            <>
                                <FileText className="w-4 h-4" />
                                GENERATE REPORT
                            </>
                        )}
                    </button>
                </div>

                {/* Reports List */}
                <div className="glass-card overflow-hidden">
                    <div className="px-6 py-4 border-b border-netrix-border/30">
                        <h2 className="text-lg font-semibold text-netrix-text">My Reports</h2>
                    </div>

                    {reports.length > 0 ? (
                        <div className="overflow-x-auto">
                            <table className="w-full table-dark">
                                <thead>
                                    <tr>
                                        <th>Report Name</th>
                                        <th>Format</th>
                                        <th>Created</th>
                                        <th>Scan</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {reports.map(report => {
                                        const Icon = formatIcons[report.format] || File
                                        return (
                                            <tr key={report.id}>
                                                <td>
                                                    <div className="flex items-center gap-2">
                                                        <Icon className="w-4 h-4 text-netrix-accent" />
                                                        <span className="font-medium">
                                                            {report.report_name || report.file_name || `Report #${report.id}`}
                                                        </span>
                                                    </div>
                                                </td>
                                                <td>
                                                    <span className="px-2 py-0.5 rounded bg-netrix-bg text-xs font-mono uppercase text-netrix-muted">
                                                        {report.format}
                                                    </span>
                                                </td>
                                                <td className="text-netrix-muted text-sm">{formatDate(report.generated_at || report.created_at)}</td>
                                                <td className="font-mono text-xs text-netrix-muted">{report.scan_id || '—'}</td>
                                                <td>
                                                    <div className="flex items-center gap-2">
                                                        <button
                                                            onClick={() => handleDownload(report.id, report.file_name || report.report_name, report.format)}
                                                            disabled={downloading === report.id}
                                                            className="p-2 rounded-lg hover:bg-netrix-accent/10 text-netrix-muted hover:text-netrix-accent transition-all"
                                                            title="Download"
                                                        >
                                                            {downloading === report.id
                                                                ? <Loader2 className="w-4 h-4 animate-spin" />
                                                                : <Download className="w-4 h-4" />
                                                            }
                                                        </button>
                                                        <button
                                                            onClick={() => handleDelete(report.id)}
                                                            className="p-2 rounded-lg hover:bg-red-500/10 text-netrix-muted hover:text-red-400 transition-all"
                                                            title="Delete"
                                                        >
                                                            <Trash2 className="w-4 h-4" />
                                                        </button>
                                                    </div>
                                                </td>
                                            </tr>
                                        )
                                    })}
                                </tbody>
                            </table>
                        </div>
                    ) : (
                        <div className="flex flex-col items-center justify-center py-16 text-netrix-muted">
                            <FileText className="w-12 h-12 mb-3 opacity-30" />
                            <p className="text-sm">No reports generated yet</p>
                            <p className="text-xs mt-1">Use the form above to generate your first report</p>
                        </div>
                    )}
                </div>
            </div>
        </Layout>
    )
}
