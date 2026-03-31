// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect, useRef, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDispatch } from 'react-redux'
import { setActiveScan, updateProgress } from '../store'
import { scansAPI } from '../services/api'
import {
    Rocket, Target, Radio, Shield, Zap, Crosshair,
    Loader2, XCircle, Clock, Wifi, Monitor, Lock,
    AlertTriangle, CheckCircle, FileText, ChevronDown,
    ChevronUp, Activity
} from 'lucide-react'
import Layout from '../components/Layout'

const scanTypes = [
    { value: 'quick', label: 'Quick', desc: 'Fast port scan (top 100 ports)', icon: Zap, time: '~2 min' },
    { value: 'stealth', label: 'Stealth', desc: 'SYN scan — less detectable', icon: Shield, time: '~15 min' },
    { value: 'full', label: 'Full', desc: 'All 65535 ports — thorough', icon: Radio, time: '~30 min' },
    { value: 'aggressive', label: 'Aggressive', desc: 'OS, version & script detection', icon: Crosshair, time: '~45 min' },
    { value: 'vulnerability', label: 'Vulnerability', desc: 'Full scan + CVE detection', icon: Target, time: '~60 min' },
]

const TERMINAL_MAX_LINES = 200

// Color mapping for terminal line types
const getTerminalLineClass = (event) => {
    switch (event) {
        case 'host_found':
        case 'scan_started':
        case 'scan_complete':
        case 'connected':
            return 'terminal-line-green'
        case 'port_found':
        case 'progress':
            return 'terminal-line-cyan'
        case 'cve_found':
        case 'error':
            return 'terminal-line-red'
        case 'warning':
            return 'terminal-line-yellow'
        default:
            return 'terminal-line-white'
    }
}

const getRiskBadge = (level) => {
    const map = {
        critical: { color: 'bg-red-500/20 text-red-400 border-red-500/30', icon: '🔴', label: 'CRITICAL' },
        high: { color: 'bg-orange-500/20 text-orange-400 border-orange-500/30', icon: '🟠', label: 'HIGH' },
        medium: { color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30', icon: '🟡', label: 'MEDIUM' },
        low: { color: 'bg-blue-500/20 text-blue-400 border-blue-500/30', icon: '🔵', label: 'LOW' },
        info: { color: 'bg-green-500/20 text-green-400 border-green-500/30', icon: '🟢', label: 'INFO' },
    }
    return map[level] || map.info
}

export default function NewScan() {
    const navigate = useNavigate()
    const dispatch = useDispatch()

    // Form state
    const [target, setTarget] = useState('')
    const [scanType, setScanType] = useState('quick')
    const [launching, setLaunching] = useState(false)
    const [error, setError] = useState('')

    // Scan state
    const [phase, setPhase] = useState('form') // form | scanning | complete
    const [scanInfo, setScanInfo] = useState(null)
    const [progress, setProgress] = useState(0)        // target value (from WS/poll)
    const [animProgress, setAnimProgress] = useState(0) // smoothly animated display value
    const [elapsed, setElapsed] = useState(0)
    const [terminalLines, setTerminalLines] = useState([])
    const [liveHosts, setLiveHosts] = useState([])
    const [expandedHost, setExpandedHost] = useState(null)
    const [stats, setStats] = useState({ hosts: 0, ports: 0, vulns: 0, critical: 0 })
    const [completionData, setCompletionData] = useState(null)
    const [cveFlash, setCveFlash] = useState(false)
    const [scanComplete, setScanComplete] = useState(false)
    const [scanFailed, setScanFailed] = useState(false)

    // Refs
    const wsRef = useRef(null)
    const terminalRef = useRef(null)
    const elapsedRef = useRef(null)
    const pollRef = useRef(null)
    const lineIdRef = useRef(0)
    const reconnectCountRef = useRef(0)
    const scanCompleteRef = useRef(false)   // avoids stale closure in WS handlers
    const MAX_RECONNECT = 3

    // Sanitize: strip protocol, paths, ports from URL-style input
    const sanitizeTarget = (value) => {
        const trimmed = value.trim()
        try {
            const url = new URL(trimmed)
            return url.hostname  // strips https://, http://, path, port
        } catch {
            return trimmed       // not a URL — use as-is
        }
    }

    // Smart context-aware validation error messages
    const validateTarget = (raw) => {
        if (!raw.trim()) return 'Target is required — enter an IP, CIDR range, or domain'
        if (/https?:\/\//i.test(raw)) {
            return 'Remove the https:// prefix — use just the domain e.g. tapidiploma.org'
        }
        const t = sanitizeTarget(raw)
        if (!t) return 'Target is required — enter an IP, CIDR range, or domain'
        if (/[;|&$`\\><"'{}()!]/.test(t)) {
            return 'Invalid target — only use letters, numbers, dots, dashes, and / for CIDR ranges'
        }
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
        // Accept: single-label hostnames (router, myserver) and FQDNs (example.com)
        const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
        if (!ipRegex.test(t) && !cidrRegex.test(t) && !hostnameRegex.test(t)) {
            if (t.includes('/')) return 'Use just the hostname or IP — no paths or slashes e.g. example.com'
            return 'Enter a valid target: IP (10.0.0.1), CIDR (10.0.0.0/24), hostname (router), or domain (example.com)'
        }
        return null
    }

    // Add line to terminal
    const addTerminalLine = useCallback((message, event = 'info') => {
        const time = new Date().toLocaleTimeString('en-IN', { timeZone: 'Asia/Kolkata', hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
        const id = ++lineIdRef.current
        setTerminalLines(prev => {
            const newLines = [...prev, { id, time, message, event }]
            return newLines.length > TERMINAL_MAX_LINES
                ? newLines.slice(newLines.length - TERMINAL_MAX_LINES)
                : newLines
        })
    }, [])

    // Update host in live hosts table
    const updateHost = useCallback((data) => {
        setLiveHosts(prev => {
            const existing = prev.find(h => h.ip === data.ip)
            if (existing) {
                return prev.map(h => h.ip === data.ip ? { ...h, ...data } : h)
            }
            return [...prev, {
                ip: data.ip,
                hostname: data.hostname || '',
                status: data.status || 'up',
                os_name: data.os_name || '',
                ports: [],
                portCount: 0,
                vulnCount: 0,
                riskScore: data.risk_score || 0,
                riskLevel: data.risk_level || 'info',
            }]
        })
    }, [])

    // Add port to a host
    const addPortToHost = useCallback((ip, portData) => {
        setLiveHosts(prev => prev.map(h => {
            if (h.ip === ip) {
                const newPorts = [...(h.ports || []), portData]
                return { ...h, ports: newPorts, portCount: newPorts.length }
            }
            return h
        }))
    }, [])

    // Add vuln to a host
    const addVulnToHost = useCallback((ip) => {
        setLiveHosts(prev => prev.map(h => {
            if (h.ip === ip) {
                const newCount = (h.vulnCount || 0) + 1
                const newRisk = Math.min(100, (h.riskScore || 0) + 20)
                let newLevel = 'info'
                if (newRisk >= 81) newLevel = 'critical'
                else if (newRisk >= 61) newLevel = 'high'
                else if (newRisk >= 41) newLevel = 'medium'
                else if (newRisk >= 21) newLevel = 'low'
                return { ...h, vulnCount: newCount, riskScore: newRisk, riskLevel: newLevel }
            }
            return h
        }))
    }, [])

    // Handle WebSocket messages
    const handleWsMessage = useCallback((data) => {
        switch (data.event) {
            case 'connected':
                addTerminalLine(data.message || '🔗 Live connection established!', 'connected')
                break

            case 'scan_started':
                addTerminalLine(data.message, 'scan_started')
                break

            case 'host_found':
                updateHost(data)
                addTerminalLine(data.message, 'host_found')
                setStats(prev => ({ ...prev, hosts: prev.hosts + 1 }))
                break

            case 'port_found':
                addPortToHost(data.ip, {
                    port: data.port,
                    protocol: data.protocol,
                    service: data.service,
                    product: data.product,
                    version: data.version,
                })
                addTerminalLine(data.message, 'port_found')
                setStats(prev => ({ ...prev, ports: prev.ports + 1 }))
                break

            case 'cve_found':
                addVulnToHost(data.ip)
                addTerminalLine(data.message, 'cve_found')
                setStats(prev => ({
                    ...prev,
                    vulns: prev.vulns + 1,
                    critical: data.severity === 'critical' ? prev.critical + 1 : prev.critical,
                }))
                // CVE red flash
                setCveFlash(true)
                setTimeout(() => setCveFlash(false), 600)
                break

            case 'progress':
                if (data.progress > 0) setProgress(data.progress)
                if (data.message) addTerminalLine(data.message, 'progress')
                break

            case 'scan_complete':
                scanCompleteRef.current = true
                setProgress(100)
                setScanComplete(true)
                addTerminalLine(data.message || '✅ Scan completed!', 'scan_complete')
                setCompletionData({
                    totalHosts: data.total_hosts || 0,
                    totalPorts: data.total_ports || 0,
                    totalVulns: data.total_vulns || 0,
                    criticalCount: data.critical_count || 0,
                    duration: data.duration || 'N/A',
                })
                stopTimer()
                // Close WS with normal code so onclose won't try to reconnect
                if (wsRef.current) {
                    try { wsRef.current.close(1000) } catch (_) {}
                    wsRef.current = null
                }
                setTimeout(() => setPhase('complete'), 1500)
                break

            case 'error':
                scanCompleteRef.current = true
                addTerminalLine(`❌ Scan failed: ${data.message || 'Unknown error'}`, 'error')
                addTerminalLine('💡 TIP: Try Quick scan first, or run VS Code as Administrator for advanced scans', 'warning')
                setScanFailed(true)
                setScanComplete(true)
                setCompletionData(null)
                stopTimer()
                // Close WS with normal code so onclose won't try to reconnect
                if (wsRef.current) {
                    try { wsRef.current.close(1000) } catch (_) {}
                    wsRef.current = null
                }
                setTimeout(() => setPhase('complete'), 1500)
                break

            default:
                if (data.message) addTerminalLine(data.message, 'info')
        }
    }, [addTerminalLine, updateHost, addPortToHost, addVulnToHost])

    // Polling fallback
    const startPolling = useCallback((scanId) => {
        if (pollRef.current) return // already polling

        addTerminalLine('📊 Using polling mode for status updates...', 'info')

        pollRef.current = setInterval(async () => {
            try {
                const res = await scansAPI.status(scanId)
                const data = res.data

                setProgress(data.progress || 0)
                dispatch(updateProgress(data.progress || 0))

                addTerminalLine(
                    `📊 Progress: ${data.progress || 0}% | Status: ${data.status}`,
                    'progress'
                )

                if (data.status === 'completed' || data.status === 'failed') {
                    clearInterval(pollRef.current)
                    pollRef.current = null
                    setScanComplete(true)
                    setProgress(100)
                    stopTimer()

                    if (data.status === 'completed') {
                        addTerminalLine('✅ Scan completed!', 'scan_complete')
                        setCompletionData({
                            totalHosts: data.total_hosts || 0,
                            totalPorts: data.total_ports || 0,
                            totalVulns: data.total_vulns || 0,
                            criticalCount: data.critical_count || 0,
                            duration: 'N/A',
                        })
                    } else if (data.status === 'failed') {
                        addTerminalLine(
                          `❌ Scan failed: ${data.error_message || 'Unknown error'}`, 
                          'error'
                        )
                        addTerminalLine(
                          '💡 TIP: Try Quick scan first, or run VS Code as Administrator for advanced scans',
                          'warning'
                        )
                        setScanFailed(true)
                        setCompletionData(null)
                    }

                    setTimeout(() => setPhase('complete'), 1500)
                }
            } catch (err) {
                // Silently continue polling
            }
        }, 3000) // Poll every 3 seconds
    }, [addTerminalLine, dispatch])

    // Connect WebSocket
    const connectWebSocket = useCallback((scanId) => {
        const token = localStorage.getItem('netrix_token')
        if (!token) {
            addTerminalLine('⚠️ No auth token found, using polling...', 'error')
            startPolling(scanId)
            return
        }

        try {
            // Build proper WebSocket URL through Vite proxy
            const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
            const wsHost = window.location.host
            const wsUrl = `${wsProtocol}//${wsHost}/api/v1/scans/ws/${scanId}?token=${token}`

            const ws = new WebSocket(wsUrl)
            wsRef.current = ws

            ws.onopen = () => {
                reconnectCountRef.current = 0
                addTerminalLine('🔗 Live WebSocket connection established!', 'connected')
            }

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data)
                    handleWsMessage(data)
                } catch (e) {
                    // ignore parse errors
                }
            }

            ws.onerror = (err) => {
                console.error('[Netrix] WebSocket error:', err)
                addTerminalLine('⚠️ Live connection failed, switching to polling...', 'warning')
                // Do NOT call ws.close() here — it triggers onclose with code 1006
                // which would cause unwanted reconnection attempts.
                // The browser will close the socket automatically after an error.
                wsRef.current = null
                startPolling(scanId)
            }

            ws.onclose = (event) => {
                // Use ref instead of state to avoid stale closure
                if (!scanCompleteRef.current && event.code !== 1000) {
                    if (reconnectCountRef.current < MAX_RECONNECT) {
                        reconnectCountRef.current++
                        const attempt = reconnectCountRef.current
                        addTerminalLine(
                            `🔄 Reconnecting WebSocket... (attempt ${attempt}/${MAX_RECONNECT})`,
                            'info'
                        )
                        setTimeout(() => {
                            connectWebSocket(scanId)
                        }, 2000 * attempt) // Exponential backoff
                    } else {
                        addTerminalLine(
                            '⚠️ Max reconnect attempts reached, switching to polling...',
                            'warning'
                        )
                        startPolling(scanId)
                    }
                }
            }
        } catch (err) {
            console.error('[Netrix] WebSocket setup error:', err)
            addTerminalLine('⚠️ WebSocket unavailable, using polling...', 'error')
            startPolling(scanId)
        }
    }, [addTerminalLine, handleWsMessage, startPolling])

    // Timer
    const startTimer = () => {
        elapsedRef.current = setInterval(() => {
            setElapsed(prev => prev + 1)
        }, 1000)
    }

    const stopTimer = () => {
        if (elapsedRef.current) {
            clearInterval(elapsedRef.current)
            elapsedRef.current = null
        }
    }

    const formatElapsed = (sec) => {
        const h = Math.floor(sec / 3600).toString().padStart(2, '0')
        const m = Math.floor((sec % 3600) / 60).toString().padStart(2, '0')
        const s = (sec % 60).toString().padStart(2, '0')
        return h !== '00' ? `${h}:${m}:${s}` : `${m}:${s}`
    }

    // Launch scan
    const handleLaunch = async () => {
        const validationError = validateTarget(target)
        if (validationError) return setError(validationError)

        const cleanTarget = sanitizeTarget(target)
        setTarget(cleanTarget)
        setError('')
        setLaunching(true)
        try {
            const res = await scansAPI.create(cleanTarget, scanType)
            const scan = res.data
            setScanInfo(scan)
            dispatch(setActiveScan(scan))
            setProgress(0)
            setAnimProgress(0)
            setElapsed(0)
            setTerminalLines([])
            setLiveHosts([])
            setStats({ hosts: 0, ports: 0, vulns: 0, critical: 0 })
            setCompletionData(null)
            setScanComplete(false)
            setScanFailed(false)
            scanCompleteRef.current = false
            reconnectCountRef.current = 0
            setPhase('scanning')
            startTimer()

            addTerminalLine(`🚀 Scan ${scan.scan_id} launched against ${target}`, 'scan_started')
            addTerminalLine(`📋 Scan type: ${scanType} | Target: ${target}`, 'info')

            // Connect WebSocket with scan_id
            connectWebSocket(scan.scan_id)
        } catch (err) {
            setError(err.response?.data?.detail || err.response?.data?.message || 'Failed to launch scan')
        } finally {
            setLaunching(false)
        }
    }

    // Cancel scan
    const handleCancel = () => {
        if (wsRef.current) {
            try { wsRef.current.close(1000) } catch (_) { }
            wsRef.current = null
        }
        if (pollRef.current) {
            clearInterval(pollRef.current)
            pollRef.current = null
        }
        stopTimer()
        setScanComplete(true)
        setScanFailed(true)
        setPhase('form')
        setProgress(0)
    }

    // Smooth progress animation — eases animProgress toward progress target
    // so the bar moves fluidly even when multiple events arrive at once.
    useEffect(() => {
        let frameId
        const animate = () => {
            setAnimProgress(prev => {
                const diff = progress - prev
                if (Math.abs(diff) < 0.3) return progress  // close enough, snap
                return prev + diff * 0.08  // ease factor: ~8% of remaining gap per frame
            })
            frameId = requestAnimationFrame(animate)
        }
        frameId = requestAnimationFrame(animate)
        return () => cancelAnimationFrame(frameId)
    }, [progress])

    // Auto-scroll terminal
    useEffect(() => {
        if (terminalRef.current) {
            terminalRef.current.scrollTop = terminalRef.current.scrollHeight
        }
    }, [terminalLines])

    // Cleanup
    useEffect(() => {
        return () => {
            if (wsRef.current) try { wsRef.current.close(1000) } catch (_) { }
            if (pollRef.current) clearInterval(pollRef.current)
            stopTimer()
        }
    }, [])

    // ═══════════════════════════════════════════
    // RENDER: Form Phase
    // ═══════════════════════════════════════════
    if (phase === 'form') {
        return (
            <Layout>
                <div className="max-w-2xl mx-auto animate-fade-in">
                    <div className="mb-6">
                        <h1 className="text-2xl font-bold text-netrix-text flex items-center gap-2">
                            <Rocket className="w-6 h-6 text-netrix-accent" />
                            Launch New Scan
                        </h1>
                        <p className="text-sm text-netrix-muted mt-1">Configure and start a network scan</p>
                    </div>

                    <div className="glass-card p-6 mb-6">
                        {/* Target */}
                        <div className="mb-6">
                            <label className="block text-sm font-medium text-netrix-muted mb-2">Target IP / CIDR / Domain</label>
                            <div className="flex items-center bg-netrix-bg border border-netrix-border rounded-lg focus-within:border-netrix-accent focus-within:ring-1 focus-within:ring-netrix-accent/30 transition-all duration-200">
                                <span className="flex items-center justify-center w-10 shrink-0 text-netrix-muted/50">
                                    <Target className="w-4 h-4" />
                                </span>
                                <input
                                    type="text"
                                    value={target}
                                    onChange={(e) => { setTarget(e.target.value); setError('') }}
                                    onBlur={(e) => { const s = sanitizeTarget(e.target.value); if (s !== e.target.value.trim()) setTarget(s) }}
                                    placeholder="e.g. 192.168.1.1, 10.0.0.0/24, router, or example.com"
                                    className="w-full bg-transparent py-3 pr-4 text-netrix-text placeholder-netrix-muted/50 focus:outline-none font-mono"
                                    autoComplete="off"
                                    onKeyDown={(e) => e.key === 'Enter' && handleLaunch()}
                                />
                            </div>
                            <p className="text-xs text-netrix-muted/60 mt-1.5 ml-1">
                                Enter IP (192.168.1.1), CIDR (192.168.1.0/24), or domain (example.com) — https:// is removed automatically
                            </p>
                        </div>

                        {/* Scan Type */}
                        <div className="mb-6">
                            <label className="block text-sm font-medium text-netrix-muted mb-3">Scan Type</label>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                                {scanTypes.map(({ value, label, desc, icon: Icon, time }) => (
                                    <button
                                        key={value}
                                        onClick={() => setScanType(value)}
                                        className={`
                                            flex items-start gap-3 p-4 rounded-xl border transition-all duration-200 text-left
                                            ${scanType === value
                                                ? 'bg-netrix-accent/10 border-netrix-accent/40 shadow-lg shadow-netrix-accent/5'
                                                : 'bg-netrix-bg/30 border-netrix-border/30 hover:border-netrix-border'
                                            }
                                        `}
                                    >
                                        <div className={`p-2 rounded-lg ${scanType === value ? 'bg-netrix-accent/20' : 'bg-netrix-bg/50'}`}>
                                            <Icon className={`w-4 h-4 ${scanType === value ? 'text-netrix-accent' : 'text-netrix-muted'}`} />
                                        </div>
                                        <div className="flex-1">
                                            <div className="flex items-center justify-between">
                                                <p className={`text-sm font-semibold ${scanType === value ? 'text-netrix-accent' : 'text-netrix-text'}`}>
                                                    {label}
                                                </p>
                                                <span className="text-[10px] font-mono text-netrix-muted bg-netrix-bg/60 px-1.5 py-0.5 rounded">
                                                    {time}
                                                </span>
                                            </div>
                                            <p className="text-xs text-netrix-muted mt-0.5">{desc}</p>
                                        </div>
                                    </button>
                                ))}
                            </div>
                        </div>

                        {error && (
                            <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center gap-2">
                                <XCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
                                <p className="text-sm text-red-400">{error}</p>
                            </div>
                        )}

                        {/* Launch Button */}
                        <button
                            onClick={handleLaunch}
                            disabled={launching}
                            className="w-full btn-primary flex items-center justify-center gap-2 py-4 text-base font-bold tracking-wide"
                        >
                            {launching ? (
                                <>
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                    Launching...
                                </>
                            ) : (
                                <>
                                    <Rocket className="w-5 h-5" />
                                    🚀 START SCAN
                                </>
                            )}
                        </button>
                    </div>
                </div>
            </Layout>
        )
    }

    // ═══════════════════════════════════════════
    // RENDER: Complete Phase
    // ═══════════════════════════════════════════
    if (phase === 'complete') {
        const cd = completionData
        const isError = scanFailed || !cd
        return (
            <Layout>
                <div className="max-w-2xl mx-auto animate-fade-in">
                    <div className="glass-card p-8">
                        {/* Header */}
                        <div className="text-center mb-8">
                            {isError ? (
                                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-red-500/20 mb-4">
                                    <XCircle className="w-8 h-8 text-red-400" />
                                </div>
                            ) : (
                                <div className="inline-flex items-center justify-center w-16 h-16 rounded-full bg-green-500/20 mb-4 scan-complete-pulse">
                                    <CheckCircle className="w-8 h-8 text-green-400" />
                                </div>
                            )}
                            <h2 className="text-2xl font-bold text-netrix-text">
                                {isError ? '❌ Scan Failed' : '✅ Scan Complete!'}
                            </h2>
                            <p className="text-sm text-netrix-muted mt-1">
                                {isError ? 'An error occurred during scanning' : `Target: ${target} • ${scanInfo?.scan_type || scanType} scan`}
                            </p>
                        </div>

                        {/* Stats Cards */}
                        {!isError && cd && (
                            <>
                                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
                                    <StatCard icon={Monitor} label="Hosts" value={cd.totalHosts} color="text-cyan-400" />
                                    <StatCard icon={Lock} label="Ports" value={cd.totalPorts} color="text-blue-400" />
                                    <StatCard icon={AlertTriangle} label="Vulns" value={cd.totalVulns} color="text-yellow-400" />
                                    <StatCard icon={AlertTriangle} label="Critical" value={cd.criticalCount} color="text-red-400" />
                                </div>

                                <div className="flex items-center justify-center gap-2 text-sm text-netrix-muted mb-6">
                                    <Clock className="w-4 h-4" />
                                    <span>Duration: <span className="text-netrix-text font-mono">{cd.duration}</span></span>
                                </div>
                            </>
                        )}

                        {/* Actions */}
                        <div className="flex gap-3">
                            {!isError && (
                                <button
                                    onClick={() => navigate(`/scan/${scanInfo?.id}`)}
                                    className="flex-1 btn-primary flex items-center justify-center gap-2 py-3"
                                >
                                    <Activity className="w-4 h-4" />
                                    View Full Results
                                </button>
                            )}
                            <button
                                onClick={() => {
                                    setPhase('form')
                                    setTarget('')
                                    setScanInfo(null)
                                    setProgress(0)
                                    setElapsed(0)
                                    setScanComplete(false)
                                    setScanFailed(false)
                                }}
                                className={`${isError ? 'flex-1' : ''} btn-secondary flex items-center justify-center gap-2 py-3`}
                            >
                                <Rocket className="w-4 h-4" />
                                New Scan
                            </button>
                        </div>
                    </div>
                </div>
            </Layout>
        )
    }

    // ═══════════════════════════════════════════
    // RENDER: Scanning Phase (LIVE)
    // ═══════════════════════════════════════════
    return (
        <Layout>
            <div className={`max-w-4xl mx-auto animate-fade-in ${cveFlash ? 'cve-flash' : ''}`}>
                {/* Header — LIVE badge */}
                <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                        <div className="live-badge">
                            <span className="live-dot" />
                            <span className="text-xs font-bold text-red-400 uppercase tracking-widest">Live</span>
                        </div>
                        <div>
                            <h1 className="text-lg font-bold text-netrix-text">
                                Scanning: <span className="font-mono text-netrix-accent">{target}</span>
                            </h1>
                            <p className="text-xs text-netrix-muted">
                                {scanTypes.find(s => s.value === scanType)?.label} Scan
                                {scanInfo && ` • ${scanInfo.scan_id}`}
                            </p>
                        </div>
                    </div>
                    <div className="flex items-center gap-2 text-sm text-netrix-muted">
                        <Clock className="w-4 h-4" />
                        <span className="font-mono text-netrix-text">{formatElapsed(elapsed)}</span>
                    </div>
                </div>

                {/* Progress Bar */}
                <div className="glass-card p-4 mb-4">
                    <div className="flex items-center justify-between text-sm mb-2">
                        <span className="text-netrix-muted">Progress</span>
                        <span className="font-mono text-netrix-accent font-bold text-lg">{Math.round(animProgress)}%</span>
                    </div>
                    <div className="progress-bar h-4">
                        <div
                            className="progress-bar-fill"
                            style={{ width: `${animProgress}%` }}
                        />
                    </div>
                </div>

                {/* Stats Row */}
                <div className="grid grid-cols-3 gap-3 mb-4">
                    <div className="glass-card p-3 text-center">
                        <Monitor className="w-5 h-5 text-cyan-400 mx-auto mb-1" />
                        <div className="text-xl font-bold text-netrix-text font-mono counter-animate">{stats.hosts}</div>
                        <div className="text-xs text-netrix-muted">Hosts</div>
                    </div>
                    <div className="glass-card p-3 text-center">
                        <Lock className="w-5 h-5 text-blue-400 mx-auto mb-1" />
                        <div className="text-xl font-bold text-netrix-text font-mono counter-animate">{stats.ports}</div>
                        <div className="text-xs text-netrix-muted">Ports</div>
                    </div>
                    <div className="glass-card p-3 text-center">
                        <AlertTriangle className="w-5 h-5 text-yellow-400 mx-auto mb-1" />
                        <div className="text-xl font-bold text-netrix-text font-mono counter-animate">{stats.vulns}</div>
                        <div className="text-xs text-netrix-muted">Vulns</div>
                    </div>
                </div>

                {/* Terminal */}
                <div className="glass-card mb-4 overflow-hidden">
                    <div className="flex items-center justify-between px-4 py-2 border-b border-netrix-border/30 bg-[#050505]">
                        <div className="flex items-center gap-2">
                            <div className="flex gap-1.5">
                                <span className="w-2.5 h-2.5 rounded-full bg-red-500/80" />
                                <span className="w-2.5 h-2.5 rounded-full bg-yellow-500/80" />
                                <span className="w-2.5 h-2.5 rounded-full bg-green-500/80" />
                            </div>
                            <span className="text-[10px] text-netrix-muted font-mono ml-2">LIVE TERMINAL OUTPUT</span>
                        </div>
                        <Activity className="w-3 h-3 text-green-400 animate-pulse" />
                    </div>
                    <div
                        ref={terminalRef}
                        className="terminal-body"
                    >
                        {terminalLines.map((line) => (
                            <div
                                key={line.id}
                                className={`terminal-line ${getTerminalLineClass(line.event)}`}
                            >
                                <span className="terminal-time">[{line.time}]</span>
                                <span className="terminal-msg">{line.message}</span>
                            </div>
                        ))}
                        <div className="terminal-cursor">
                            <span className="cursor-blink">▌</span>
                        </div>
                    </div>
                </div>

                {/* Discovered Hosts Table */}
                {liveHosts.length > 0 && (
                    <div className="glass-card mb-4 overflow-hidden">
                        <div className="px-4 py-3 border-b border-netrix-border/30">
                            <h3 className="text-sm font-semibold text-netrix-text flex items-center gap-2">
                                <Monitor className="w-4 h-4 text-netrix-accent" />
                                Discovered Hosts ({liveHosts.length})
                            </h3>
                        </div>
                        <div className="divide-y divide-netrix-border/20">
                            {liveHosts.map((host, idx) => {
                                const badge = getRiskBadge(host.riskLevel)
                                const isExpanded = expandedHost === host.ip
                                return (
                                    <div key={host.ip} className="host-row animate-host-in" style={{ animationDelay: `${idx * 100}ms` }}>
                                        <button
                                            onClick={() => setExpandedHost(isExpanded ? null : host.ip)}
                                            className="w-full px-4 py-3 flex items-center gap-4 hover:bg-netrix-accent/5 transition-colors"
                                        >
                                            <div className="flex-1 text-left">
                                                <span className="font-mono text-sm text-netrix-text">{host.ip}</span>
                                                {host.hostname && (
                                                    <span className="text-xs text-netrix-muted ml-2">({host.hostname})</span>
                                                )}
                                            </div>
                                            <div className="text-xs text-netrix-muted font-mono">
                                                {host.portCount} port{host.portCount !== 1 ? 's' : ''}
                                            </div>
                                            {host.vulnCount > 0 && (
                                                <div className="text-xs text-yellow-400 font-mono">
                                                    {host.vulnCount} vuln{host.vulnCount !== 1 ? 's' : ''}
                                                </div>
                                            )}
                                            <div className={`text-[10px] font-bold px-2 py-0.5 rounded border ${badge.color}`}>
                                                {badge.icon} {badge.label}
                                            </div>
                                            {isExpanded ? <ChevronUp className="w-4 h-4 text-netrix-muted" /> : <ChevronDown className="w-4 h-4 text-netrix-muted" />}
                                        </button>
                                        {isExpanded && host.ports && host.ports.length > 0 && (
                                            <div className="px-4 pb-3 animate-fade-in">
                                                <table className="w-full text-xs">
                                                    <thead>
                                                        <tr className="text-netrix-muted">
                                                            <th className="text-left py-1 px-2">Port</th>
                                                            <th className="text-left py-1 px-2">Protocol</th>
                                                            <th className="text-left py-1 px-2">Service</th>
                                                            <th className="text-left py-1 px-2">Product</th>
                                                        </tr>
                                                    </thead>
                                                    <tbody>
                                                        {host.ports.map((p, i) => (
                                                            <tr key={i} className="text-netrix-text border-t border-netrix-border/10">
                                                                <td className="py-1 px-2 font-mono text-cyan-400">{p.port}</td>
                                                                <td className="py-1 px-2">{p.protocol}</td>
                                                                <td className="py-1 px-2">{p.service}</td>
                                                                <td className="py-1 px-2 text-netrix-muted">{p.product} {p.version}</td>
                                                            </tr>
                                                        ))}
                                                    </tbody>
                                                </table>
                                            </div>
                                        )}
                                    </div>
                                )
                            })}
                        </div>
                    </div>
                )}

                {/* Cancel Button */}
                <button
                    onClick={handleCancel}
                    className="w-full btn-danger flex items-center justify-center gap-2 py-3"
                >
                    <XCircle className="w-4 h-4" />
                    Cancel Scan
                </button>
            </div>
        </Layout>
    )
}

// ═══════════════════════════════════════════
// Stat Card Component (for completion screen)
// ═══════════════════════════════════════════
function StatCard({ icon: Icon, label, value, color }) {
    return (
        <div className="glass-card p-4 text-center">
            <Icon className={`w-5 h-5 ${color} mx-auto mb-2`} />
            <div className="text-2xl font-bold text-netrix-text font-mono counter-animate">{value}</div>
            <div className="text-xs text-netrix-muted mt-1">{label}</div>
        </div>
    )
}
