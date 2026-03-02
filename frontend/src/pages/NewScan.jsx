import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDispatch } from 'react-redux'
import { setActiveScan, updateProgress } from '../store'
import { scansAPI } from '../services/api'
import {
    Rocket, Target, Radio, Shield, Zap,
    Crosshair, Loader2, XCircle, Clock, Wifi
} from 'lucide-react'
import Layout from '../components/Layout'

const scanTypes = [
    { value: 'quick', label: 'Quick', desc: 'Fast port scan (top 100 ports)', icon: Zap },
    { value: 'stealth', label: 'Stealth', desc: 'SYN scan — less detectable', icon: Shield },
    { value: 'full', label: 'Full', desc: 'All 65535 ports — thorough', icon: Radio },
    { value: 'aggressive', label: 'Aggressive', desc: 'OS, version & script detection', icon: Crosshair },
    { value: 'vulnerability', label: 'Vulnerability', desc: 'Full scan + CVE detection', icon: Target },
]

export default function NewScan() {
    const navigate = useNavigate()
    const dispatch = useDispatch()
    const pollRef = useRef(null)

    const [target, setTarget] = useState('')
    const [scanType, setScanType] = useState('quick')
    const [launching, setLaunching] = useState(false)
    const [error, setError] = useState('')
    const [activeScanId, setActiveScanId] = useState(null)
    const [progress, setProgress] = useState(0)
    const [statusText, setStatusText] = useState('')
    const [elapsed, setElapsed] = useState(0)
    const [scanInfo, setScanInfo] = useState(null)
    const elapsedRef = useRef(null)

    const validateTarget = (t) => {
        if (!t.trim()) return 'Target is required'
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
        const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
        const cidrRegex = /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/
        if (!ipRegex.test(t) && !domainRegex.test(t) && !cidrRegex.test(t)) {
            return 'Enter a valid IP, CIDR, or domain'
        }
        return null
    }

    const handleLaunch = async () => {
        const validationError = validateTarget(target)
        if (validationError) return setError(validationError)

        setError('')
        setLaunching(true)
        try {
            const res = await scansAPI.create(target, scanType)
            const scan = res.data
            setActiveScanId(scan.id)
            setScanInfo(scan)
            dispatch(setActiveScan(scan))
            setProgress(0)
            setStatusText('Initializing scan...')
            setElapsed(0)
            startPolling(scan.id)
            startTimer()
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to launch scan')
        } finally {
            setLaunching(false)
        }
    }

    const startPolling = (scanId) => {
        pollRef.current = setInterval(async () => {
            try {
                const res = await scansAPI.status(scanId)
                const data = res.data
                const pct = data.progress ?? 0
                setProgress(pct)
                dispatch(updateProgress(pct))
                setStatusText(data.status_text || data.status || 'Scanning...')

                if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
                    stopPolling()
                    stopTimer()
                    if (data.status === 'completed') {
                        setTimeout(() => navigate(`/scan/${scanId}`), 1000)
                    }
                }
            } catch {
                /* continue polling */
            }
        }, 3000)
    }

    const stopPolling = () => {
        if (pollRef.current) {
            clearInterval(pollRef.current)
            pollRef.current = null
        }
    }

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
        const m = Math.floor(sec / 60).toString().padStart(2, '0')
        const s = (sec % 60).toString().padStart(2, '0')
        return `${m}:${s}`
    }

    useEffect(() => {
        return () => {
            stopPolling()
            stopTimer()
        }
    }, [])

    const isScanning = !!activeScanId

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
                        <div className="relative">
                            <Target className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-netrix-muted/50" />
                            <input
                                type="text"
                                value={target}
                                onChange={(e) => setTarget(e.target.value)}
                                placeholder="e.g. 192.168.1.0/24 or example.com"
                                className="input-dark pl-10 font-mono"
                                disabled={isScanning}
                            />
                        </div>
                    </div>

                    {/* Scan Type */}
                    <div className="mb-6">
                        <label className="block text-sm font-medium text-netrix-muted mb-3">Scan Type</label>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                            {scanTypes.map(({ value, label, desc, icon: Icon }) => (
                                <button
                                    key={value}
                                    onClick={() => !isScanning && setScanType(value)}
                                    disabled={isScanning}
                                    className={`
                    flex items-start gap-3 p-4 rounded-xl border transition-all duration-200 text-left
                    ${scanType === value
                                            ? 'bg-netrix-accent/10 border-netrix-accent/40 shadow-lg shadow-netrix-accent/5'
                                            : 'bg-netrix-bg/30 border-netrix-border/30 hover:border-netrix-border'
                                        }
                    ${isScanning ? 'opacity-50 cursor-not-allowed' : 'cursor-pointer'}
                  `}
                                >
                                    <div className={`p-2 rounded-lg ${scanType === value ? 'bg-netrix-accent/20' : 'bg-netrix-bg/50'}`}>
                                        <Icon className={`w-4 h-4 ${scanType === value ? 'text-netrix-accent' : 'text-netrix-muted'}`} />
                                    </div>
                                    <div>
                                        <p className={`text-sm font-semibold ${scanType === value ? 'text-netrix-accent' : 'text-netrix-text'}`}>
                                            {label}
                                        </p>
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
                    {!isScanning && (
                        <button
                            onClick={handleLaunch}
                            disabled={launching}
                            className="w-full btn-primary flex items-center justify-center gap-2 py-4 text-base"
                        >
                            {launching ? (
                                <>
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                    Launching...
                                </>
                            ) : (
                                <>
                                    <Rocket className="w-5 h-5" />
                                    START SCAN
                                </>
                            )}
                        </button>
                    )}
                </div>

                {/* Live Progress */}
                {isScanning && (
                    <div className="glass-card p-6 glow-cyan scan-line-effect animate-slide-up">
                        <h2 className="text-lg font-semibold text-netrix-text mb-4 flex items-center gap-2">
                            <Wifi className="w-5 h-5 text-netrix-accent animate-pulse" />
                            Live Scan Progress
                        </h2>

                        {/* Progress Bar */}
                        <div className="mb-4">
                            <div className="flex items-center justify-between text-sm mb-2">
                                <span className="text-netrix-muted">{statusText}</span>
                                <span className="font-mono text-netrix-accent font-semibold">{Math.round(progress)}%</span>
                            </div>
                            <div className="progress-bar">
                                <div
                                    className="progress-bar-fill"
                                    style={{ width: `${progress}%` }}
                                />
                            </div>
                        </div>

                        {/* Scan Info */}
                        <div className="grid grid-cols-2 gap-4 mt-4">
                            <div className="flex items-center gap-2 text-sm text-netrix-muted">
                                <Clock className="w-4 h-4" />
                                <span>Elapsed: <span className="font-mono text-netrix-text">{formatElapsed(elapsed)}</span></span>
                            </div>
                            <div className="flex items-center gap-2 text-sm text-netrix-muted">
                                <Target className="w-4 h-4" />
                                <span>Target: <span className="font-mono text-netrix-text">{target}</span></span>
                            </div>
                        </div>

                        {/* Cancel */}
                        <button
                            onClick={() => {
                                stopPolling()
                                stopTimer()
                                setActiveScanId(null)
                                setProgress(0)
                            }}
                            className="mt-4 btn-danger w-full flex items-center justify-center gap-2"
                        >
                            <XCircle className="w-4 h-4" />
                            Cancel
                        </button>
                    </div>
                )}
            </div>
        </Layout>
    )
}
