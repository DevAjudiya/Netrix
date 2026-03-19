import { useNavigate } from 'react-router-dom'
import { Clock, Target, Wifi, AlertTriangle } from 'lucide-react'
import VulnBadge from './VulnBadge'
import { formatDateIST } from '../utils/formatDate'

const statusConfig = {
    completed: { color: 'text-green-400', bg: 'bg-green-400/10', label: 'Completed' },
    running: { color: 'text-cyan-400', bg: 'bg-cyan-400/10', label: 'Running' },
    pending: { color: 'text-yellow-400', bg: 'bg-yellow-400/10', label: 'Pending' },
    failed: { color: 'text-red-400', bg: 'bg-red-400/10', label: 'Failed' },
    cancelled: { color: 'text-gray-400', bg: 'bg-gray-400/10', label: 'Cancelled' }
}

export default function ScanCard({ scan }) {
    const navigate = useNavigate()
    const status = statusConfig[scan.status] || statusConfig.pending

    const formatDate = formatDateIST

    return (
        <div
            onClick={() => navigate(`/scan/${scan.id}`)}
            className="glass-card-hover p-5 cursor-pointer group"
        >
            <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-2">
                    <div className="p-2 rounded-lg bg-netrix-accent/10">
                        <Target className="w-4 h-4 text-netrix-accent" />
                    </div>
                    <div>
                        <h3 className="text-sm font-semibold text-netrix-text group-hover:text-netrix-accent transition-colors">
                            {scan.scan_id || `Scan #${scan.id}`}
                        </h3>
                        <p className="text-xs text-netrix-muted">{scan.target}</p>
                    </div>
                </div>
                <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium ${status.bg} ${status.color}`}>
                    {scan.status === 'running' && (
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
                    )}
                    {status.label}
                </span>
            </div>

            <div className="grid grid-cols-3 gap-3 mt-4">
                <div className="flex items-center gap-1.5 text-xs text-netrix-muted">
                    <Wifi className="w-3.5 h-3.5" />
                    <span>{scan.scan_type || 'quick'}</span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-netrix-muted">
                    <Clock className="w-3.5 h-3.5" />
                    <span>{formatDate(scan.created_at)}</span>
                </div>
                {scan.risk_level && (
                    <div className="flex items-center gap-1.5 text-xs">
                        <AlertTriangle className="w-3.5 h-3.5 text-netrix-muted" />
                        <VulnBadge severity={scan.risk_level} showDot={false} size="sm" />
                    </div>
                )}
            </div>
        </div>
    )
}
