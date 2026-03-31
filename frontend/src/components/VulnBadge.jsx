// © 2026 @DevAjudiya. All rights reserved.
const severityConfig = {
    critical: {
        bg: 'bg-severity-critical/15',
        border: 'border-severity-critical/40',
        text: 'text-severity-critical',
        dot: 'bg-severity-critical',
        label: 'CRITICAL'
    },
    high: {
        bg: 'bg-severity-high/15',
        border: 'border-severity-high/40',
        text: 'text-severity-high',
        dot: 'bg-severity-high',
        label: 'HIGH'
    },
    medium: {
        bg: 'bg-severity-medium/15',
        border: 'border-severity-medium/40',
        text: 'text-severity-medium',
        dot: 'bg-severity-medium',
        label: 'MEDIUM'
    },
    low: {
        bg: 'bg-severity-low/15',
        border: 'border-severity-low/40',
        text: 'text-severity-low',
        dot: 'bg-severity-low',
        label: 'LOW'
    },
    info: {
        bg: 'bg-severity-info/15',
        border: 'border-severity-info/40',
        text: 'text-severity-info',
        dot: 'bg-severity-info',
        label: 'INFO'
    }
}

export default function VulnBadge({ severity, showDot = true, size = 'sm' }) {
    const config = severityConfig[severity?.toLowerCase()] || severityConfig.info
    const padding = size === 'sm' ? 'px-2.5 py-0.5 text-xs' : 'px-3 py-1 text-sm'

    return (
        <span className={`inline-flex items-center gap-1.5 ${padding} font-semibold rounded-full border ${config.bg} ${config.border} ${config.text}`}>
            {showDot && (
                <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />
            )}
            {config.label}
        </span>
    )
}
