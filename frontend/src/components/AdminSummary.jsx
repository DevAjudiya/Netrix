import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { adminAPI } from '../services/api'
import {
    Users, Scan, ShieldCheck, Ban,
    ArrowRight, Shield
} from 'lucide-react'

function QuickCard({ icon: Icon, label, value, to, accent }) {
    const navigate = useNavigate()
    const colors = {
        cyan: 'border-netrix-accent/20 from-netrix-accent/5 text-netrix-accent',
        purple: 'border-purple-500/20 from-purple-500/5 text-purple-400',
        emerald: 'border-emerald-500/20 from-emerald-500/5 text-emerald-400',
        red: 'border-red-500/20 from-red-500/5 text-red-400',
    }
    const cls = colors[accent] || colors.cyan

    return (
        <button
            onClick={() => navigate(to)}
            className={`
                flex flex-col gap-2 p-4 rounded-xl border bg-gradient-to-br to-transparent
                hover:opacity-90 transition-all duration-200 text-left w-full group
                ${cls}
            `}
        >
            <div className="flex items-center justify-between">
                <Icon className={`w-4 h-4 ${cls.split(' ')[2]}`} />
                <ArrowRight className="w-3.5 h-3.5 opacity-0 group-hover:opacity-60 transition-opacity" />
            </div>
            <div className={`text-2xl font-bold ${cls.split(' ')[2]}`}>
                {value ?? '—'}
            </div>
            <p className="text-xs text-netrix-muted">{label}</p>
        </button>
    )
}

export default function AdminSummary() {
    const [stats, setStats] = useState(null)

    useEffect(() => {
        adminAPI.stats().then(r => setStats(r.data)).catch(() => {})
    }, [])

    return (
        <div className="glass-card p-5 mt-6">
            <div className="flex items-center gap-2 mb-4">
                <Shield className="w-4 h-4 text-purple-400" />
                <h2 className="text-sm font-semibold text-netrix-text">Admin Overview</h2>
                <span className="ml-auto text-[10px] px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 font-medium uppercase tracking-wide border border-purple-500/20">
                    Admin
                </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <QuickCard
                    icon={Users}
                    label="Total Users"
                    value={stats?.total_users}
                    to="/admin/users"
                    accent="cyan"
                />
                <QuickCard
                    icon={Scan}
                    label="All-User Scans"
                    value={stats?.total_scans_all_users}
                    to="/admin/scans"
                    accent="purple"
                />
                <QuickCard
                    icon={ShieldCheck}
                    label="CVEs in DB"
                    value={stats?.cve_count?.toLocaleString?.()}
                    to="/admin/cve"
                    accent="emerald"
                />
                <QuickCard
                    icon={Ban}
                    label="Banned Users"
                    value={stats?.banned_users}
                    to="/admin/users"
                    accent="red"
                />
            </div>
        </div>
    )
}
