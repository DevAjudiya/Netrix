import { useState } from 'react'
import { useSelector, useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import { logout } from '../store'
import { User, Shield, Bell, Key, LogOut, Save } from 'lucide-react'
import Layout from '../components/Layout'

export default function Settings() {
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const { user } = useSelector(s => s.auth)
    const [saved, setSaved] = useState(false)

    const handleSave = () => {
        setSaved(true)
        setTimeout(() => setSaved(false), 2000)
    }

    const handleLogout = () => {
        dispatch(logout())
        navigate('/login')
    }

    return (
        <Layout>
            <div className="animate-fade-in max-w-2xl">
                {/* Header */}
                <div className="mb-6">
                    <h1 className="text-2xl font-bold text-netrix-text">Settings</h1>
                    <p className="text-sm text-netrix-muted mt-0.5">Manage your account and preferences</p>
                </div>

                {/* Profile Card */}
                <div className="glass-card p-6 mb-4">
                    <h2 className="text-lg font-semibold text-netrix-text flex items-center gap-2 mb-4">
                        <User className="w-5 h-5 text-netrix-accent" />
                        Profile
                    </h2>
                    <div className="space-y-4">
                        <div>
                            <label className="block text-xs text-netrix-muted mb-1">Username</label>
                            <div className="px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-netrix-text text-sm">
                                {user?.username || '—'}
                            </div>
                        </div>
                        <div>
                            <label className="block text-xs text-netrix-muted mb-1">Email</label>
                            <div className="px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-netrix-text text-sm">
                                {user?.email || '—'}
                            </div>
                        </div>
                        <div>
                            <label className="block text-xs text-netrix-muted mb-1">Role</label>
                            <div className="px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-sm">
                                <span className="text-cyan-400 font-medium">{user?.role || 'Administrator'}</span>
                            </div>
                        </div>
                    </div>
                </div>

                {/* Security Card */}
                <div className="glass-card p-6 mb-4">
                    <h2 className="text-lg font-semibold text-netrix-text flex items-center gap-2 mb-4">
                        <Shield className="w-5 h-5 text-netrix-accent" />
                        Security
                    </h2>
                    <div className="space-y-3">
                        <div className="flex items-center justify-between py-2 border-b border-netrix-border">
                            <div className="flex items-center gap-2 text-sm text-netrix-text">
                                <Key className="w-4 h-4 text-netrix-muted" />
                                JWT Authentication
                            </div>
                            <span className="text-xs text-green-400 bg-green-400/10 px-2 py-0.5 rounded-full">Active</span>
                        </div>
                        <div className="flex items-center justify-between py-2 border-b border-netrix-border">
                            <div className="flex items-center gap-2 text-sm text-netrix-text">
                                <Bell className="w-4 h-4 text-netrix-muted" />
                                Rate Limiting
                            </div>
                            <span className="text-xs text-green-400 bg-green-400/10 px-2 py-0.5 rounded-full">Enabled</span>
                        </div>
                        <div className="flex items-center justify-between py-2">
                            <div className="flex items-center gap-2 text-sm text-netrix-text">
                                <Shield className="w-4 h-4 text-netrix-muted" />
                                Session Token
                            </div>
                            <span className="text-xs text-netrix-muted font-mono">
                                {localStorage.getItem('netrix_token')?.slice(0, 20)}…
                            </span>
                        </div>
                    </div>
                </div>

                {/* Actions */}
                <div className="flex items-center justify-between gap-3">
                    <button
                        onClick={handleLogout}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg text-red-400 border border-red-400/30 hover:bg-red-400/10 text-sm transition-colors"
                    >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                    </button>
                    <button
                        onClick={handleSave}
                        className="btn-primary flex items-center gap-2"
                    >
                        <Save className="w-4 h-4" />
                        {saved ? 'Saved!' : 'Save Changes'}
                    </button>
                </div>
            </div>
        </Layout>
    )
}
