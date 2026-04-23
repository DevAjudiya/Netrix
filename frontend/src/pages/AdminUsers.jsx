// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect, useCallback } from 'react'
import {
    Users, UserCheck, UserX, Shield, BarChart2,
    Search, ChevronLeft, ChevronRight, Edit2,
    Ban, Trash2, KeyRound, X, Check, AlertTriangle,
    RefreshCw, Copy, ShieldPlus, ShieldMinus, UserPlus, Eye, EyeOff
} from 'lucide-react'
import Layout from '../components/Layout'
import { adminAPI } from '../services/api'
import { formatDateIST } from '../utils/formatDate'

// ── Stat Card ─────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color, shadow }) {
    return (
        <div className={`bg-netrix-card border border-netrix-border/50 rounded-xl p-5 flex items-center gap-4 shadow-lg ${shadow}`}>
            <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center flex-shrink-0`}>
                <Icon className="w-6 h-6 text-white" />
            </div>
            <div>
                <p className="text-netrix-muted text-sm">{label}</p>
                <p className="text-netrix-text text-2xl font-bold">{value ?? '—'}</p>
            </div>
        </div>
    )
}

// ── Role Badge ────────────────────────────────────────────────────────────

function RoleBadge({ role }) {
    return role === 'admin'
        ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-purple-500/15 text-purple-400 border border-purple-500/30"><Shield className="w-3 h-3" />Admin</span>
        : <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-blue-500/15 text-blue-400 border border-blue-500/30"><BarChart2 className="w-3 h-3" />Analyst</span>
}

// ── Status Badge ──────────────────────────────────────────────────────────

function StatusBadge({ isActive, isBanned }) {
    if (isBanned)
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30">Banned</span>
    if (!isActive)
        return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-gray-500/15 text-gray-400 border border-gray-500/30">Inactive</span>
    return <span className="px-2 py-0.5 rounded text-xs font-semibold bg-green-500/15 text-green-400 border border-green-500/30">Active</span>
}

// ── Edit Modal ─────────────────────────────────────────────────────────────

function EditModal({ user, onClose, onSaved }) {
    const [role, setRole] = useState(user.role)
    const [isActive, setIsActive] = useState(user.is_active)
    const [isBanned, setIsBanned] = useState(user.is_banned)
    const [banReason, setBanReason] = useState(user.ban_reason || '')
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')

    const handleSave = async () => {
        setSaving(true)
        setError('')
        try {
            const payload = { role, is_active: isActive, is_banned: isBanned }
            if (isBanned) payload.ban_reason = banReason.trim() || null
            else payload.ban_reason = null
            await adminAPI.updateUser(user.id, payload)
            onSaved()
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to update user.')
        } finally {
            setSaving(false)
        }
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-netrix-card border border-netrix-border rounded-2xl w-full max-w-md shadow-2xl">
                <div className="flex items-center justify-between p-5 border-b border-netrix-border/50">
                    <h2 className="text-netrix-text font-semibold text-lg">Edit User — {user.username}</h2>
                    <button onClick={onClose} className="text-netrix-muted hover:text-netrix-text transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                <div className="p-5 space-y-4">
                    {/* Role */}
                    <div>
                        <label className="block text-sm text-netrix-muted mb-1.5">Role</label>
                        <select
                            value={role}
                            onChange={e => setRole(e.target.value)}
                            className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-netrix-text text-sm focus:outline-none focus:border-netrix-accent"
                        >
                            <option value="analyst">Analyst</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>

                    {/* Active toggle */}
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-netrix-muted">Account Active</span>
                        <button
                            type="button"
                            onClick={() => setIsActive(v => !v)}
                            className={`relative inline-flex items-center h-5 w-10 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none ${isActive ? 'bg-netrix-accent' : 'bg-netrix-border'}`}
                        >
                            <span className={`inline-block h-4 w-4 rounded-full bg-white shadow ring-0 transition-transform duration-200 ${isActive ? 'translate-x-5' : 'translate-x-0'}`} />
                        </button>
                    </div>

                    {/* Ban toggle */}
                    <div className="flex items-center justify-between">
                        <span className="text-sm text-netrix-muted">Banned</span>
                        <button
                            type="button"
                            onClick={() => setIsBanned(v => !v)}
                            className={`relative inline-flex items-center h-5 w-10 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none ${isBanned ? 'bg-red-500' : 'bg-netrix-border'}`}
                        >
                            <span className={`inline-block h-4 w-4 rounded-full bg-white shadow ring-0 transition-transform duration-200 ${isBanned ? 'translate-x-5' : 'translate-x-0'}`} />
                        </button>
                    </div>

                    {/* Ban reason (conditional) */}
                    {isBanned && (
                        <div>
                            <label className="block text-sm text-netrix-muted mb-1.5">Ban Reason</label>
                            <textarea
                                value={banReason}
                                onChange={e => setBanReason(e.target.value)}
                                rows={3}
                                maxLength={500}
                                placeholder="Reason for ban (optional but recommended)"
                                className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-netrix-text text-sm focus:outline-none focus:border-red-500 resize-none"
                            />
                            <p className="text-xs text-netrix-muted mt-1 text-right">{banReason.length}/500</p>
                        </div>
                    )}

                    {error && (
                        <p className="text-red-400 text-sm flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}
                        </p>
                    )}
                </div>

                <div className="flex gap-3 p-5 border-t border-netrix-border/50">
                    <button
                        onClick={onClose}
                        className="flex-1 px-4 py-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text hover:border-netrix-accent/50 transition-all text-sm"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleSave}
                        disabled={saving}
                        className="flex-1 px-4 py-2 rounded-lg bg-netrix-accent text-white font-medium hover:bg-netrix-accent/90 transition-all text-sm disabled:opacity-50 flex items-center justify-center gap-2"
                    >
                        {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
                        {saving ? 'Saving…' : 'Save Changes'}
                    </button>
                </div>
            </div>
        </div>
    )
}

// ── Password Reset Modal ───────────────────────────────────────────────────

function PasswordResetModal({ username, tempPassword, onClose }) {
    const [copied, setCopied] = useState(false)

    const copyToClipboard = () => {
        navigator.clipboard.writeText(tempPassword)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-netrix-card border border-netrix-border rounded-2xl w-full max-w-md shadow-2xl">
                <div className="p-5 border-b border-netrix-border/50 flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-amber-500/15 flex items-center justify-center">
                        <KeyRound className="w-5 h-5 text-amber-400" />
                    </div>
                    <div>
                        <h2 className="text-netrix-text font-semibold">Password Reset</h2>
                        <p className="text-netrix-muted text-xs">Share this with {username} securely</p>
                    </div>
                </div>

                <div className="p-5 space-y-4">
                    <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                        <p className="text-amber-300 text-xs">This password will not be shown again. Copy it now.</p>
                    </div>

                    <div>
                        <label className="block text-xs text-netrix-muted mb-1.5">Temporary Password</label>
                        <div className="flex items-center gap-2">
                            <code className="flex-1 bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-netrix-text text-sm font-mono break-all">
                                {tempPassword}
                            </code>
                            <button
                                onClick={copyToClipboard}
                                className="p-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-accent hover:border-netrix-accent/50 transition-all"
                                title="Copy to clipboard"
                            >
                                {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                            </button>
                        </div>
                    </div>
                </div>

                <div className="p-5 border-t border-netrix-border/50">
                    <button
                        onClick={onClose}
                        className="w-full px-4 py-2 rounded-lg bg-netrix-accent text-white font-medium hover:bg-netrix-accent/90 transition-all text-sm"
                    >
                        Done
                    </button>
                </div>
            </div>
        </div>
    )
}

// ── Add User Modal ────────────────────────────────────────────────────────

function AddUserModal({ onClose, onCreated }) {
    const [form, setForm] = useState({ username: '', email: '', password: '', role: 'analyst' })
    const [showPw, setShowPw] = useState(false)
    const [saving, setSaving] = useState(false)
    const [error, setError] = useState('')

    const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

    const handleCreate = async () => {
        if (!form.username.trim() || !form.email.trim() || !form.password) {
            setError('Username, email, and password are required.')
            return
        }
        setSaving(true)
        setError('')
        try {
            await adminAPI.createUser(form)
            onCreated()
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to create user.')
        } finally {
            setSaving(false)
        }
    }

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-netrix-card border border-netrix-border rounded-2xl w-full max-w-md shadow-2xl">
                <div className="flex items-center justify-between p-5 border-b border-netrix-border/50">
                    <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-xl bg-netrix-accent/15 flex items-center justify-center">
                            <UserPlus className="w-5 h-5 text-netrix-accent" />
                        </div>
                        <h2 className="text-netrix-text font-semibold text-lg">Add New User</h2>
                    </div>
                    <button onClick={onClose} className="text-netrix-muted hover:text-netrix-text transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                <div className="p-5 space-y-4">
                    <div>
                        <label className="block text-sm text-netrix-muted mb-1.5">Username</label>
                        <input
                            type="text"
                            value={form.username}
                            onChange={e => set('username', e.target.value)}
                            placeholder="e.g. john_doe"
                            className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-netrix-text text-sm focus:outline-none focus:border-netrix-accent"
                        />
                    </div>
                    <div>
                        <label className="block text-sm text-netrix-muted mb-1.5">Email</label>
                        <input
                            type="email"
                            value={form.email}
                            onChange={e => set('email', e.target.value)}
                            placeholder="john@example.com"
                            className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-netrix-text text-sm focus:outline-none focus:border-netrix-accent"
                        />
                    </div>
                    <div>
                        <label className="block text-sm text-netrix-muted mb-1.5">Password</label>
                        <div className="relative">
                            <input
                                type={showPw ? 'text' : 'password'}
                                value={form.password}
                                onChange={e => set('password', e.target.value)}
                                placeholder="Min 8 characters"
                                className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 pr-10 text-netrix-text text-sm focus:outline-none focus:border-netrix-accent"
                            />
                            <button
                                type="button"
                                onClick={() => setShowPw(v => !v)}
                                className="absolute right-3 top-1/2 -translate-y-1/2 text-netrix-muted hover:text-netrix-text transition-colors"
                            >
                                {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                        </div>
                    </div>
                    <div>
                        <label className="block text-sm text-netrix-muted mb-1.5">Role</label>
                        <select
                            value={form.role}
                            onChange={e => set('role', e.target.value)}
                            className="w-full bg-netrix-bg border border-netrix-border rounded-lg px-3 py-2 text-netrix-text text-sm focus:outline-none focus:border-netrix-accent"
                        >
                            <option value="analyst">Analyst</option>
                            <option value="admin">Admin</option>
                        </select>
                    </div>

                    {error && (
                        <p className="text-red-400 text-sm flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}
                        </p>
                    )}
                </div>

                <div className="flex gap-3 p-5 border-t border-netrix-border/50">
                    <button
                        onClick={onClose}
                        className="flex-1 px-4 py-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text hover:border-netrix-accent/50 transition-all text-sm"
                    >
                        Cancel
                    </button>
                    <button
                        onClick={handleCreate}
                        disabled={saving}
                        className="flex-1 px-4 py-2 rounded-lg bg-netrix-accent text-white font-medium hover:bg-netrix-accent/90 transition-all text-sm disabled:opacity-50 flex items-center justify-center gap-2"
                    >
                        {saving ? <RefreshCw className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />}
                        {saving ? 'Creating…' : 'Create User'}
                    </button>
                </div>
            </div>
        </div>
    )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function AdminUsers() {
    const [stats, setStats] = useState(null)
    const [users, setUsers] = useState([])
    const [total, setTotal] = useState(0)
    const [totalPages, setTotalPages] = useState(1)
    const [page, setPage] = useState(1)
    const [search, setSearch] = useState('')
    const [searchInput, setSearchInput] = useState('')
    const [loading, setLoading] = useState(true)
    const [statsLoading, setStatsLoading] = useState(true)
    const [error, setError] = useState('')

    const [showAddUser, setShowAddUser] = useState(false)
    const [editUser, setEditUser] = useState(null)
    const [deleteConfirm, setDeleteConfirm] = useState(null)  // user to delete
    const [deleting, setDeleting] = useState(false)
    const [resetting, setResetting] = useState(null)  // user id being reset
    const [resetResult, setResetResult] = useState(null)  // { username, tempPassword }
    const [promotingRole, setPromotingRole] = useState(null)  // user id being role-toggled

    const PAGE_SIZE = 20

    // ── Data fetching ──────────────────────────────────────────────────

    const fetchStats = useCallback(async () => {
        setStatsLoading(true)
        try {
            const res = await adminAPI.stats()
            setStats(res.data)
        } catch {
            // stats are non-critical; fail silently
        } finally {
            setStatsLoading(false)
        }
    }, [])

    const fetchUsers = useCallback(async () => {
        setLoading(true)
        setError('')
        try {
            const params = { page, page_size: PAGE_SIZE }
            if (search) params.search = search
            const res = await adminAPI.listUsers(params)
            const data = res.data
            setUsers(data.users)
            setTotal(data.total)
            setTotalPages(data.total_pages)
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to load users.')
        } finally {
            setLoading(false)
        }
    }, [page, search])

    useEffect(() => { fetchStats() }, [fetchStats])
    useEffect(() => { fetchUsers() }, [fetchUsers])

    // ── Search ─────────────────────────────────────────────────────────

    const handleSearch = (e) => {
        e.preventDefault()
        setPage(1)
        setSearch(searchInput.trim())
    }

    // ── Delete ─────────────────────────────────────────────────────────

    const handleDelete = async () => {
        if (!deleteConfirm) return
        setDeleting(true)
        try {
            await adminAPI.deleteUser(deleteConfirm.id)
            setDeleteConfirm(null)
            fetchUsers()
            fetchStats()
        } catch (err) {
            setError(err.response?.data?.detail || 'Failed to delete user.')
            setDeleteConfirm(null)
        } finally {
            setDeleting(false)
        }
    }

    // ── Toggle role ────────────────────────────────────────────────────

    const handleToggleRole = async (user) => {
        const newRole = user.role === 'admin' ? 'analyst' : 'admin'
        setPromotingRole(user.id)
        try {
            await adminAPI.updateUser(user.id, { role: newRole })
            fetchUsers()
            fetchStats()
        } catch (err) {
            setError(err.response?.data?.detail || 'Role update failed.')
        } finally {
            setPromotingRole(null)
        }
    }

    // ── Reset password ─────────────────────────────────────────────────

    const handleResetPassword = async (user) => {
        setResetting(user.id)
        try {
            const res = await adminAPI.resetPassword(user.id)
            setResetResult({ username: res.data.username, tempPassword: res.data.temp_password })
        } catch (err) {
            setError(err.response?.data?.detail || 'Password reset failed.')
        } finally {
            setResetting(null)
        }
    }

    // ── Render ─────────────────────────────────────────────────────────

    const statCards = [
        { label: 'Total Users', key: 'total_users', icon: Users, color: 'from-blue-500 to-blue-600', shadow: 'shadow-blue-500/10' },
        { label: 'Active Users', key: 'active_users', icon: UserCheck, color: 'from-emerald-500 to-emerald-600', shadow: 'shadow-emerald-500/10' },
        { label: 'Banned Users', key: 'banned_users', icon: Ban, color: 'from-red-500 to-red-600', shadow: 'shadow-red-500/10' },
        { label: 'Admins', key: 'admins', icon: Shield, color: 'from-purple-500 to-purple-600', shadow: 'shadow-purple-500/10' },
        { label: 'Analysts', key: 'analysts', icon: BarChart2, color: 'from-cyan-500 to-cyan-600', shadow: 'shadow-cyan-500/10' },
    ]

    return (
        <Layout>
            <div className="p-6 space-y-6 max-w-7xl mx-auto">

                {/* Header */}
                <div>
                    <h1 className="text-2xl font-bold text-netrix-text">User Management</h1>
                    <p className="text-netrix-muted text-sm mt-1">Manage roles, ban status, and account access for all platform users.</p>
                </div>

                {/* Stats Row */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
                    {statCards.map(({ label, key, icon, color, shadow }) => (
                        <StatCard
                            key={key}
                            label={label}
                            value={statsLoading ? '…' : stats?.[key]}
                            icon={icon}
                            color={color}
                            shadow={shadow}
                        />
                    ))}
                </div>

                {/* Search + Table */}
                <div className="bg-netrix-card border border-netrix-border/50 rounded-2xl overflow-hidden">
                    {/* Toolbar */}
                    <div className="p-4 border-b border-netrix-border/50 flex flex-col sm:flex-row items-start sm:items-center gap-3">
                        <button
                        onClick={() => setShowAddUser(true)}
                        className="flex items-center gap-2 px-4 py-2 rounded-lg bg-netrix-accent text-white text-sm font-medium hover:bg-netrix-accent/90 transition-all flex-shrink-0"
                    >
                        <UserPlus className="w-4 h-4" />
                        Add User
                    </button>
                    <form onSubmit={handleSearch} className="flex-1 flex gap-2">
                            <div className="relative flex-1 max-w-sm">
                                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-netrix-muted" />
                                <input
                                    type="text"
                                    value={searchInput}
                                    onChange={e => setSearchInput(e.target.value)}
                                    placeholder="Search username or email…"
                                    className="w-full pl-9 pr-3 py-2 bg-netrix-bg border border-netrix-border rounded-lg text-sm text-netrix-text placeholder:text-netrix-muted focus:outline-none focus:border-netrix-accent"
                                />
                            </div>
                            <button
                                type="submit"
                                className="px-4 py-2 bg-netrix-accent text-white rounded-lg text-sm font-medium hover:bg-netrix-accent/90 transition-all"
                            >
                                Search
                            </button>
                            {search && (
                                <button
                                    type="button"
                                    onClick={() => { setSearch(''); setSearchInput(''); setPage(1) }}
                                    className="px-3 py-2 border border-netrix-border rounded-lg text-sm text-netrix-muted hover:text-netrix-text transition-all"
                                >
                                    Clear
                                </button>
                            )}
                        </form>
                        <span className="text-xs text-netrix-muted">{total} user{total !== 1 ? 's' : ''}</span>
                    </div>

                    {/* Error */}
                    {error && (
                        <div className="mx-4 mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 flex-shrink-0" />{error}
                        </div>
                    )}

                    {/* Table */}
                    <div className="overflow-x-auto">
                        <table className="w-full">
                            <thead>
                                <tr className="border-b border-netrix-border/50 bg-netrix-bg/40">
                                    {['ID', 'Username', 'Email', 'Role', 'Status', 'Scans', 'Last Login', 'Actions'].map(h => (
                                        <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-netrix-muted uppercase tracking-wider whitespace-nowrap">
                                            {h}
                                        </th>
                                    ))}
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-netrix-border/30">
                                {loading ? (
                                    <tr>
                                        <td colSpan={8} className="px-4 py-12 text-center text-netrix-muted text-sm">
                                            <RefreshCw className="w-5 h-5 animate-spin mx-auto mb-2" />
                                            Loading users…
                                        </td>
                                    </tr>
                                ) : users.length === 0 ? (
                                    <tr>
                                        <td colSpan={8} className="px-4 py-12 text-center text-netrix-muted text-sm">
                                            No users found.
                                        </td>
                                    </tr>
                                ) : users.map(user => (
                                    <tr key={user.id} className="hover:bg-netrix-bg/30 transition-colors">
                                        <td className="px-4 py-3 text-netrix-muted text-sm font-mono">{user.id}</td>
                                        <td className="px-4 py-3 text-netrix-text text-sm font-medium">{user.username}</td>
                                        <td className="px-4 py-3 text-netrix-muted text-sm">{user.email}</td>
                                        <td className="px-4 py-3"><RoleBadge role={user.role} /></td>
                                        <td className="px-4 py-3"><StatusBadge isActive={user.is_active} isBanned={user.is_banned} /></td>
                                        <td className="px-4 py-3 text-netrix-muted text-sm">{user.scan_count}</td>
                                        <td className="px-4 py-3 text-netrix-muted text-xs whitespace-nowrap">
                                            {user.last_login ? formatDateIST(user.last_login) : '—'}
                                        </td>
                                        <td className="px-4 py-3">
                                            <div className="flex items-center gap-1">
                                                <button
                                                    onClick={() => setEditUser(user)}
                                                    title="Edit user"
                                                    className="p-1.5 rounded-lg text-netrix-muted hover:text-netrix-accent hover:bg-netrix-accent/10 transition-all"
                                                >
                                                    <Edit2 className="w-4 h-4" />
                                                </button>
                                                <button
                                                    onClick={() => handleToggleRole(user)}
                                                    disabled={promotingRole === user.id}
                                                    title={user.role === 'admin' ? 'Demote to Analyst' : 'Promote to Admin'}
                                                    className={`p-1.5 rounded-lg transition-all disabled:opacity-50 ${
                                                        user.role === 'admin'
                                                            ? 'text-netrix-muted hover:text-orange-400 hover:bg-orange-400/10'
                                                            : 'text-netrix-muted hover:text-purple-400 hover:bg-purple-400/10'
                                                    }`}
                                                >
                                                    {promotingRole === user.id
                                                        ? <RefreshCw className="w-4 h-4 animate-spin" />
                                                        : user.role === 'admin'
                                                            ? <ShieldMinus className="w-4 h-4" />
                                                            : <ShieldPlus className="w-4 h-4" />
                                                    }
                                                </button>
                                                <button
                                                    onClick={() => handleResetPassword(user)}
                                                    disabled={resetting === user.id}
                                                    title="Reset password"
                                                    className="p-1.5 rounded-lg text-netrix-muted hover:text-amber-400 hover:bg-amber-400/10 transition-all disabled:opacity-50"
                                                >
                                                    {resetting === user.id
                                                        ? <RefreshCw className="w-4 h-4 animate-spin" />
                                                        : <KeyRound className="w-4 h-4" />
                                                    }
                                                </button>
                                                <button
                                                    onClick={() => setDeleteConfirm(user)}
                                                    title="Deactivate user"
                                                    className="p-1.5 rounded-lg text-netrix-muted hover:text-red-400 hover:bg-red-400/10 transition-all"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>

                    {/* Pagination */}
                    {totalPages > 1 && (
                        <div className="p-4 border-t border-netrix-border/50 flex items-center justify-between">
                            <span className="text-xs text-netrix-muted">
                                Page {page} of {totalPages}
                            </span>
                            <div className="flex gap-2">
                                <button
                                    onClick={() => setPage(p => Math.max(1, p - 1))}
                                    disabled={page === 1}
                                    className="p-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text hover:border-netrix-accent/50 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    <ChevronLeft className="w-4 h-4" />
                                </button>
                                <button
                                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                                    disabled={page === totalPages}
                                    className="p-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text hover:border-netrix-accent/50 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                                >
                                    <ChevronRight className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>

            {/* Add User Modal */}
            {showAddUser && (
                <AddUserModal
                    onClose={() => setShowAddUser(false)}
                    onCreated={() => {
                        setShowAddUser(false)
                        fetchUsers()
                        fetchStats()
                    }}
                />
            )}

            {/* Edit Modal */}
            {editUser && (
                <EditModal
                    user={editUser}
                    onClose={() => setEditUser(null)}
                    onSaved={() => {
                        setEditUser(null)
                        fetchUsers()
                        fetchStats()
                    }}
                />
            )}

            {/* Delete Confirmation Modal */}
            {deleteConfirm && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
                    <div className="bg-netrix-card border border-netrix-border rounded-2xl w-full max-w-sm shadow-2xl p-6 space-y-4">
                        <div className="flex items-center gap-3">
                            <div className="w-10 h-10 rounded-xl bg-red-500/15 flex items-center justify-center">
                                <Trash2 className="w-5 h-5 text-red-400" />
                            </div>
                            <div>
                                <h2 className="text-netrix-text font-semibold">Deactivate User</h2>
                                <p className="text-netrix-muted text-xs">This will soft-delete the account</p>
                            </div>
                        </div>
                        <p className="text-netrix-muted text-sm">
                            Are you sure you want to deactivate <strong className="text-netrix-text">{deleteConfirm.username}</strong>? Their scans will be orphaned. This action can be reversed by re-enabling the account.
                        </p>
                        <div className="flex gap-3">
                            <button
                                onClick={() => setDeleteConfirm(null)}
                                className="flex-1 px-4 py-2 rounded-lg border border-netrix-border text-netrix-muted hover:text-netrix-text transition-all text-sm"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleDelete}
                                disabled={deleting}
                                className="flex-1 px-4 py-2 rounded-lg bg-red-500 text-white font-medium hover:bg-red-600 transition-all text-sm disabled:opacity-50 flex items-center justify-center gap-2"
                            >
                                {deleting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                                {deleting ? 'Deactivating…' : 'Deactivate'}
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* Password Reset Result Modal */}
            {resetResult && (
                <PasswordResetModal
                    username={resetResult.username}
                    tempPassword={resetResult.tempPassword}
                    onClose={() => setResetResult(null)}
                />
            )}
        </Layout>
    )
}
