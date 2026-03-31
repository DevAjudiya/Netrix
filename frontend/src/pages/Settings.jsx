// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect } from 'react'
import { useSelector, useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import {
    User, Shield, Bell, Key, LogOut, Lock, Mail,
    Scan, Monitor, Trash2, AlertTriangle, Copy,
    RefreshCw, Eye, EyeOff, Check,
    Sun, Moon, Laptop,
} from 'lucide-react'
import Layout from '../components/Layout'
import { logout, setUser } from '../store'
import { settingsAPI, authAPI } from '../services/api'
import { useToast } from '../context/ToastContext'
import { useTheme } from '../context/ThemeContext'

// ── Preference helpers (localStorage) ────────────────────────────

const PREFS_KEY = 'netrix_prefs'

const defaultPrefs = {
    defaultScanType: 'quick',
    defaultPorts: '',
    autoGenerateReport: false,
    notifyScanComplete: true,
    notifyCriticalVuln: true,
    notifyEmail: false,
    dateFormat: 'IST',
    itemsPerPage: 25,
    compactMode: false,
}

function loadPrefs() {
    try {
        return { ...defaultPrefs, ...JSON.parse(localStorage.getItem(PREFS_KEY) || '{}') }
    } catch {
        return defaultPrefs
    }
}

function savePrefs(prefs) {
    localStorage.setItem(PREFS_KEY, JSON.stringify(prefs))
}

// ── Small reusable components ─────────────────────────────────────

function SectionCard({ title, icon: Icon, children }) {
    return (
        <div className="glass-card p-6 mb-4">
            <h2 className="text-base font-semibold text-netrix-text flex items-center gap-2 mb-5">
                <Icon className="w-4 h-4 text-netrix-accent" />
                {title}
            </h2>
            {children}
        </div>
    )
}

function Field({ label, hint, children }) {
    return (
        <div className="mb-4">
            <label className="block text-xs font-medium text-netrix-muted mb-1">{label}</label>
            {children}
            {hint && <p className="text-[11px] text-netrix-muted mt-1">{hint}</p>}
        </div>
    )
}

function Input({ className = '', ...props }) {
    return (
        <input
            className={`w-full px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-netrix-text text-sm
                focus:outline-none focus:border-netrix-accent transition-colors ${className}`}
            {...props}
        />
    )
}

function Toggle({ checked, onChange, label, hint }) {
    return (
        <div className="flex items-center justify-between py-3 border-b border-netrix-border last:border-0">
            <div>
                <p className="text-sm text-netrix-text">{label}</p>
                {hint && <p className="text-[11px] text-netrix-muted mt-0.5">{hint}</p>}
            </div>
            <button
                onClick={() => onChange(!checked)}
                className={`relative w-10 h-5 rounded-full transition-colors flex-shrink-0 ${checked ? 'bg-netrix-accent' : 'bg-netrix-border'}`}
            >
                <span className={`absolute top-0.5 left-0.5 w-4 h-4 rounded-full bg-white shadow transition-transform ${checked ? 'translate-x-5' : ''}`} />
            </button>
        </div>
    )
}

function SaveBtn({ loading, onClick, label = 'Save Changes' }) {
    return (
        <button
            onClick={onClick}
            disabled={loading}
            className="btn-primary flex items-center gap-2 mt-4 disabled:opacity-50"
        >
            {loading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Check className="w-4 h-4" />}
            {label}
        </button>
    )
}

// ── Nav tabs ──────────────────────────────────────────────────────

const TABS = [
    { id: 'account',       label: 'Account',          icon: User },
    { id: 'security',      label: 'Security',          icon: Shield },
    { id: 'scan_prefs',    label: 'Scan Preferences',  icon: Scan },
    { id: 'notifications', label: 'Notifications',     icon: Bell },
    { id: 'display',       label: 'Display & UI',      icon: Monitor },
    { id: 'danger',        label: 'Danger Zone',        icon: AlertTriangle },
]

// ─────────────────────────────────────────────────────────────────
// Main Component
// ─────────────────────────────────────────────────────────────────

export default function Settings() {
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const { user } = useSelector(s => s.auth)
    const { showToast } = useToast()
    const { theme, setTheme } = useTheme()

    const [activeTab, setActiveTab] = useState('account')
    const [prefs, setPrefs] = useState(loadPrefs)

    // ── Account state ────────────────────────────────────────────
    const [pwForm, setPwForm] = useState({ current: '', next: '', confirm: '' })
    const [showPw, setShowPw] = useState({ current: false, next: false, confirm: false })
    const [pwLoading, setPwLoading] = useState(false)

    const [emailForm, setEmailForm] = useState({ email: '', password: '' })
    const [emailLoading, setEmailLoading] = useState(false)

    // ── Security / API Key state ─────────────────────────────────
    const [apiKey, setApiKey] = useState(null)
    const [hasApiKey, setHasApiKey] = useState(false)
    const [apiKeyLoading, setApiKeyLoading] = useState(false)
    const [newKeyPlain, setNewKeyPlain] = useState(null) // shown once after generation
    const [copied, setCopied] = useState(false)

    // ── Danger Zone state ────────────────────────────────────────
    const [deleteScansLoading, setDeleteScansLoading] = useState(false)
    const [deleteAccForm, setDeleteAccForm] = useState('')
    const [deleteAccLoading, setDeleteAccLoading] = useState(false)
    const [confirmDeleteScans, setConfirmDeleteScans] = useState(false)
    const [confirmDeleteAcc, setConfirmDeleteAcc] = useState(false)

    useEffect(() => {
        fetchApiKey()
    }, [])

    const fetchApiKey = async () => {
        try {
            const res = await settingsAPI.getApiKey()
            setHasApiKey(res.data.has_key)
            setApiKey(res.data.api_key)
        } catch { /* ignore */ }
    }

    // ── Save prefs to localStorage whenever they change ──────────
    const updatePref = (key, value) => {
        const updated = { ...prefs, [key]: value }
        setPrefs(updated)
        savePrefs(updated)
    }

    const handleLogout = () => {
        dispatch(logout())
        navigate('/login')
    }

    // ── Change Password ──────────────────────────────────────────
    const handleChangePassword = async () => {
        if (!pwForm.current || !pwForm.next) return showToast('Please fill in all fields.', 'warning')
        if (pwForm.next.length < 8) return showToast('New password must be at least 8 characters.', 'warning')
        if (pwForm.next !== pwForm.confirm) return showToast('New passwords do not match.', 'error')
        setPwLoading(true)
        try {
            await settingsAPI.changePassword(pwForm.current, pwForm.next)
            showToast('Password updated successfully.', 'success')
            setPwForm({ current: '', next: '', confirm: '' })
        } catch (e) {
            showToast(e.response?.data?.detail || 'Failed to update password.', 'error')
        } finally {
            setPwLoading(false)
        }
    }

    // ── Change Email ─────────────────────────────────────────────
    const handleChangeEmail = async () => {
        if (!emailForm.email || !emailForm.password) return showToast('Please fill in all fields.', 'warning')
        setEmailLoading(true)
        try {
            const res = await settingsAPI.changeEmail(emailForm.email, emailForm.password)
            showToast('Email updated successfully.', 'success')
            dispatch(setUser({ ...user, email: res.data.email }))
            setEmailForm({ email: '', password: '' })
        } catch (e) {
            showToast(e.response?.data?.detail || 'Failed to update email.', 'error')
        } finally {
            setEmailLoading(false)
        }
    }

    // ── API Key ──────────────────────────────────────────────────
    const handleGenerateApiKey = async () => {
        setApiKeyLoading(true)
        setNewKeyPlain(null)
        try {
            const res = await settingsAPI.generateApiKey()
            setNewKeyPlain(res.data.api_key)
            setHasApiKey(true)
            setApiKey(null)
            showToast('API key generated. Copy it now!', 'success')
        } catch (e) {
            showToast(e.response?.data?.detail || 'Failed to generate API key.', 'error')
        } finally {
            setApiKeyLoading(false)
        }
    }

    const handleRevokeApiKey = async () => {
        setApiKeyLoading(true)
        try {
            await settingsAPI.revokeApiKey()
            setHasApiKey(false)
            setApiKey(null)
            setNewKeyPlain(null)
            showToast('API key revoked.', 'success')
        } catch (e) {
            showToast(e.response?.data?.detail || 'Failed to revoke API key.', 'error')
        } finally {
            setApiKeyLoading(false)
        }
    }

    const handleCopyKey = () => {
        navigator.clipboard.writeText(newKeyPlain)
        setCopied(true)
        setTimeout(() => setCopied(false), 2000)
    }

    // ── Danger Zone ──────────────────────────────────────────────
    const handleDeleteAllScans = async () => {
        setDeleteScansLoading(true)
        try {
            const res = await settingsAPI.deleteAllScans()
            showToast(res.data.message, 'success')
            setConfirmDeleteScans(false)
        } catch (e) {
            showToast(e.response?.data?.detail || 'Failed to delete scans.', 'error')
        } finally {
            setDeleteScansLoading(false)
        }
    }

    const handleDeleteAccount = async () => {
        if (!deleteAccForm) return showToast('Enter your password to confirm.', 'warning')
        setDeleteAccLoading(true)
        try {
            await settingsAPI.deleteAccount(deleteAccForm)
            showToast('Account deleted. Goodbye!', 'info')
            dispatch(logout())
            navigate('/login')
        } catch (e) {
            showToast(e.response?.data?.detail || 'Failed to delete account.', 'error')
        } finally {
            setDeleteAccLoading(false)
        }
    }

    // ── Render ───────────────────────────────────────────────────

    return (
        <Layout>
            <div className="animate-fade-in max-w-3xl">
                {/* Header */}
                <div className="mb-5 flex items-center justify-between">
                    <div>
                        <h1 className="text-2xl font-bold text-netrix-text">Settings</h1>
                        <p className="text-sm text-netrix-muted mt-0.5">Manage your account and preferences</p>
                    </div>
                    <button
                        onClick={handleLogout}
                        className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm text-red-400 border border-red-400/30 hover:bg-red-400/10 transition-colors"
                    >
                        <LogOut className="w-4 h-4" />
                        Sign Out
                    </button>
                </div>

                {/* ── Top Tab Bar ─────────────────────────────── */}
                <div className="flex gap-1 mb-6 bg-netrix-surface border border-netrix-border rounded-xl p-1 overflow-x-auto">
                    {TABS.map(({ id, label, icon: Icon }) => (
                        <button
                            key={id}
                            onClick={() => setActiveTab(id)}
                            className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-medium whitespace-nowrap transition-colors flex-shrink-0
                                ${activeTab === id
                                    ? id === 'danger'
                                        ? 'bg-red-500/15 text-red-400'
                                        : 'bg-netrix-accent/15 text-netrix-accent'
                                    : id === 'danger'
                                        ? 'text-netrix-muted hover:text-red-400 hover:bg-red-400/10'
                                        : 'text-netrix-muted hover:text-netrix-text hover:bg-netrix-bg/60'
                                }`}
                        >
                            <Icon className="w-3.5 h-3.5" />
                            {label}
                        </button>
                    ))}
                </div>

                {/* ── Content ─────────────────────────────────── */}
                <div>

                        {/* ── Account ───────────────────────────── */}
                        {activeTab === 'account' && (
                            <>
                                <SectionCard title="Profile" icon={User}>
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <p className="text-xs text-netrix-muted mb-1">Username</p>
                                            <div className="px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-netrix-text text-sm font-medium">
                                                {user?.username || '—'}
                                            </div>
                                        </div>
                                        <div>
                                            <p className="text-xs text-netrix-muted mb-1">Role</p>
                                            <div className="px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-sm">
                                                <span className="text-cyan-400 font-medium capitalize">{user?.role || '—'}</span>
                                            </div>
                                        </div>
                                        <div className="col-span-2">
                                            <p className="text-xs text-netrix-muted mb-1">Current Email</p>
                                            <div className="px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-netrix-text text-sm">
                                                {user?.email || '—'}
                                            </div>
                                        </div>
                                    </div>
                                </SectionCard>

                                <SectionCard title="Change Email" icon={Mail}>
                                    <Field label="New Email Address">
                                        <Input
                                            type="email"
                                            placeholder="new@example.com"
                                            value={emailForm.email}
                                            onChange={e => setEmailForm(f => ({ ...f, email: e.target.value }))}
                                        />
                                    </Field>
                                    <Field label="Confirm Password" hint="Enter your current password to verify the change.">
                                        <Input
                                            type="password"
                                            placeholder="Your current password"
                                            value={emailForm.password}
                                            onChange={e => setEmailForm(f => ({ ...f, password: e.target.value }))}
                                        />
                                    </Field>
                                    <SaveBtn loading={emailLoading} onClick={handleChangeEmail} label="Update Email" />
                                </SectionCard>

                                <SectionCard title="Change Password" icon={Lock}>
                                    {[
                                        { key: 'current', label: 'Current Password', ph: 'Enter current password' },
                                        { key: 'next',    label: 'New Password',     ph: 'Min. 8 characters' },
                                        { key: 'confirm', label: 'Confirm New Password', ph: 'Repeat new password' },
                                    ].map(({ key, label, ph }) => (
                                        <Field key={key} label={label}>
                                            <div className="relative">
                                                <Input
                                                    type={showPw[key] ? 'text' : 'password'}
                                                    placeholder={ph}
                                                    value={pwForm[key]}
                                                    onChange={e => setPwForm(f => ({ ...f, [key]: e.target.value }))}
                                                    className="pr-10"
                                                />
                                                <button
                                                    type="button"
                                                    onClick={() => setShowPw(s => ({ ...s, [key]: !s[key] }))}
                                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-netrix-muted hover:text-netrix-text"
                                                >
                                                    {showPw[key] ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                                </button>
                                            </div>
                                        </Field>
                                    ))}
                                    <SaveBtn loading={pwLoading} onClick={handleChangePassword} label="Update Password" />
                                </SectionCard>
                            </>
                        )}

                        {/* ── Security ──────────────────────────── */}
                        {activeTab === 'security' && (
                            <>
                                <SectionCard title="System Security" icon={Shield}>
                                    <div className="space-y-0">
                                        {[
                                            { label: 'JWT Authentication', status: 'Active', color: 'green' },
                                            { label: 'Rate Limiting', status: 'Enabled', color: 'green' },
                                            { label: 'CORS Protection', status: 'Enabled', color: 'green' },
                                        ].map(({ label, status, color }) => (
                                            <div key={label} className="flex items-center justify-between py-3 border-b border-netrix-border last:border-0">
                                                <span className="text-sm text-netrix-text">{label}</span>
                                                <span className={`text-xs font-medium px-2 py-0.5 rounded-full bg-${color}-400/10 text-${color}-400`}>
                                                    {status}
                                                </span>
                                            </div>
                                        ))}
                                        <div className="flex items-center justify-between py-3">
                                            <span className="text-sm text-netrix-text">Session Token</span>
                                            <span className="text-xs text-netrix-muted font-mono">
                                                {localStorage.getItem('netrix_token')?.slice(0, 20)}…
                                            </span>
                                        </div>
                                    </div>
                                </SectionCard>

                                <SectionCard title="API Key" icon={Key}>
                                    <p className="text-xs text-netrix-muted mb-4">
                                        Use your API key to authenticate CLI and script access. It acts as a Bearer token.
                                    </p>

                                    {newKeyPlain && (
                                        <div className="mb-4 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
                                            <p className="text-xs text-amber-400 font-medium mb-2 flex items-center gap-1">
                                                <AlertTriangle className="w-3.5 h-3.5" />
                                                Copy your key now — it won't be shown again.
                                            </p>
                                            <div className="flex items-center gap-2">
                                                <code className="flex-1 text-xs font-mono text-netrix-text bg-netrix-bg px-3 py-2 rounded border border-netrix-border break-all">
                                                    {newKeyPlain}
                                                </code>
                                                <button
                                                    onClick={handleCopyKey}
                                                    className="p-2 rounded-lg hover:bg-netrix-accent/10 text-netrix-muted hover:text-netrix-accent transition-colors flex-shrink-0"
                                                    title="Copy"
                                                >
                                                    {copied ? <Check className="w-4 h-4 text-green-400" /> : <Copy className="w-4 h-4" />}
                                                </button>
                                            </div>
                                        </div>
                                    )}

                                    {hasApiKey && !newKeyPlain && (
                                        <div className="flex items-center gap-2 mb-4 px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border">
                                            <Key className="w-4 h-4 text-netrix-accent flex-shrink-0" />
                                            <code className="text-xs font-mono text-netrix-muted flex-1">{apiKey || 'netrix_' + '•'.repeat(24) + '…'}</code>
                                            <span className="text-[10px] text-green-400 font-medium bg-green-400/10 px-2 py-0.5 rounded-full">Active</span>
                                        </div>
                                    )}

                                    {!hasApiKey && !newKeyPlain && (
                                        <p className="text-sm text-netrix-muted mb-4">No API key generated yet.</p>
                                    )}

                                    <div className="flex gap-2">
                                        <button
                                            onClick={handleGenerateApiKey}
                                            disabled={apiKeyLoading}
                                            className="btn-primary flex items-center gap-2 text-sm disabled:opacity-50"
                                        >
                                            {apiKeyLoading ? <RefreshCw className="w-4 h-4 animate-spin" /> : <RefreshCw className="w-4 h-4" />}
                                            {hasApiKey ? 'Regenerate Key' : 'Generate API Key'}
                                        </button>
                                        {hasApiKey && (
                                            <button
                                                onClick={handleRevokeApiKey}
                                                disabled={apiKeyLoading}
                                                className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm text-red-400 border border-red-400/30 hover:bg-red-400/10 transition-colors disabled:opacity-50"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                                Revoke
                                            </button>
                                        )}
                                    </div>
                                </SectionCard>
                            </>
                        )}

                        {/* ── Scan Preferences ──────────────────── */}
                        {activeTab === 'scan_prefs' && (
                            <SectionCard title="Scan Preferences" icon={Scan}>
                                <Field label="Default Scan Type" hint="Pre-selected scan type when you open New Scan.">
                                    <select
                                        value={prefs.defaultScanType}
                                        onChange={e => updatePref('defaultScanType', e.target.value)}
                                        className="w-full px-3 py-2 rounded-lg bg-netrix-surface border border-netrix-border text-netrix-text text-sm focus:outline-none focus:border-netrix-accent"
                                    >
                                        <option value="quick">Quick (30s–1 min)</option>
                                        <option value="stealth">Stealth (2–5 min)</option>
                                        <option value="full">Full (5–15 min)</option>
                                        <option value="aggressive">Aggressive (3–8 min)</option>
                                        <option value="vulnerability">Vulnerability (10–20 min)</option>
                                    </select>
                                </Field>

                                <Field label="Default Ports" hint="Pre-fill the custom ports field (e.g. 22,80,443,8080). Leave empty to use scan profile defaults.">
                                    <Input
                                        type="text"
                                        placeholder="e.g. 22,80,443,8080"
                                        value={prefs.defaultPorts}
                                        onChange={e => updatePref('defaultPorts', e.target.value)}
                                    />
                                </Field>

                                <div className="mt-2">
                                    <Toggle
                                        checked={prefs.autoGenerateReport}
                                        onChange={v => updatePref('autoGenerateReport', v)}
                                        label="Auto-generate PDF Report"
                                        hint="Automatically create a PDF report when a scan completes."
                                    />
                                </div>

                                <p className="text-[11px] text-netrix-muted mt-4 flex items-center gap-1">
                                    <Check className="w-3 h-3 text-green-400" />
                                    Preferences saved automatically.
                                </p>
                            </SectionCard>
                        )}

                        {/* ── Notifications ─────────────────────── */}
                        {activeTab === 'notifications' && (
                            <SectionCard title="Notifications" icon={Bell}>
                                <Toggle
                                    checked={prefs.notifyScanComplete}
                                    onChange={v => updatePref('notifyScanComplete', v)}
                                    label="Scan Complete Alert"
                                    hint="Show a browser notification when a scan finishes."
                                />
                                <Toggle
                                    checked={prefs.notifyCriticalVuln}
                                    onChange={v => updatePref('notifyCriticalVuln', v)}
                                    label="Critical Vulnerability Alert"
                                    hint="Notify when a Critical severity CVE is found during a scan."
                                />
                                <Toggle
                                    checked={prefs.notifyEmail}
                                    onChange={v => updatePref('notifyEmail', v)}
                                    label="Email Notifications"
                                    hint="Receive scan summaries and critical alerts via email."
                                />
                                <p className="text-[11px] text-netrix-muted mt-4 flex items-center gap-1">
                                    <Check className="w-3 h-3 text-green-400" />
                                    Preferences saved automatically.
                                </p>
                            </SectionCard>
                        )}

                        {/* ── Display & UI ──────────────────────── */}
                        {activeTab === 'display' && (
                            <SectionCard title="Display & UI" icon={Monitor}>
                                {/* Theme */}
                                <Field label="Theme">
                                    <div className="grid grid-cols-3 gap-2">
                                        {[
                                            { value: 'dark',   label: 'Dark',   icon: Moon },
                                            { value: 'light',  label: 'Light',  icon: Sun },
                                            { value: 'system', label: 'System', icon: Laptop },
                                        ].map(({ value, label, icon: Icon }) => (
                                            <button
                                                key={value}
                                                onClick={() => setTheme(value)}
                                                className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border text-xs font-medium transition-colors
                                                    ${theme === value
                                                        ? 'border-netrix-accent bg-netrix-accent/10 text-netrix-accent'
                                                        : 'border-netrix-border text-netrix-muted hover:border-netrix-accent/50'
                                                    }`}
                                            >
                                                <Icon className="w-5 h-5" />
                                                {label}
                                            </button>
                                        ))}
                                    </div>
                                </Field>

                                {/* Date format */}
                                <Field label="Date & Time Format" hint="Applies to scan timestamps and reports.">
                                    <div className="flex gap-2">
                                        {['IST', 'UTC', 'Local'].map(fmt => (
                                            <button
                                                key={fmt}
                                                onClick={() => updatePref('dateFormat', fmt)}
                                                className={`flex-1 py-2 rounded-lg text-sm font-medium border transition-colors
                                                    ${prefs.dateFormat === fmt
                                                        ? 'border-netrix-accent bg-netrix-accent/10 text-netrix-accent'
                                                        : 'border-netrix-border text-netrix-muted hover:border-netrix-accent/50'
                                                    }`}
                                            >
                                                {fmt}
                                            </button>
                                        ))}
                                    </div>
                                </Field>

                                {/* Items per page */}
                                <Field label="Items Per Page" hint="Rows shown in scan history, vulnerability, and report tables.">
                                    <div className="flex gap-2">
                                        {[10, 25, 50, 100].map(n => (
                                            <button
                                                key={n}
                                                onClick={() => updatePref('itemsPerPage', n)}
                                                className={`flex-1 py-2 rounded-lg text-sm font-medium border transition-colors
                                                    ${prefs.itemsPerPage === n
                                                        ? 'border-netrix-accent bg-netrix-accent/10 text-netrix-accent'
                                                        : 'border-netrix-border text-netrix-muted hover:border-netrix-accent/50'
                                                    }`}
                                            >
                                                {n}
                                            </button>
                                        ))}
                                    </div>
                                </Field>

                                <Toggle
                                    checked={prefs.compactMode}
                                    onChange={v => updatePref('compactMode', v)}
                                    label="Compact Mode"
                                    hint="Reduce row height in tables for denser data display."
                                />

                                <p className="text-[11px] text-netrix-muted mt-4 flex items-center gap-1">
                                    <Check className="w-3 h-3 text-green-400" />
                                    Preferences saved automatically.
                                </p>
                            </SectionCard>
                        )}

                        {/* ── Danger Zone ───────────────────────── */}
                        {activeTab === 'danger' && (
                            <>
                                <div className="glass-card p-6 mb-4 border border-red-500/20">
                                    <h2 className="text-base font-semibold text-red-400 flex items-center gap-2 mb-1">
                                        <AlertTriangle className="w-4 h-4" />
                                        Danger Zone
                                    </h2>
                                    <p className="text-xs text-netrix-muted mb-5">These actions are irreversible. Proceed with caution.</p>

                                    {/* Delete All Scans */}
                                    <div className="border border-netrix-border rounded-xl p-4 mb-4">
                                        <div className="flex items-start justify-between gap-4">
                                            <div>
                                                <p className="text-sm font-medium text-netrix-text">Delete All Scan History</p>
                                                <p className="text-xs text-netrix-muted mt-0.5">Permanently delete all your scans, hosts, ports, and vulnerabilities.</p>
                                            </div>
                                            {!confirmDeleteScans ? (
                                                <button
                                                    onClick={() => setConfirmDeleteScans(true)}
                                                    className="flex-shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-red-400 border border-red-400/30 hover:bg-red-400/10 transition-colors"
                                                >
                                                    <Trash2 className="w-3.5 h-3.5" />
                                                    Delete All
                                                </button>
                                            ) : (
                                                <div className="flex-shrink-0 flex items-center gap-2">
                                                    <span className="text-xs text-netrix-muted">Are you sure?</span>
                                                    <button
                                                        onClick={handleDeleteAllScans}
                                                        disabled={deleteScansLoading}
                                                        className="flex items-center gap-1 px-3 py-1.5 rounded-lg text-sm bg-red-500 text-white hover:bg-red-600 disabled:opacity-50 transition-colors"
                                                    >
                                                        {deleteScansLoading ? <RefreshCw className="w-3 h-3 animate-spin" /> : null}
                                                        Yes, Delete
                                                    </button>
                                                    <button
                                                        onClick={() => setConfirmDeleteScans(false)}
                                                        className="px-3 py-1.5 rounded-lg text-sm text-netrix-muted border border-netrix-border hover:bg-netrix-surface transition-colors"
                                                    >
                                                        Cancel
                                                    </button>
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    {/* Delete Account */}
                                    <div className="border border-red-500/20 rounded-xl p-4">
                                        <p className="text-sm font-medium text-red-400">Delete Account</p>
                                        <p className="text-xs text-netrix-muted mt-0.5 mb-3">
                                            Permanently delete your account and all associated data. This cannot be undone.
                                        </p>
                                        {!confirmDeleteAcc ? (
                                            <button
                                                onClick={() => setConfirmDeleteAcc(true)}
                                                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm text-red-400 border border-red-400/30 hover:bg-red-400/10 transition-colors"
                                            >
                                                <AlertTriangle className="w-3.5 h-3.5" />
                                                Delete My Account
                                            </button>
                                        ) : (
                                            <div className="space-y-3">
                                                <Input
                                                    type="password"
                                                    placeholder="Enter your password to confirm"
                                                    value={deleteAccForm}
                                                    onChange={e => setDeleteAccForm(e.target.value)}
                                                />
                                                <div className="flex items-center gap-2">
                                                    <button
                                                        onClick={handleDeleteAccount}
                                                        disabled={deleteAccLoading}
                                                        className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-sm bg-red-500 text-white hover:bg-red-600 disabled:opacity-50 transition-colors"
                                                    >
                                                        {deleteAccLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Trash2 className="w-3.5 h-3.5" />}
                                                        Confirm Delete
                                                    </button>
                                                    <button
                                                        onClick={() => { setConfirmDeleteAcc(false); setDeleteAccForm('') }}
                                                        className="px-4 py-2 rounded-lg text-sm text-netrix-muted border border-netrix-border hover:bg-netrix-surface transition-colors"
                                                    >
                                                        Cancel
                                                    </button>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </>
                        )}
                </div>
            </div>
        </Layout>
    )
}
