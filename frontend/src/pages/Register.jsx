// © 2026 @DevAjudiya. All rights reserved.
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { authAPI } from '../services/api'
import { Shield, Eye, EyeOff, Loader2, Lock, User, Mail, CheckCircle } from 'lucide-react'
import ThemeToggle from '../components/ThemeToggle'

export default function Register() {
    const navigate = useNavigate()
    const [username, setUsername] = useState('')
    const [email, setEmail] = useState('')
    const [password, setPassword] = useState('')
    const [confirmPassword, setConfirmPassword] = useState('')
    const [showPassword, setShowPassword] = useState(false)
    const [showConfirmPassword, setShowConfirmPassword] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')
    const [readOnly, setReadOnly] = useState(true)

    const validatePassword = (pwd) => {
        if (pwd.length < 8) return 'Password must be at least 8 characters long'
        if (!/[A-Z]/.test(pwd)) return 'Password must contain at least one uppercase letter'
        if (!/[0-9]/.test(pwd)) return 'Password must contain at least one digit'
        if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(pwd))
            return 'Password must contain at least one special character'
        return null
    }

    const handleSubmit = async (e) => {
        e.preventDefault()
        setError('')

        if (!username.trim()) return setError('Username is required')
        if (!email.trim()) return setError('Email is required')
        if (!password.trim()) return setError('Password is required')

        const pwdError = validatePassword(password)
        if (pwdError) return setError(pwdError)

        if (password !== confirmPassword) return setError('Passwords do not match')

        setLoading(true)
        try {
            await authAPI.register(username, email, password)
            navigate('/login', { state: { registered: true } })
        } catch (err) {
            const data = err.response?.data
            let msg = 'Registration failed. Please try again.'
            if (data?.message) {
                msg = data.message
            } else if (Array.isArray(data?.detail)) {
                // Pydantic 422 validation error — extract first message
                const raw = data.detail[0]?.msg || msg
                msg = raw.replace(/^Value error,\s*/i, '')
            } else if (typeof data?.detail === 'string') {
                msg = data.detail
            }
            setError(msg)
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="min-h-screen bg-netrix-bg flex items-center justify-center p-4 relative overflow-hidden">
            {/* Background Grid */}
            <div
                className="absolute inset-0 opacity-[0.03]"
                style={{
                    backgroundImage: `
                        linear-gradient(rgba(6,182,212,0.3) 1px, transparent 1px),
                        linear-gradient(90deg, rgba(6,182,212,0.3) 1px, transparent 1px)
                    `,
                    backgroundSize: '60px 60px',
                }}
            />

            {/* Glow Orbs */}
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-[120px]" />
            <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-[120px]" />

            {/* Theme Toggle */}
            <div className="absolute top-4 right-4 z-20">
                <ThemeToggle />
            </div>

            <div className="w-full max-w-md relative z-10 animate-fade-in">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl gradient-accent shadow-lg shadow-cyan-500/25 mb-4">
                        <Shield className="w-8 h-8 text-white" />
                    </div>
                    <h1 className="text-3xl font-bold text-gradient mb-1">NETRIX</h1>
                    <p className="text-netrix-muted text-sm">Network Security Suite</p>
                </div>

                {/* Register Card */}
                <div className="glass-card p-8 glow-cyan">
                    <div className="mb-6">
                        <h2 className="text-xl font-semibold text-netrix-text">Create account</h2>
                        <p className="text-sm text-netrix-muted mt-1">Register for your security console</p>
                    </div>

                    {error && (
                        <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center gap-2">
                            <Lock className="w-4 h-4 text-red-400 flex-shrink-0" />
                            <p className="text-sm text-red-400">{error}</p>
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-4" autoComplete="off">
                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Username</label>
                            <div className="flex items-center bg-netrix-bg border border-netrix-border rounded-lg focus-within:border-netrix-accent focus-within:ring-1 focus-within:ring-netrix-accent/30 transition-all duration-200">
                                <span className="flex items-center justify-center w-10 shrink-0 text-netrix-muted/50">
                                    <User className="w-4 h-4" />
                                </span>
                                <input
                                    type="text"
                                    name="register-username"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    placeholder="Choose a username"
                                    className="w-full bg-transparent py-3 pr-4 text-netrix-text placeholder-netrix-muted/50 focus:outline-none"
                                    autoFocus
                                    autoComplete="off"
                                    readOnly={readOnly}
                                    onFocus={() => setReadOnly(false)}
                                    disabled={loading}
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Email</label>
                            <div className="flex items-center bg-netrix-bg border border-netrix-border rounded-lg focus-within:border-netrix-accent focus-within:ring-1 focus-within:ring-netrix-accent/30 transition-all duration-200">
                                <span className="flex items-center justify-center w-10 shrink-0 text-netrix-muted/50">
                                    <Mail className="w-4 h-4" />
                                </span>
                                <input
                                    type="email"
                                    name="register-email"
                                    value={email}
                                    onChange={(e) => setEmail(e.target.value)}
                                    placeholder="Enter your email"
                                    className="w-full bg-transparent py-3 pr-4 text-netrix-text placeholder-netrix-muted/50 focus:outline-none"
                                    autoComplete="off"
                                    disabled={loading}
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Password</label>
                            <div className="flex items-center bg-netrix-bg border border-netrix-border rounded-lg focus-within:border-netrix-accent focus-within:ring-1 focus-within:ring-netrix-accent/30 transition-all duration-200 relative">
                                <span className="flex items-center justify-center w-10 shrink-0 text-netrix-muted/50">
                                    <Lock className="w-4 h-4" />
                                </span>
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    name="new-password"
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="Choose a password"
                                    className="w-full bg-transparent py-3 pr-10 text-netrix-text placeholder-netrix-muted/50 focus:outline-none"
                                    autoComplete="new-password"
                                    readOnly={readOnly}
                                    onFocus={() => setReadOnly(false)}
                                    disabled={loading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-netrix-muted/50 hover:text-netrix-muted transition-colors"
                                >
                                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                            {password && (
                                <ul className="mt-1.5 space-y-0.5 text-xs">
                                    {[
                                        { label: 'At least 8 characters', ok: password.length >= 8 },
                                        { label: 'One uppercase letter', ok: /[A-Z]/.test(password) },
                                        { label: 'One digit', ok: /[0-9]/.test(password) },
                                        { label: 'One special character', ok: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password) },
                                    ].map(({ label, ok }) => (
                                        <li key={label} className={`flex items-center gap-1.5 ${ok ? 'text-green-400' : 'text-netrix-muted/60'}`}>
                                            <span>{ok ? '✓' : '·'}</span>{label}
                                        </li>
                                    ))}
                                </ul>
                            )}
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Confirm Password</label>
                            <div className="flex items-center bg-netrix-bg border border-netrix-border rounded-lg focus-within:border-netrix-accent focus-within:ring-1 focus-within:ring-netrix-accent/30 transition-all duration-200 relative">
                                <span className="flex items-center justify-center w-10 shrink-0 text-netrix-muted/50">
                                    <CheckCircle className="w-4 h-4" />
                                </span>
                                <input
                                    type={showConfirmPassword ? 'text' : 'password'}
                                    name="confirm-password"
                                    value={confirmPassword}
                                    onChange={(e) => setConfirmPassword(e.target.value)}
                                    placeholder="Repeat your password"
                                    className="w-full bg-transparent py-3 pr-10 text-netrix-text placeholder-netrix-muted/50 focus:outline-none"
                                    autoComplete="new-password"
                                    disabled={loading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                    className="absolute right-3 top-1/2 -translate-y-1/2 text-netrix-muted/50 hover:text-netrix-muted transition-colors"
                                >
                                    {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                </button>
                            </div>
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full btn-primary flex items-center justify-center gap-2 mt-6"
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    Creating account...
                                </>
                            ) : (
                                <>
                                    <Shield className="w-4 h-4" />
                                    CREATE ACCOUNT
                                </>
                            )}
                        </button>
                    </form>

                    <p className="text-center text-sm text-netrix-muted mt-5">
                        Already have an account?{' '}
                        <button
                            onClick={() => navigate('/login')}
                            className="text-netrix-accent hover:text-cyan-300 transition-colors font-medium"
                        >
                            Sign in
                        </button>
                    </p>
                </div>

                <p className="text-center text-netrix-muted/40 text-xs mt-6">
                    Netrix v1.0 — Network Scanning &amp; Vulnerability Assessment
                    <br />
                    &copy; 2026 @DevAjudiya. All rights reserved.
                </p>
            </div>
        </div>
    )
}
