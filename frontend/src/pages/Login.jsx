import { useState } from 'react'
import { useDispatch } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import { loginSuccess, setAuthError } from '../store'
import { authAPI } from '../services/api'
import { Shield, Eye, EyeOff, Loader2, Lock, User } from 'lucide-react'

export default function Login() {
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const [username, setUsername] = useState('')
    const [password, setPassword] = useState('')
    const [showPassword, setShowPassword] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')

    const handleSubmit = async (e) => {
        e.preventDefault()
        setError('')

        if (!username.trim()) return setError('Username is required')
        if (!password.trim()) return setError('Password is required')

        setLoading(true)
        try {
            const res = await authAPI.login(username, password)
            const { access_token } = res.data

            // Store token so the axios interceptor attaches it to subsequent requests
            localStorage.setItem('netrix_token', access_token)

            // Fetch the authenticated user's profile
            const meRes = await authAPI.me()
            const user = meRes.data

            dispatch(loginSuccess({ token: access_token, user }))
            navigate('/dashboard', { replace: true })
        } catch (err) {
            // Clean up token if /me request failed after login
            localStorage.removeItem('netrix_token')
            const msg = err.response?.data?.message || err.response?.data?.detail || 'Invalid credentials. Please try again.'
            setError(msg)
            dispatch(setAuthError(msg))
        } finally {
            setLoading(false)
        }
    }

    return (
        <div className="min-h-screen bg-netrix-bg flex items-center justify-center p-4 relative overflow-hidden">
            {/* Background Grid */}
            <div className="absolute inset-0 opacity-[0.03]"
                style={{
                    backgroundImage: `
            linear-gradient(rgba(6,182,212,0.3) 1px, transparent 1px),
            linear-gradient(90deg, rgba(6,182,212,0.3) 1px, transparent 1px)
          `,
                    backgroundSize: '60px 60px'
                }}
            />

            {/* Glow Orbs */}
            <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-[120px]" />
            <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-[120px]" />

            <div className="w-full max-w-md relative z-10 animate-fade-in">
                {/* Logo */}
                <div className="text-center mb-8">
                    <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl gradient-accent shadow-lg shadow-cyan-500/25 mb-4">
                        <Shield className="w-8 h-8 text-white" />
                    </div>
                    <h1 className="text-3xl font-bold text-gradient mb-1">NETRIX</h1>
                    <p className="text-netrix-muted text-sm">Network Security Suite</p>
                </div>

                {/* Login Card */}
                <div className="glass-card p-8 glow-cyan">
                    <div className="mb-6">
                        <h2 className="text-xl font-semibold text-netrix-text">Welcome back</h2>
                        <p className="text-sm text-netrix-muted mt-1">Sign in to your security console</p>
                    </div>

                    {error && (
                        <div className="mb-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 flex items-center gap-2">
                            <Lock className="w-4 h-4 text-red-400 flex-shrink-0" />
                            <p className="text-sm text-red-400">{error}</p>
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Username</label>
                            <div className="relative">
                                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-netrix-muted/50" />
                                <input
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    placeholder="Enter your username"
                                    className="input-dark pl-10"
                                    autoFocus
                                    disabled={loading}
                                />
                            </div>
                        </div>

                        <div>
                            <label className="block text-sm font-medium text-netrix-muted mb-1.5">Password</label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-netrix-muted/50" />
                                <input
                                    type={showPassword ? 'text' : 'password'}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    placeholder="Enter your password"
                                    className="input-dark pl-10 pr-10"
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
                        </div>

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full btn-primary flex items-center justify-center gap-2 mt-6"
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="w-4 h-4 animate-spin" />
                                    Authenticating...
                                </>
                            ) : (
                                <>
                                    <Shield className="w-4 h-4" />
                                    LOGIN TO NETRIX
                                </>
                            )}
                        </button>
                    </form>
                </div>

                <p className="text-center text-netrix-muted/40 text-xs mt-6">
                    Netrix v1.0 — Network Scanning &amp; Vulnerability Assessment
                </p>
            </div>
        </div>
    )
}
