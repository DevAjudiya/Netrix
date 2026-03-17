import { useDispatch, useSelector } from 'react-redux'
import { useNavigate } from 'react-router-dom'
import { logout } from '../store'
import { authAPI } from '../services/api'
import { Shield, LogOut, User, Menu } from 'lucide-react'
import ThemeToggle from './ThemeToggle'

export default function Navbar({ onToggleSidebar }) {
    const dispatch = useDispatch()
    const navigate = useNavigate()
    const { user } = useSelector(state => state.auth)

    const handleLogout = async () => {
        try {
            await authAPI.logout()
        } catch (err) {
            /* ignore logout errors */
        }
        dispatch(logout())
        navigate('/login')
    }

    return (
        <header className="fixed top-0 left-0 right-0 z-40 h-16 bg-netrix-card/90 backdrop-blur-xl border-b border-netrix-border/50">
            <div className="flex items-center justify-between h-full px-4 lg:px-6">
                <div className="flex items-center gap-3">
                    <button
                        onClick={onToggleSidebar}
                        className="lg:hidden p-2 rounded-lg hover:bg-netrix-bg transition-colors"
                    >
                        <Menu className="w-5 h-5 text-netrix-muted" />
                    </button>

                    <div className="flex items-center gap-2.5">
                        <div className="relative">
                            <Shield className="w-7 h-7 text-netrix-accent" />
                            <span className="absolute -top-0.5 -right-0.5 w-2 h-2 bg-green-500 rounded-full border border-netrix-card" />
                        </div>
                        <div>
                            <h1 className="text-lg font-bold text-gradient leading-tight">NETRIX</h1>
                            <p className="text-[10px] text-netrix-muted uppercase tracking-[0.2em] leading-tight">Security Suite</p>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-3">
                    <ThemeToggle />
                    <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-netrix-bg/50 border border-netrix-border/30">
                        <div className="w-7 h-7 rounded-full gradient-accent flex items-center justify-center">
                            <User className="w-3.5 h-3.5 text-white" />
                        </div>
                        <span className="text-sm text-netrix-text font-medium">
                            {user?.username || 'Admin'}
                        </span>
                    </div>
                    <button
                        onClick={handleLogout}
                        className="flex items-center gap-2 px-3 py-2 rounded-lg text-netrix-muted hover:text-red-400 hover:bg-red-500/10 transition-all duration-200"
                        title="Logout"
                    >
                        <LogOut className="w-4 h-4" />
                        <span className="hidden sm:inline text-sm">Logout</span>
                    </button>
                </div>
            </div>
        </header>
    )
}
