import { NavLink } from 'react-router-dom'
import {
    LayoutDashboard, Plus, History, Bug, FileText,
    ChevronLeft, ChevronRight, Zap
} from 'lucide-react'

const navItems = [
    { path: '/dashboard', icon: LayoutDashboard, label: 'Dashboard' },
    { path: '/scan/new', icon: Plus, label: 'New Scan' },
    { path: '/history', icon: History, label: 'Scan History' },
    { path: '/vulnerabilities', icon: Bug, label: 'Vulnerabilities' },
    { path: '/reports', icon: FileText, label: 'Reports' },
]

export default function Sidebar({ collapsed, onToggle, mobileOpen, onMobileClose }) {
    return (
        <>
            {mobileOpen && (
                <div
                    className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 lg:hidden"
                    onClick={onMobileClose}
                />
            )}

            <aside className={`
        fixed top-16 left-0 bottom-0 z-40
        bg-netrix-card/95 backdrop-blur-xl border-r border-netrix-border/50
        transition-all duration-300 ease-in-out flex flex-col
        ${collapsed ? 'w-[72px]' : 'w-60'}
        ${mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
      `}>
                <nav className="flex-1 py-4 px-3 space-y-1 overflow-y-auto">
                    {navItems.map(({ path, icon: Icon, label }) => (
                        <NavLink
                            key={path}
                            to={path}
                            onClick={onMobileClose}
                            className={({ isActive }) => `
                flex items-center gap-3 px-3 py-2.5 rounded-lg
                transition-all duration-200 group relative
                ${isActive
                                    ? 'bg-netrix-accent/10 text-netrix-accent border border-netrix-accent/20'
                                    : 'text-netrix-muted hover:text-netrix-text hover:bg-netrix-bg/50 border border-transparent'
                                }
              `}
                        >
                            {({ isActive }) => (
                                <>
                                    {isActive && (
                                        <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-6 bg-netrix-accent rounded-r" />
                                    )}
                                    <Icon className={`w-5 h-5 flex-shrink-0 ${isActive ? 'text-netrix-accent' : ''}`} />
                                    {!collapsed && (
                                        <span className="text-sm font-medium truncate">{label}</span>
                                    )}
                                    {collapsed && (
                                        <span className="absolute left-full ml-3 px-2 py-1 rounded-md bg-netrix-bg text-netrix-text text-xs font-medium whitespace-nowrap opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 shadow-lg border border-netrix-border z-50">
                                            {label}
                                        </span>
                                    )}
                                </>
                            )}
                        </NavLink>
                    ))}
                </nav>

                <div className="p-3 border-t border-netrix-border/30">
                    {!collapsed && (
                        <div className="mb-3 p-3 rounded-lg bg-gradient-to-br from-cyan-500/10 to-blue-600/10 border border-netrix-accent/20">
                            <div className="flex items-center gap-2 mb-1">
                                <Zap className="w-4 h-4 text-netrix-accent" />
                                <span className="text-xs font-semibold text-netrix-accent">Quick Scan</span>
                            </div>
                            <p className="text-[11px] text-netrix-muted leading-relaxed">
                                Launch a quick port scan from the New Scan page
                            </p>
                        </div>
                    )}
                    <button
                        onClick={onToggle}
                        className="hidden lg:flex w-full items-center justify-center gap-2 px-3 py-2 rounded-lg text-netrix-muted hover:text-netrix-text hover:bg-netrix-bg/50 transition-all duration-200"
                    >
                        {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
                        {!collapsed && <span className="text-xs">Collapse</span>}
                    </button>
                </div>
            </aside>
        </>
    )
}
