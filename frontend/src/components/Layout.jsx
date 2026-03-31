// © 2026 @DevAjudiya. All rights reserved.
import { useState, useEffect } from 'react'
import { useDispatch } from 'react-redux'
import { setUser, logout } from '../store'
import { authAPI } from '../services/api'
import Navbar from './Navbar'
import Sidebar from './Sidebar'

export default function Layout({ children }) {
    const dispatch = useDispatch()
    const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
    const [mobileOpen, setMobileOpen] = useState(false)

    useEffect(() => {
        const fetchUser = async () => {
            try {
                const res = await authAPI.me()
                dispatch(setUser(res.data))
            } catch {
                dispatch(logout())
            }
        }
        fetchUser()
    }, [dispatch])

    return (
        <div className="min-h-screen bg-netrix-bg">
            <Navbar onToggleSidebar={() => setMobileOpen(prev => !prev)} />
            <Sidebar
                collapsed={sidebarCollapsed}
                onToggle={() => setSidebarCollapsed(prev => !prev)}
                mobileOpen={mobileOpen}
                onMobileClose={() => setMobileOpen(false)}
            />
            <main className={`
        pt-16 min-h-screen transition-all duration-300
        ${sidebarCollapsed ? 'lg:pl-[72px]' : 'lg:pl-60'}
      `}>
                <div className="p-4 lg:p-6 max-w-[1600px] mx-auto">
                    {children}
                </div>
                <footer className={`px-4 lg:px-6 pb-4 transition-all duration-300 ${sidebarCollapsed ? 'lg:pl-[72px]' : 'lg:pl-60'}`}>
                    <p className="text-center text-netrix-muted/30 text-xs">
                        &copy; 2026 @DevAjudiya. All rights reserved.
                    </p>
                </footer>
            </main>
        </div>
    )
}
