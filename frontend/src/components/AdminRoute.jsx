import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useSelector } from 'react-redux'
import { useToast } from '../context/ToastContext'

/**
 * Route guard that requires the user to be authenticated AND have role === 'admin'.
 * - Waits for the session bootstrap (/auth/me) to finish before making a decision.
 * - Unauthenticated users are redirected to /login.
 * - Authenticated non-admins are redirected to /dashboard with an error toast.
 */
export default function AdminRoute({ children }) {
    const { isAuthenticated, user, userLoading } = useSelector(state => state.auth)
    const navigate = useNavigate()
    const { showToast } = useToast()
    const [allowed, setAllowed] = useState(false)

    useEffect(() => {
        // Still waiting for /auth/me to return — do nothing yet
        if (userLoading) return

        if (!isAuthenticated) {
            navigate('/login', { replace: true })
        } else if (user?.role !== 'admin') {
            showToast('Access restricted — admin role required.', 'error')
            navigate('/dashboard', { replace: true })
        } else {
            setAllowed(true)
        }
    }, [isAuthenticated, user, userLoading, navigate, showToast])

    // Render nothing while the session is being restored or access is denied
    if (!allowed) return null
    return children
}
