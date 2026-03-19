import { useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { useDispatch, useSelector } from 'react-redux'
import { setUser, logout } from './store'
import { authAPI } from './services/api'
import ProtectedRoute from './components/ProtectedRoute'
import AdminRoute from './components/AdminRoute'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanResults from './pages/ScanResults'
import Vulnerabilities from './pages/Vulnerabilities'
import Reports from './pages/Reports'
import History from './pages/History'
import Settings from './pages/Settings'
import AdminUsers from './pages/AdminUsers'
import AdminScans from './pages/AdminScans'
import AdminLogs from './pages/AdminLogs'
import AdminHealth from './pages/AdminHealth'
import AdminCVE from './pages/AdminCVE'

// Restores the user object from /auth/me on every page load when a token exists.
// Without this, user is null after refresh and role-based UI never renders.
function AuthBootstrap() {
    const dispatch = useDispatch()
    const { token, user } = useSelector(state => state.auth)

    useEffect(() => {
        if (token && !user) {
            authAPI.me()
                .then(res => dispatch(setUser(res.data)))
                .catch(() => dispatch(logout()))
        }
    }, []) // eslint-disable-line react-hooks/exhaustive-deps

    return null
}

function App() {
    return (
        <BrowserRouter>
            <AuthBootstrap />
            <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/" element={<Navigate to="/dashboard" replace />} />
                <Route path="/dashboard" element={
                    <ProtectedRoute><Dashboard /></ProtectedRoute>
                } />
                <Route path="/scan/new" element={
                    <ProtectedRoute><NewScan /></ProtectedRoute>
                } />
                <Route path="/scan/:id" element={
                    <ProtectedRoute><ScanResults /></ProtectedRoute>
                } />
                <Route path="/vulnerabilities" element={
                    <ProtectedRoute><Vulnerabilities /></ProtectedRoute>
                } />
                <Route path="/reports" element={
                    <ProtectedRoute><Reports /></ProtectedRoute>
                } />
                <Route path="/history" element={
                    <ProtectedRoute><History /></ProtectedRoute>
                } />
                <Route path="/settings" element={
                    <ProtectedRoute><Settings /></ProtectedRoute>
                } />
                <Route path="/admin/users" element={
                    <AdminRoute><AdminUsers /></AdminRoute>
                } />
                <Route path="/admin/scans" element={
                    <AdminRoute><AdminScans /></AdminRoute>
                } />
                <Route path="/admin/logs" element={
                    <AdminRoute><AdminLogs /></AdminRoute>
                } />
                <Route path="/admin/health" element={
                    <AdminRoute><AdminHealth /></AdminRoute>
                } />
                <Route path="/admin/cve" element={
                    <AdminRoute><AdminCVE /></AdminRoute>
                } />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
        </BrowserRouter>
    )
}

export default App
