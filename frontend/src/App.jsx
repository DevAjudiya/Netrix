import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import ProtectedRoute from './components/ProtectedRoute'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanResults from './pages/ScanResults'
import Vulnerabilities from './pages/Vulnerabilities'
import Reports from './pages/Reports'
import History from './pages/History'
import Settings from './pages/Settings'

function App() {
    return (
        <BrowserRouter>
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
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
            </Routes>
        </BrowserRouter>
    )
}

export default App
