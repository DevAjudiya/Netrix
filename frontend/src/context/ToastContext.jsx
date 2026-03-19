import { createContext, useContext, useState, useCallback, useRef } from 'react'
import { CheckCircle, XCircle, AlertTriangle, Info, X } from 'lucide-react'

const ToastContext = createContext(null)

const ICONS = {
    success: CheckCircle,
    error: XCircle,
    warning: AlertTriangle,
    info: Info,
}

const STYLES = {
    success: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-300',
    error: 'border-red-500/40 bg-red-500/10 text-red-300',
    warning: 'border-amber-500/40 bg-amber-500/10 text-amber-300',
    info: 'border-netrix-accent/40 bg-netrix-accent/10 text-netrix-accent',
}

let _nextId = 1

export function ToastProvider({ children }) {
    const [toasts, setToasts] = useState([])
    const timers = useRef({})

    const dismiss = useCallback((id) => {
        clearTimeout(timers.current[id])
        delete timers.current[id]
        setToasts(prev => prev.filter(t => t.id !== id))
    }, [])

    const showToast = useCallback((message, type = 'info', duration = 3500) => {
        const id = _nextId++
        setToasts(prev => [...prev, { id, message, type }])
        timers.current[id] = setTimeout(() => dismiss(id), duration)
    }, [dismiss])

    return (
        <ToastContext.Provider value={{ showToast }}>
            {children}
            {/* Toast container */}
            <div className="fixed top-20 right-4 z-[9999] flex flex-col gap-2 pointer-events-none">
                {toasts.map(({ id, message, type }) => {
                    const Icon = ICONS[type] || Info
                    const style = STYLES[type] || STYLES.info
                    return (
                        <div
                            key={id}
                            className={`
                                pointer-events-auto flex items-start gap-3 px-4 py-3 rounded-xl
                                border backdrop-blur-xl shadow-xl min-w-[280px] max-w-sm
                                ${style}
                                animate-slide-in-right
                            `}
                        >
                            <Icon className="w-4 h-4 flex-shrink-0 mt-0.5" />
                            <span className="text-sm flex-1">{message}</span>
                            <button
                                onClick={() => dismiss(id)}
                                className="flex-shrink-0 opacity-60 hover:opacity-100 transition-opacity"
                            >
                                <X className="w-3.5 h-3.5" />
                            </button>
                        </div>
                    )
                })}
            </div>
        </ToastContext.Provider>
    )
}

export function useToast() {
    const ctx = useContext(ToastContext)
    if (!ctx) throw new Error('useToast must be used inside ToastProvider')
    return ctx
}
