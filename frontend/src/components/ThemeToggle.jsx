import { useTheme } from '../context/ThemeContext'
import { Sun, Moon } from 'lucide-react'

export default function ThemeToggle() {
    const { theme, toggleTheme } = useTheme()

    return (
        <button
            onClick={toggleTheme}
            className="relative p-2 rounded-lg bg-netrix-bg/50 border border-netrix-border/30 hover:border-netrix-accent/40 hover:bg-netrix-accent/10 transition-all duration-300 group"
            title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
            aria-label="Toggle theme"
        >
            <div className="relative w-5 h-5 overflow-hidden">
                <Sun
                    className={`w-5 h-5 text-amber-400 absolute inset-0 transition-all duration-300 ${theme === 'light'
                            ? 'rotate-0 scale-100 opacity-100'
                            : 'rotate-90 scale-0 opacity-0'
                        }`}
                />
                <Moon
                    className={`w-5 h-5 text-blue-300 absolute inset-0 transition-all duration-300 ${theme === 'dark'
                            ? 'rotate-0 scale-100 opacity-100'
                            : '-rotate-90 scale-0 opacity-0'
                        }`}
                />
            </div>
        </button>
    )
}
