/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                netrix: {
                    bg: 'rgb(var(--netrix-bg) / <alpha-value>)',
                    card: 'rgb(var(--netrix-card) / <alpha-value>)',
                    border: 'rgb(var(--netrix-border) / <alpha-value>)',
                    text: 'rgb(var(--netrix-text) / <alpha-value>)',
                    muted: 'rgb(var(--netrix-muted) / <alpha-value>)',
                    accent: 'rgb(var(--netrix-accent) / <alpha-value>)',
                    'accent-hover': 'rgb(var(--netrix-accent-hover) / <alpha-value>)',
                },
                severity: {
                    critical: '#DC2626',
                    high: '#EA580C',
                    medium: '#CA8A04',
                    low: '#16A34A',
                    info: '#3B82F6',
                }
            },
            fontFamily: {
                sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
            },
            animation: {
                'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                'scan-line': 'scanLine 2s linear infinite',
                'fade-in': 'fadeIn 0.5s ease-out',
                'slide-up': 'slideUp 0.4s ease-out',
                'slide-in-left': 'slideInLeft 0.3s ease-out',
            },
            keyframes: {
                scanLine: {
                    '0%': { transform: 'translateX(-100%)' },
                    '100%': { transform: 'translateX(100%)' },
                },
                fadeIn: {
                    '0%': { opacity: '0' },
                    '100%': { opacity: '1' },
                },
                slideUp: {
                    '0%': { opacity: '0', transform: 'translateY(20px)' },
                    '100%': { opacity: '1', transform: 'translateY(0)' },
                },
                slideInLeft: {
                    '0%': { opacity: '0', transform: 'translateX(-20px)' },
                    '100%': { opacity: '1', transform: 'translateX(0)' },
                },
            },
        },
    },
    plugins: [],
}
