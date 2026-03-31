// © 2026 @DevAjudiya. All rights reserved.
export default function LoadingSpinner({ size = 'md', text = '' }) {
    const sizes = {
        sm: 'w-5 h-5',
        md: 'w-8 h-8',
        lg: 'w-12 h-12',
        xl: 'w-16 h-16'
    }

    return (
        <div className="flex flex-col items-center justify-center gap-3">
            <div className={`${sizes[size]} relative`}>
                <div className={`${sizes[size]} rounded-full border-2 border-netrix-border animate-spin`}
                    style={{ borderTopColor: '#06B6D4' }}
                />
                <div className={`absolute inset-0 ${sizes[size]} rounded-full border-2 border-transparent animate-spin`}
                    style={{
                        borderBottomColor: '#3B82F6',
                        animationDuration: '1.5s',
                        animationDirection: 'reverse'
                    }}
                />
            </div>
            {text && (
                <p className="text-netrix-muted text-sm animate-pulse">{text}</p>
            )}
        </div>
    )
}
