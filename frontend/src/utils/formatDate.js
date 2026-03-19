// Shared IST date formatter — all timestamps displayed in Indian Standard Time (UTC+5:30)

// The backend returns ISO strings without a timezone suffix (e.g. "2026-03-19T04:26:09").
// Without "Z" or "+HH:MM", different browsers treat bare ISO strings inconsistently.
// We always append "Z" so JavaScript parses them as UTC, then toLocaleString converts to IST.
const toUTC = (dateStr) => {
    if (!dateStr) return null
    const s = String(dateStr)
    // Already has timezone info
    if (s.endsWith('Z') || /[+-]\d{2}:\d{2}$/.test(s)) return s
    return s + 'Z'
}

export const formatDateIST = (dateStr) => {
    const utc = toUTC(dateStr)
    if (!utc) return '—'
    const d = new Date(utc)
    if (isNaN(d)) return '—'
    return d.toLocaleString('en-IN', {
        timeZone: 'Asia/Kolkata',
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: true,
    })
}

export const formatTimeIST = (dateStr) => {
    const utc = toUTC(dateStr)
    if (!utc) return '—'
    const d = new Date(utc)
    if (isNaN(d)) return '—'
    return d.toLocaleTimeString('en-IN', {
        timeZone: 'Asia/Kolkata',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
    })
}
