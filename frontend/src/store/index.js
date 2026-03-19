import { configureStore, createSlice } from '@reduxjs/toolkit'

const _hasToken = !!localStorage.getItem('netrix_token')

const authSlice = createSlice({
    name: 'auth',
    initialState: {
        user: null,
        token: localStorage.getItem('netrix_token'),
        isAuthenticated: _hasToken,
        // true while we're fetching /auth/me to restore the session on page load
        userLoading: _hasToken,
        loading: false,
        error: null
    },
    reducers: {
        loginSuccess: (state, action) => {
            state.user = action.payload.user
            state.token = action.payload.token
            state.isAuthenticated = true
            state.userLoading = false
            state.error = null
            localStorage.setItem('netrix_token', action.payload.token)
        },
        logout: (state) => {
            state.user = null
            state.token = null
            state.isAuthenticated = false
            state.userLoading = false
            localStorage.removeItem('netrix_token')
        },
        setUser: (state, action) => {
            state.user = action.payload
            state.userLoading = false
        },
        setUserLoading: (state, action) => {
            state.userLoading = action.payload
        },
        setError: (state, action) => {
            state.error = action.payload
        }
    }
})

const scansSlice = createSlice({
    name: 'scans',
    initialState: {
        scans: [],
        currentScan: null,
        activeScan: null,
        scanProgress: 0,
        loading: false,
        error: null
    },
    reducers: {
        setScans: (state, action) => {
            state.scans = action.payload
        },
        setCurrentScan: (state, action) => {
            state.currentScan = action.payload
        },
        setActiveScan: (state, action) => {
            state.activeScan = action.payload
        },
        updateProgress: (state, action) => {
            state.scanProgress = action.payload
        },
        setLoading: (state, action) => {
            state.loading = action.payload
        },
        setError: (state, action) => {
            state.error = action.payload
        }
    }
})

const dashboardSlice = createSlice({
    name: 'dashboard',
    initialState: {
        stats: null,
        recentScans: [],
        vulnChart: null,
        loading: false
    },
    reducers: {
        setStats: (state, action) => {
            state.stats = action.payload
        },
        setRecentScans: (state, action) => {
            state.recentScans = action.payload
        },
        setVulnChart: (state, action) => {
            state.vulnChart = action.payload
        },
        setLoading: (state, action) => {
            state.loading = action.payload
        }
    }
})

export const {
    loginSuccess, logout, setUser, setUserLoading,
    setError: setAuthError
} = authSlice.actions

export const {
    setScans, setCurrentScan, setActiveScan,
    updateProgress, setLoading, setError
} = scansSlice.actions

export const {
    setStats, setRecentScans,
    setVulnChart, setLoading: setDashLoading
} = dashboardSlice.actions

export const store = configureStore({
    reducer: {
        auth: authSlice.reducer,
        scans: scansSlice.reducer,
        dashboard: dashboardSlice.reducer
    }
})
