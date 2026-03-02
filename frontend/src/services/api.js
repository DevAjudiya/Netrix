import axios from 'axios'

const API_BASE = '/api/v1'

const api = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' }
})

api.interceptors.request.use(config => {
  const token = localStorage.getItem('netrix_token')
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

api.interceptors.response.use(
  response => response,
  error => {
    if (error.response?.status === 401) {
      localStorage.removeItem('netrix_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authAPI = {
  login: (username, password) =>
    api.post('/auth/login', { username, password }),
  me: () => api.get('/auth/me'),
  logout: () => api.post('/auth/logout')
}

export const scansAPI = {
  create: (target, scanType, customArgs, customPorts) =>
    api.post('/scans/', {
      target,
      scan_type: scanType,
      custom_args: customArgs,
      custom_ports: customPorts
    }),
  list: (params) => api.get('/scans/', { params }),
  get: (scanId) => api.get(`/scans/${scanId}`),
  status: (scanId) => api.get(`/scans/${scanId}/status`),
  results: (scanId) => api.get(`/scans/${scanId}/results`),
  delete: (scanId) => api.delete(`/scans/${scanId}`)
}

export const reportsAPI = {
  generate: (scanId, format, reportName) =>
    api.post('/reports/generate', {
      scan_id: scanId,
      format,
      report_name: reportName
    }),
  list: (params) => api.get('/reports/', { params }),
  download: (reportId) =>
    api.get(`/reports/${reportId}/download`, {
      responseType: 'blob'
    }),
  delete: (reportId) => api.delete(`/reports/${reportId}`)
}

export const vulnsAPI = {
  list: (params) => api.get('/vulnerabilities/', { params }),
  get: (vulnId) => api.get(`/vulnerabilities/${vulnId}`),
  stats: (scanId) => api.get(`/vulnerabilities/stats/${scanId}`),
  cve: (cveId) => api.get(`/vulnerabilities/cve/${cveId}`)
}

export const dashboardAPI = {
  stats: () => api.get('/dashboard/stats'),
  recentScans: () => api.get('/dashboard/recent-scans'),
  vulnChart: () => api.get('/dashboard/vulnerability-chart'),
  scanHistory: () => api.get('/dashboard/scan-history-chart')
}

export const hostsAPI = {
  list: (params) => api.get('/hosts/', { params }),
  get: (hostId) => api.get(`/hosts/${hostId}`),
  ports: (hostId) => api.get(`/hosts/${hostId}/ports`),
  vulns: (hostId) => api.get(`/hosts/${hostId}/vulnerabilities`)
}

export default api
