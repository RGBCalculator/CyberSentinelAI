const rawBaseUrl = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';
const API_BASE_URL = rawBaseUrl.replace(/\/+$/, '');

const getAuthHeaders = () => {
  const token = localStorage.getItem('access_token');
  if (token) {
    return {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    };
  }
  return {
    'Content-Type': 'application/json'
  };
};

const handleResponse = async (response) => {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = data.detail || data.message || `HTTP ${response.status}: ${response.statusText || 'Request failed'}`;
    throw new Error(error);
  }
  return data;
};

export const api = {
  get: async (endpoint) => {
    const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'GET',
      headers: getAuthHeaders(),
    });
    return handleResponse(response);
  },

  post: async (endpoint, payload) => {
    const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const response = await fetch(`${API_BASE_URL}${path}`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify(payload),
    });
    return handleResponse(response);
  },

  // Specialized methods
  login: (email, password) => api.post('/v1/auth/login', { email, password }),
  register: (userData) => api.post('/v1/auth/register', userData),
  testProtected: () => api.get('/v1/protected'),
  
  // Security Posture (Demo repository intelligence)
  getPosture: () => api.get('/v1/posture'),
  getFinding: (id) => api.get(`/v1/findings/${id}`),

  // Unified SOC & Scanner
  getSocOverview: () => api.get('/v1/soc/overview'),
  getFindings: (params = {}) => {
    const searchParams = new URLSearchParams();
    if (params.severity && params.severity !== 'ALL') searchParams.append('severity', params.severity);
    if (params.category && params.category !== 'ALL') searchParams.append('category', params.category);
    if (params.search) searchParams.append('search', params.search);
    if (params.limit) searchParams.append('limit', params.limit);
    if (params.skip) searchParams.append('skip', params.skip);
    const qs = searchParams.toString();
    return api.get(`/v1/findings${qs ? `?${qs}` : ''}`);
  },
  scanUrl: (url, metadata = {}) => api.post('/v1/scan', { target: url, scan_type: 'url', metadata }),
  getRecentScans: (limit = 20, skip = 0, riskLevel = null) => {
    let url = `/v1/scans?limit=${limit}&skip=${skip}`;
    if (riskLevel && riskLevel !== 'ALL') url += `&risk_level=${riskLevel}`;
    return api.get(url);
  },
  getScanById: (id) => api.get(`/v1/scans/${id}`),

  // Website Security & Trust Intelligence
  analyzeWebsite: (target) => api.post('/v1/website/analyze', { target }),

  // Threat Intelligence
  getThreatIntelStatus: () => api.get('/v1/threat-intel/status'),
  lookupThreatIntel: (indicator, indicatorType = 'url') => 
    api.post('/v1/threat-intel/lookup', { indicator, indicator_type: indicatorType }),

  // Reports Export
  exportReport: () => api.get('/v1/reports/export'),
};
