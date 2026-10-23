const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api';

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
    const error = data.detail || data.message || 'An error occurred';
    throw new Error(error);
  }
  return data;
};

export const api = {
  get: async (endpoint) => {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: 'GET',
      headers: getAuthHeaders(),
    });
    return handleResponse(response);
  },

  post: async (endpoint, payload) => {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
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
  
  // CyberSentinel Phase 12 methods
  getPosture: () => api.get('/v1/posture'),
  getFinding: (id) => api.get(`/v1/findings/${id}`),
};
