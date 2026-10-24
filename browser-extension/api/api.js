/**
 * CyberSentinel AI - Browser Extension API Client
 * Facilitates communication with the CyberSentinel AI backend services.
 */

const DEFAULT_API_BASE = 'http://localhost:8000';

class CyberSentinelApi {
  constructor(baseUrl = DEFAULT_API_BASE) {
    this.baseUrl = baseUrl;
  }

  /**
   * Retrieves the configured API base URL from chrome.storage.local or defaults to localhost.
   */
  async getBaseUrl() {
    try {
      if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
        const res = await chrome.storage.local.get(['apiBaseUrl']);
        if (res && res.apiBaseUrl) {
          return res.apiBaseUrl;
        }
      }
    } catch {
      // Fallback to default
    }
    return this.baseUrl;
  }

  /**
   * Dispatches a target URL to the backend /api/v1/scan endpoint.
   * @param {string} targetUrl - Active tab URL to inspect
   * @param {string} [token] - Optional Bearer auth token if user is logged in
   * @returns {Promise<Object>} Scan results payload
   */
  async scanUrl(targetUrl, token = null) {
    const base = await this.getBaseUrl();
    const endpoint = `${base}/api/v1/scan`;

    const headers = {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    };

    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 20000); // 20s timeout

    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers,
        body: JSON.stringify({
          target: targetUrl,
          scan_type: 'url'
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);

      if (!response.ok) {
        const errPayload = await response.json().catch(() => ({}));
        const message = errPayload.detail || `Scan failed with HTTP ${response.status}`;
        throw new Error(message);
      }

      return await response.json();
    } catch (err) {
      clearTimeout(timeoutId);
      if (err.name === 'AbortError') {
        throw new Error('Analysis timed out. SOC backend may be under high load.');
      }
      throw err;
    }
  }

  /**
   * Checks connectivity to the backend health endpoint.
   * @returns {Promise<boolean>}
   */
  async checkHealth() {
    try {
      const base = await this.getBaseUrl();
      const response = await fetch(`${base}/health`, { method: 'GET' });
      return response.ok;
    } catch {
      return false;
    }
  }
}

// Support both ES Module import and global script loading
if (typeof window !== 'undefined') {
  window.CyberSentinelApi = CyberSentinelApi;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { CyberSentinelApi };
}
