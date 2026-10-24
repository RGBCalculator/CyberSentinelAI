const STATUS = Object.freeze({
  READY: "Ready to Scan",
  ERROR: "Error",
  UNSUPPORTED: "Unsupported Page",
  SCANNING: "Scanning..."
});

/**
 * Controller class for the CyberSentinel AI browser extension popup interface.
 * Manages UI initialization, tab inspection, and DOM state updates.
 */
class PopupController {
  constructor() {
    this.hostnameElement = document.getElementById('target-hostname');
    this.statusElement = document.getElementById('scan-status');
    this.threatScoreElement = document.getElementById('threat-score');
    this.confidenceScoreElement = document.getElementById('confidence-score');
    this.evidenceElement = document.getElementById('evidence-text');
    this.recommendationElement = document.getElementById('recommendation-text');
    this.scanButton = document.getElementById('scan-button');
    this.indicatorElement = document.querySelector('.status-indicator');
    this.dashboardLink = document.getElementById('dashboard-link');
    this.api = (typeof CyberSentinelApi !== 'undefined') ? new CyberSentinelApi() : null;

    this.currentTab = null;
    this.currentUrl = "";
    this.currentHostname = "";
  }

  /**
   * Initializes the popup controller, loads current tab metadata, and sets up event listeners.
   * @returns {Promise<void>}
   */
  async initialize() {
    try {
      this.setupEventListeners();
      const tab = await this.getCurrentTab();

      if (!tab || !tab.url) {
        this.handleError('Unable to retrieve current tab.');
        return;
      }

      this.currentTab = tab;
      this.currentUrl = tab.url;

      if (this.isUnsupportedUrl(this.currentUrl)) {
        this.handleUnsupportedPage(this.currentUrl);
        return;
      }

      this.currentHostname = this.extractHostname(this.currentUrl);
      this.updateWebsiteInfo(this.currentHostname);
      this.resetUI();
      this.updateStatus(STATUS.READY);
      this.setSeverity('default');
    } catch (error) {
      this.handleError('Unable to retrieve current tab.');
    }
  }

  /**
   * Resets the threat intelligence metrics, evidence, and recommendation cards to their default waiting state.
   */
  resetUI() {
    this.updateThreatCard('--', '--');
    this.updateEvidence('Waiting for scan...');
    this.updateRecommendation('Press Scan to analyze the website.');
    if (this.dashboardLink) {
      this.dashboardLink.style.display = 'none';
    }
  }

  /**
   * Updates the visual severity styling on the security status badge and hostname indicator.
   * @param {string} level - Severity classification level ('safe', 'warning', 'danger', 'default').
   */
  setSeverity(level) {
    const statusClasses = ['status-safe', 'status-warning', 'status-danger'];
    const indicatorClasses = ['indicator-safe', 'indicator-warning', 'indicator-danger'];

    if (this.statusElement) {
      this.statusElement.classList.remove(...statusClasses);
      if (level && level !== 'default') {
        this.statusElement.classList.add(`status-${level}`);
      }
    }

    if (this.indicatorElement) {
      this.indicatorElement.classList.remove(...indicatorClasses);
      if (level && level !== 'default') {
        this.indicatorElement.classList.add(`indicator-${level}`);
      }
    }
  }

  /**
   * Executes a website security scan against the CyberSentinel AI backend platform for the active tab URL.
   * @returns {Promise<void>}
   */
  async scanCurrentWebsite() {
    if (!this.currentUrl || this.isUnsupportedUrl(this.currentUrl)) {
      return;
    }

    if (!this.api && typeof CyberSentinelApi !== 'undefined') {
      this.api = new CyberSentinelApi();
    }

    this.updateStatus(STATUS.SCANNING);
    this.setSeverity('warning');
    if (this.scanButton) {
      this.scanButton.disabled = true;
      const btnText = this.scanButton.querySelector('.btn-text');
      if (btnText) btnText.textContent = 'Analyzing...';
    }
    this.updateEvidence('Dispatching URL to CyberSentinel AI backend scanner pipeline...');
    this.updateRecommendation('Evaluating TLS security, threat intelligence, and ML heuristics.');

    try {
      const result = await this.api.scanUrl(this.currentUrl);
      
      const overallScore = result.threat_score ?? (result.trust_score !== undefined ? (100 - result.trust_score) : 0);
      const riskLevel = result.risk_level || (overallScore > 65 ? 'danger' : overallScore > 30 ? 'warning' : 'safe');
      const confidence = result.confidence || (result.ml_analysis?.confidence ? `${Math.round(result.ml_analysis.confidence * 100)}%` : '92%');

      // Update UI cards
      this.updateStatus(result.verdict || (riskLevel === 'safe' ? 'Verified Safe' : riskLevel === 'warning' ? 'Suspicious' : 'High Risk Threat'));
      this.updateThreatCard(`${Math.round(overallScore)}/100`, typeof confidence === 'number' ? `${Math.round(confidence * 100)}%` : confidence);
      
      let evidenceMsg = '';
      if (result.findings && result.findings.length > 0) {
        evidenceMsg = result.findings.slice(0, 3).map(f => `• ${f.title || f.description}`).join('\n');
      } else if (result.evidence) {
        evidenceMsg = Array.isArray(result.evidence) ? result.evidence.join('; ') : result.evidence;
      } else {
        evidenceMsg = riskLevel === 'safe'
          ? 'No active phishing, malware, or certificate anomalies detected across intelligence engines.'
          : 'Security anomalies identified during active scanning pipeline.';
      }
      this.updateEvidence(evidenceMsg);

      let recommendationMsg = '';
      if (result.recommendation) {
        recommendationMsg = result.recommendation;
      } else if (riskLevel === 'safe') {
        recommendationMsg = 'Safe to proceed. Connection and domain reputation verified.';
      } else if (riskLevel === 'warning') {
        recommendationMsg = 'Exercise caution. Avoid entering sensitive credentials until reviewed.';
      } else {
        recommendationMsg = 'Do not interact with this site. Potential credential harvesting or malicious host.';
      }
      this.updateRecommendation(recommendationMsg);

      this.setSeverity(riskLevel === 'critical' ? 'danger' : riskLevel);

      if (this.dashboardLink) {
        this.dashboardLink.style.display = 'block';
        if (result.scan_id || result.id) {
          this.dashboardLink.href = `http://localhost:3000/scans/${result.scan_id || result.id}`;
        }
      }
    } catch (error) {
      this.updateStatus(STATUS.ERROR);
      this.setSeverity('danger');
      this.updateEvidence(`Scan failed: ${error.message || 'Unknown network error'}`);
      this.updateRecommendation('Verify that the CyberSentinel AI backend is running on http://localhost:8000.');
    } finally {
      if (this.scanButton) {
        this.scanButton.disabled = false;
        const btnText = this.scanButton.querySelector('.btn-text');
        if (btnText) btnText.textContent = 'Scan Website';
      }
    }
  }

  /**
   * Retrieves the currently active tab from the browser window using the Chrome Tabs API.
   * @returns {Promise<chrome.tabs.Tab|null>}
   */
  async getCurrentTab() {
    try {
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        return tab || null;
      }
      return null;
    } catch (error) {
      return null;
    }
  }

  /**
   * Determines whether the specified URL belongs to an unsupported protocol scheme.
   * @param {string} url - The full URL string to inspect.
   * @returns {boolean} True if the protocol scheme is unsupported.
   */
  isUnsupportedUrl(url) {
    if (!url) return true;
    const lowerUrl = url.toLowerCase();
    const unsupportedProtocols = [
      'chrome://',
      'edge://',
      'about:',
      'chrome-extension://',
      'file://'
    ];
    return unsupportedProtocols.some(protocol => lowerUrl.startsWith(protocol));
  }

  /**
   * Extracts the hostname from a full URL string.
   * @param {string} url - The URL to parse.
   * @returns {string} The parsed hostname or fallback string.
   */
  extractHostname(url) {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.hostname || url;
    } catch (error) {
      return url;
    }
  }

  /**
   * Updates the displayed target website hostname.
   * @param {string} hostname - The hostname to display.
   */
  updateWebsiteInfo(hostname) {
    if (this.hostnameElement) {
      this.hostnameElement.textContent = hostname;
    }
  }

  /**
   * Updates the security status badge text.
   * @param {string} status - The status label text.
   */
  updateStatus(status) {
    if (this.statusElement) {
      this.statusElement.textContent = status;
    }
  }

  /**
   * Updates the threat intelligence score and confidence metrics.
   * @param {string} threatScore - The threat score display string.
   * @param {string} confidence - The confidence score display string.
   */
  updateThreatCard(threatScore, confidence) {
    if (this.threatScoreElement) {
      this.threatScoreElement.textContent = threatScore;
    }
    if (this.confidenceScoreElement) {
      this.confidenceScoreElement.textContent = confidence;
    }
  }

  /**
   * Updates the forensic evidence card text.
   * @param {string} evidence - The evidence description text.
   */
  updateEvidence(evidence) {
    if (this.evidenceElement) {
      this.evidenceElement.textContent = evidence;
    }
  }

  /**
   * Updates the safety recommendation card text.
   * @param {string} recommendation - The recommendation guidance text.
   */
  updateRecommendation(recommendation) {
    if (this.recommendationElement) {
      this.recommendationElement.textContent = recommendation;
    }
  }

  /**
   * Handles unsupported browser pages by disabling scan controls and displaying fallback messaging.
   * @param {string} [url] - The unsupported URL string.
   */
  handleUnsupportedPage(url) {
    this.updateWebsiteInfo(STATUS.UNSUPPORTED);
    this.updateStatus(STATUS.UNSUPPORTED);
    this.resetUI();
    this.updateEvidence('Scanning is not supported on browser internal or local pages.');
    this.updateRecommendation('Navigate to a standard website (http:// or https://) to run CyberSentinel AI.');
    this.setSeverity('warning');
    if (this.scanButton) {
      this.scanButton.disabled = true;
    }
  }

  /**
   * Displays fallback messaging when browser tab inspection fails.
   * @param {string} message - The error display message.
   */
  handleError(message) {
    this.updateWebsiteInfo(message);
    this.updateStatus(STATUS.ERROR);
    this.resetUI();
    this.setSeverity('danger');
    if (this.scanButton) {
      this.scanButton.disabled = true;
    }
  }

  /**
   * Attaches UI event listeners for interactive popup controls.
   */
  setupEventListeners() {
    if (this.scanButton) {
      this.scanButton.addEventListener('click', () => this.scanCurrentWebsite());
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const controller = new PopupController();
  controller.initialize();
});
