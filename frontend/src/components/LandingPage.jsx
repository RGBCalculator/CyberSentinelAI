import React, { useState } from 'react';

const LandingPage = ({ onGetStarted, onLogin, onOpenDemo }) => {
  const [demoUrl, setDemoUrl] = useState('https://secure.bank-example.com');
  const [demoStatus, setDemoStatus] = useState('idle'); // 'idle' | 'scanning' | 'complete'

  const handleDemoScan = (e) => {
    e.preventDefault();
    if (!demoUrl.trim()) return;
    setDemoStatus('scanning');
    setTimeout(() => {
      setDemoStatus('complete');
    }, 900);
  };

  return (
    <div className="landing-page-root">
      {/* Top Public Navigation Bar */}
      <header className="landing-navbar">
        <div className="landing-nav-container">
          <div className="landing-brand">
            <span className="brand-shield-icon">🛡️</span>
            <span className="brand-name">CyberSentinel<span className="brand-accent">AI</span></span>
          </div>

          <nav className="landing-nav-links">
            <a href="#features" className="landing-nav-link">Features</a>
            <a href="#how-it-works" className="landing-nav-link">How it works</a>
            <a href="#preview" className="landing-nav-link">Demo</a>
          </nav>

          <div className="landing-nav-actions">
            <button 
              type="button" 
              className="btn-outline-landing"
              onClick={onLogin}
            >
              Log in
            </button>
            <button 
              type="button" 
              className="btn-primary-landing"
              onClick={onGetStarted}
            >
              Get started
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="landing-main">
        <section className="landing-hero-section">
          <div className="hero-content">
            <div className="hero-badge">
              <span className="hero-badge-dot"></span>
              <span>AI-POWERED WEBSITE THREAT SCANNING & SOC PLATFORM</span>
            </div>

            <h1 className="hero-headline">
              Check websites for security risks
            </h1>

            <p className="hero-subtitle">
              Enterprise-grade URL threat scanning, deep SSL/TLS certificate auditing, and AI-powered phishing detection. Analyze any website for malicious redirects, credential harvesting, and security posture in real time.
            </p>

            <div className="hero-cta-group">
              <button 
                type="button" 
                className="btn-primary-landing btn-hero-lg"
                onClick={onGetStarted}
              >
                Get started ➔
              </button>
              <button 
                type="button" 
                className="btn-outline-landing btn-hero-lg"
                onClick={onOpenDemo}
              >
                See product demo
              </button>
            </div>
          </div>

          {/* Interactive UI Composition Preview (matches reference image layout) */}
          <div id="preview" className="hero-preview-container">
            <div className="preview-window-frame">
              {/* Window Header */}
              <div className="window-header-bar">
                <div className="window-controls">
                  <span className="dot dot-red"></span>
                  <span className="dot dot-amber"></span>
                  <span className="dot dot-green"></span>
                </div>
                <div className="window-title-address font-mono">
                  https://app.cybersentinel.ai/soc/overview
                </div>
                <div className="window-status-tag">
                  ● LIVE SENSOR
                </div>
              </div>

              {/* Window Inner SOC Dashboard Preview */}
              <div className="window-inner-dashboard">
                {/* Simulated Quick Scanner Bar */}
                <form onSubmit={handleDemoScan} className="preview-scanner-bar">
                  <div className="preview-input-wrap">
                    <span className="preview-input-icon">🔍</span>
                    <input 
                      type="text" 
                      value={demoUrl}
                      onChange={(e) => setDemoUrl(e.target.value)}
                      placeholder="Enter any domain or URL to inspect..."
                      className="preview-url-input"
                    />
                  </div>
                  <button 
                    type="submit" 
                    className="btn-primary-landing preview-scan-btn"
                    disabled={demoStatus === 'scanning'}
                  >
                    {demoStatus === 'scanning' ? 'Inspecting...' : 'Scan Website'}
                  </button>
                </form>

                {demoStatus === 'complete' && (
                  <div className="preview-live-verdict mt-3">
                    <span className="verdict-chip safe">✓ VERIFIED SAFE</span>
                    <span className="verdict-detail">TLS 1.3 | Encrypted Transport | Clean Reputation | 0 Phishing Anomaly</span>
                  </div>
                )}

                {/* Simulated KPI Grid */}
                <div className="preview-kpi-row">
                  <div className="preview-kpi-card">
                    <span className="kpi-label">TOTAL SCANS</span>
                    <span className="kpi-num">1,428</span>
                    <span className="kpi-sub text-muted">Across 85 assets</span>
                  </div>
                  <div className="preview-kpi-card">
                    <span className="kpi-label">COMPLETED</span>
                    <span className="kpi-num text-success">1,390</span>
                    <span className="kpi-sub text-muted">97.3% success</span>
                  </div>
                  <div className="preview-kpi-card">
                    <span className="kpi-label">PARTIAL</span>
                    <span className="kpi-num text-warning">26</span>
                    <span className="kpi-sub text-muted">Warnings logged</span>
                  </div>
                  <div className="preview-kpi-card">
                    <span className="kpi-label">FAILED / BLOCKED</span>
                    <span className="kpi-num text-error">12</span>
                    <span className="kpi-sub text-muted">SSRF / Threats</span>
                  </div>
                </div>

                {/* Simulated Findings & Activity Preview */}
                <div className="preview-content-split">
                  <div className="preview-findings-box">
                    <div className="preview-box-header">
                      <span>FINDINGS BY SEVERITY</span>
                      <span className="text-muted text-xs">4 Active</span>
                    </div>
                    <div className="preview-sev-chips">
                      <div className="preview-sev-chip critical">
                        <span className="sev-dot red"></span>
                        <span>Critical: 1</span>
                      </div>
                      <div className="preview-sev-chip high">
                        <span className="sev-dot orange"></span>
                        <span>High: 1</span>
                      </div>
                      <div className="preview-sev-chip medium">
                        <span className="sev-dot amber"></span>
                        <span>Medium: 2</span>
                      </div>
                      <div className="preview-sev-chip low">
                        <span className="sev-dot teal"></span>
                        <span>Low: 0</span>
                      </div>
                    </div>
                    <div className="preview-sample-finding">
                      <div className="finding-top">
                        <span className="badge-crit">CRITICAL</span>
                        <span className="font-mono text-muted text-xs">CVE-2024-SQLI</span>
                      </div>
                      <div className="finding-name">SQL Injection in User Authentication Endpoint</div>
                      <div className="finding-target font-mono text-xs text-muted">auth/login.py:L42</div>
                    </div>
                  </div>

                  <div className="preview-recent-box">
                    <div className="preview-box-header">
                      <span>RECENT TARGET AUDITS</span>
                      <span className="text-cyan text-xs cursor-pointer" onClick={onOpenDemo}>OPEN DASHBOARD ➔</span>
                    </div>
                    <div className="preview-recent-list">
                      <div className="preview-recent-item">
                        <span className="recent-target font-mono">https://github.com</span>
                        <span className="recent-status status-pill ready">COMPLETED</span>
                        <span className="recent-score text-success">SAFE</span>
                      </div>
                      <div className="preview-recent-item">
                        <span className="recent-target font-mono">https://expired.badssl.com</span>
                        <span className="recent-status status-pill warning">TEST CASE</span>
                        <span className="recent-score text-error">EXPIRED</span>
                      </div>
                      <div className="preview-recent-item">
                        <span className="recent-target font-mono">https://internal-finance-api</span>
                        <span className="recent-status status-pill ready">COMPLETED</span>
                        <span className="recent-score text-warning">HIGH RISK</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* How It Works Section */}
        <section id="how-it-works" className="landing-section">
          <div className="section-header-center">
            <span className="section-tag">SIMPLIFIED WORKFLOW</span>
            <h2 className="section-heading">How CyberSentinel AI Works</h2>
            <p className="section-desc">
              Three streamlined steps from URL submission to forensic evidence and actionable remediation.
            </p>
          </div>

          <div className="how-it-works-grid">
            <div className="step-card">
              <div className="step-number">01</div>
              <div className="step-icon-wrap">🌐</div>
              <h3 className="step-title">Enter a URL</h3>
              <p className="step-desc">
                Submit any domain or website to initiate multi-stage cryptographic and architectural audits. All targets are pre-validated by the hardened SSRF firewall.
              </p>
            </div>

            <div className="step-card">
              <div className="step-number">02</div>
              <div className="step-icon-wrap">⚡</div>
              <h3 className="step-title">Run security checks</h3>
              <p className="step-desc">
                Automated multi-engine evaluation: X.509 certificate validation, DNS authoritative lookups, HTTP security headers, brand impersonation, and threat feeds.
              </p>
            </div>

            <div className="step-card">
              <div className="step-number">03</div>
              <div className="step-icon-wrap">📊</div>
              <h3 className="step-title">Review evidence & remediation</h3>
              <p className="step-desc">
                Inspect structured vulnerability findings, explainable feature weights, forensic indicators, and concrete remediation recommendations.
              </p>
            </div>
          </div>
        </section>

        {/* Features Grid */}
        <section id="features" className="landing-section">
          <div className="section-header-center">
            <span className="section-tag">ENGINEERED FOR MODERN SOC TEAMS</span>
            <h2 className="section-heading">Comprehensive Security Capabilities</h2>
            <p className="section-desc">
              Unifying network perimeter defense, certificate validation, and threat detection into one interface.
            </p>
          </div>

          <div className="features-grid">
            <div className="feature-card">
              <div className="feature-icon">🔍</div>
              <h3 className="feature-title">Real-Time URL Threat Scanner</h3>
              <p className="feature-desc">
                Multi-stage scanning pipeline analyzing domain structure, redirections, and known indicators of compromise with live stage progress.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🔐</div>
              <h3 className="feature-title">Deep SSL/TLS Cryptographic Audit</h3>
              <p className="feature-desc">
                Full X.509 inspection: SANs, SHA-256 fingerprints, expiry countdowns, key algorithms, cipher suites, and HTTP-to-HTTPS redirect testing.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🛡️</div>
              <h3 className="feature-title">Heuristic Phishing & Fake Login Detector</h3>
              <p className="feature-desc">
                Sandboxed DOM inspection detecting brand impersonation (Microsoft, Google, Apple, etc.), cross-origin form actions, and raw IP destinations.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🌐</div>
              <h3 className="feature-title">Multi-Source Threat Intelligence Hub</h3>
              <p className="feature-desc">
                Aggregated intelligence connectors for VirusTotal, PhishTank, OpenPhish, and AbuseIPDB with in-memory TTL caching and honest provider status.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">🧠</div>
              <h3 className="feature-title">Explainable Risk Scoring</h3>
              <p className="feature-desc">
                Transparent feature attribution and deterministic risk scoring. Understand exactly which signals contributed to an anomaly verdict.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon">📑</div>
              <h3 className="feature-title">Executive Reports & Data Export</h3>
              <p className="feature-desc">
                Download structured JSON audit logs and generate printable executive reports for compliance reviews and security audits.
              </p>
            </div>
          </div>
        </section>

        {/* Controlled Certificate Test Cases Notice */}
        <section className="landing-section test-cases-banner-section">
          <div className="test-cases-promo-box">
            <div className="promo-badge">CONTROLLED TESTING</div>
            <h3>Test Against Deliberately Misconfigured Targets</h3>
            <p>
              Verify your security tools safely using the officially maintained BadSSL test targets. Inspect expired certificates, self-signed origins, hostname mismatches, and unencrypted plaintext HTTP without probing live hostile hosts.
            </p>
            <button 
              type="button" 
              className="btn-primary-landing"
              onClick={onOpenDemo}
            >
              Try BadSSL Test Targets in SOC ➔
            </button>
          </div>
        </section>
      </main>

      {/* Footer */}
      <footer className="landing-footer">
        <div className="landing-footer-container">
          <div className="footer-brand">
            <span className="brand-shield-icon">🛡️</span>
            <span className="brand-name">CyberSentinelAI</span>
            <p className="footer-tagline">AI-Powered Cybersecurity Platform & Unified SOC</p>
          </div>
          <div className="footer-right">
            <div className="footer-system-status">
              <span className="pulse-dot"></span>
              <span>All Systems Operational</span>
            </div>
            <p className="text-muted text-xs mt-2">
              CyberSentinel AI SOC 2.2 — Authorized Defensive Security Testing
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
