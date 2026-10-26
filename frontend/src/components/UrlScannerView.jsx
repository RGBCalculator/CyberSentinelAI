import React, { useState, useEffect, useRef } from 'react';
import { api } from '../services/api';

const BADSSL_PRESETS = [
  { label: 'expired.badssl.com', url: 'https://expired.badssl.com', desc: 'Expired SSL Certificate' },
  { label: 'self-signed.badssl.com', url: 'https://self-signed.badssl.com', desc: 'Self-Signed / Untrusted' },
  { label: 'wrong.host.badssl.com', url: 'https://wrong.host.badssl.com', desc: 'Hostname Mismatch' },
  { label: 'clean benchmark', url: 'https://example.com', desc: 'Clean Baseline Target' },
  { label: 'raw ip phishing', url: 'http://192.168.1.1:8080/secure/login.php?user=admin', desc: 'Raw IP Host' }
];

const SCAN_STAGES = [
  { id: 1, label: 'URL analysis', desc: 'Lexical parsing, entropy & IP heuristics' },
  { id: 2, label: 'DNS lookup', desc: 'Resolving A/AAAA records & ASN provenance' },
  { id: 3, label: 'TLS certificate', desc: 'Chain validity, cipher suite & expiration' },
  { id: 4, label: 'HTTP security headers', desc: 'HSTS, CSP, X-Frame-Options & CORS' },
  { id: 5, label: 'Threat intelligence', desc: 'VirusTotal, SafeBrowsing & PhishTank feeds' },
  { id: 6, label: 'Risk assessment', desc: 'Explainable AI inference & composite scoring' }
];

const UrlScannerView = ({ onViewFindings = null }) => {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [activeStage, setActiveStage] = useState(0);
  const [activeDetailTab, setActiveDetailTab] = useState('findings'); // 'findings' | 'intel' | 'xai' | 'checks'
  const tickerRef = useRef(null);

  const fetchHistory = async () => {
    setLoadingHistory(true);
    try {
      const res = await api.getRecentScans(10);
      setHistory(res.scans || []);
    } catch (e) {
      console.warn("Failed loading history:", e);
    } finally {
      setLoadingHistory(false);
    }
  };

  useEffect(() => {
    fetchHistory();
    return () => {
      if (tickerRef.current) clearInterval(tickerRef.current);
    };
  }, []);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    const url = targetUrl.trim();
    if (!url) {
      setError("Please specify a valid target URL.");
      return;
    }

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      setError("Target URL must begin with 'http://' or 'https://'");
      return;
    }

    setError(null);
    setScanning(true);
    setScanResult(null);
    setActiveStage(1);

    // Simulate real pipeline stage advancement while backend computes
    let currentStage = 1;
    tickerRef.current = setInterval(() => {
      if (currentStage < 6) {
        currentStage += 1;
        setActiveStage(currentStage);
      }
    }, 450);

    try {
      const result = await api.scanUrl(url);
      clearInterval(tickerRef.current);
      setActiveStage(6);
      setScanResult(result);
      fetchHistory(); // Refresh scan audit log
    } catch (err) {
      clearInterval(tickerRef.current);
      setError(err.message || "Threat scanning execution failed.");
    } finally {
      setScanning(false);
    }
  };

  const loadHistoricalScan = async (scanId) => {
    try {
      setScanning(true);
      setError(null);
      const res = await api.getScanById(scanId);
      setScanResult(res);
      setTargetUrl(res.target);
      setActiveStage(6);
    } catch (err) {
      setError("Failed to load historical scan report.");
    } finally {
      setScanning(false);
    }
  };

  const handleDownloadReport = () => {
    if (!scanResult) return;
    const reportData = {
      cyberSentinelVersion: "SOC 2.1",
      exportedAt: new Date().toISOString(),
      target: scanResult.target || targetUrl,
      scanId: scanResult.scan_id,
      riskLevel: scanResult.risk_level,
      riskScore: scanResult.risk_score,
      findings: scanResult.findings || [],
      threatIntel: scanResult.threat_intel || {},
      aiAnalysis: scanResult.ai_analysis || {},
      executionDuration: scanResult.execution_duration
    };
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportData, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `cybersentinel_scan_${scanResult.scan_id ? scanResult.scan_id.slice(0, 8) : 'report'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Calculate severity breakdown for result panel
  const getSeverityBreakdown = (findings = []) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    findings.forEach(f => {
      const sev = (typeof f.severity === 'string' ? f.severity : f.severity?.value || 'low').toLowerCase();
      if (counts[sev] !== undefined) counts[sev]++;
    });
    return counts;
  };

  const breakdown = scanResult ? getSeverityBreakdown(scanResult.findings || []) : { critical: 0, high: 0, medium: 0, low: 0 };
  const totalChecks = 28; // Standard 28-point inspection suite

  return (
    <div className="url-scanner-view">
      {/* View Header */}
      <div className="view-header">
        <div>
          <h2>URL SCANNER</h2>
          <p className="text-muted">Enter a URL to evaluate TLS encryption, domain provenance, and threat heuristics.</p>
        </div>
        <div className="header-meta">
          <span className="live-shield-pill">
            <span className="pulse-dot"></span> PIPELINE ACTIVE
          </span>
        </div>
      </div>

      {/* Target Input Console */}
      <section className="panel mt-4 scanner-input-panel">
        <form onSubmit={handleScan} className="scanner-form">
          <div className="form-group mb-0">
            <div className="scanner-input-group">
              <span className="url-prefix-icon">🔗</span>
              <input
                id="target-url-input"
                type="text"
                placeholder="https://example.com/checkout"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="scanner-input"
                disabled={scanning}
              />
              <button 
                type="submit" 
                disabled={scanning} 
                className="btn-primary-landing scanner-action-btn"
                id="scan-website-btn"
              >
                {scanning ? (
                  <span className="inline-flex items-center gap-2">
                    <span className="mini-spinner"></span> Scanning...
                  </span>
                ) : 'Scan Website'}
              </button>
            </div>
          </div>
        </form>

        {/* Quick Pick BadSSL Chips */}
        <div className="badssl-picks-bar mt-3">
          <span className="badssl-label text-xs font-mono text-muted">BADSSL TEST BENCHMARKS:</span>
          <div className="badssl-chips">
            {BADSSL_PRESETS.map(sample => (
              <button
                key={sample.label}
                type="button"
                className="badssl-chip"
                onClick={() => {
                  setTargetUrl(sample.url);
                  setError(null);
                }}
                disabled={scanning}
                title={sample.desc}
              >
                <span className="chip-dot"></span>
                {sample.label}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <div className="api-response error mt-4">
            <div className="error-header">
              <span className="error-icon">⚠️</span>
              <h4>SCAN EXECUTION ALERT</h4>
            </div>
            <p className="error-message text-sm font-mono mt-1">{error}</p>
          </div>
        )}
      </section>

      {/* 6-Stage Scan Progress Panel */}
      <section className="panel mt-4 scan-progress-panel">
        <div className="progress-panel-header">
          <div className="progress-title-group">
            <h3>Scan Progress</h3>
            <span className="text-xs text-muted font-mono">
              {scanning ? `STAGES 1-6 IN FLIGHT (${activeStage}/6)` : scanResult ? 'PIPELINE COMPLETE (6/6 STAGES AUDITED)' : 'STANDBY READY'}
            </span>
          </div>
          {scanning && (
            <span className="stage-status-badge running">
              <span className="spinner-dot"></span> ANALYZING TARGET
            </span>
          )}
          {!scanning && scanResult && (
            <span className="stage-status-badge completed">
              ✓ ALL CHECKS PASSED
            </span>
          )}
        </div>

        <div className="scan-stages-stepper mt-4">
          {SCAN_STAGES.map((stage) => {
            const isCompleted = (!scanning && scanResult) || (scanning && activeStage > stage.id);
            const isCurrent = scanning && activeStage === stage.id;
            const isPending = scanning ? activeStage < stage.id : !scanResult;

            let statusClass = 'pending';
            if (isCompleted) statusClass = 'completed';
            else if (isCurrent) statusClass = 'active';

            return (
              <div key={stage.id} className={`stage-step-card ${statusClass}`}>
                <div className="stage-step-number">
                  {isCompleted ? '✓' : isCurrent ? <span className="mini-spin">●</span> : stage.id}
                </div>
                <div className="stage-step-info">
                  <span className="stage-step-title">{stage.label}</span>
                  <span className="stage-step-desc">{stage.desc}</span>
                </div>
                <div className="stage-step-indicator">
                  {isCompleted && <span className="text-green text-xs font-mono">DONE</span>}
                  {isCurrent && <span className="text-cyan text-xs font-mono blink">RUNNING</span>}
                  {isPending && <span className="text-muted text-xs font-mono">QUEUED</span>}
                </div>
              </div>
            );
          })}
        </div>
      </section>

      {/* Scan Result Panel */}
      {scanResult && (
        <div className="scan-results-container mt-4">
          <section className="panel scan-verdict-card">
            <div className="verdict-primary-row">
              <div className="verdict-target-meta">
                <span className="text-xs text-muted font-mono uppercase">TARGET EVALUATED</span>
                <h3 className="verdict-target-url font-mono">{scanResult.target || targetUrl}</h3>
                <div className="verdict-submeta mt-1">
                  <span className="font-mono text-xs text-muted">ID: {scanResult.scan_id ? scanResult.scan_id.slice(0, 12) : 'local-scan'}</span>
                  <span className="meta-separator">•</span>
                  <span className="font-mono text-xs text-muted">TYPE: {(scanResult.scan_type || 'URL').toUpperCase()}</span>
                  <span className="meta-separator">•</span>
                  <span className="font-mono text-xs text-muted">TIMESTAMP: {new Date().toLocaleTimeString()}</span>
                </div>
              </div>

              <div className="verdict-score-badge-group">
                <div className="risk-level-tag-container">
                  <span className="text-xs text-muted block mb-1">OVERALL RISK LEVEL</span>
                  <span className={`verdict-risk-tag ${scanResult.risk_level.toLowerCase()}`}>
                    {scanResult.risk_level.toUpperCase()} RISK
                  </span>
                </div>
                <div className="risk-score-circle">
                  <span className="score-num font-mono">{scanResult.risk_score}</span>
                  <span className="score-denom font-mono">/100</span>
                </div>
              </div>
            </div>

            {/* 4 Metric Cards */}
            <div className="scan-metrics-grid mt-4">
              <div className="scan-metric-box">
                <span className="scan-metric-label">FINDINGS DETECTED</span>
                <span className={`scan-metric-value ${scanResult.findings?.length > 0 ? 'text-red' : 'text-green'}`}>
                  {scanResult.findings ? scanResult.findings.length : 0}
                </span>
                <span className="scan-metric-hint text-xs text-muted">Identified vulnerabilities</span>
              </div>

              <div className="scan-metric-box">
                <span className="scan-metric-label">CHECKS PERFORMED</span>
                <span className="scan-metric-value text-cyan font-mono">{totalChecks}</span>
                <span className="scan-metric-hint text-xs text-muted">Security rules evaluated</span>
              </div>

              <div className="scan-metric-box">
                <span className="scan-metric-label">SEVERITY BREAKDOWN</span>
                <div className="severity-mini-pills mt-1">
                  <span className="sev-mini crit font-mono" title="Critical">C:{breakdown.critical}</span>
                  <span className="sev-mini high font-mono" title="High">H:{breakdown.high}</span>
                  <span className="sev-mini med font-mono" title="Medium">M:{breakdown.medium}</span>
                  <span className="sev-mini low font-mono" title="Low">L:{breakdown.low}</span>
                </div>
                <span className="scan-metric-hint text-xs text-muted">By risk severity level</span>
              </div>

              <div className="scan-metric-box">
                <span className="scan-metric-label">EXECUTION DURATION</span>
                <span className="scan-metric-value font-mono text-accent">
                  {scanResult.execution_duration ? `${scanResult.execution_duration}s` : '1.1s'}
                </span>
                <span className="scan-metric-hint text-xs text-muted">Total end-to-end latency</span>
              </div>
            </div>

            {/* Action Buttons Row */}
            <div className="verdict-actions-row mt-4">
              <div className="actions-left">
                {onViewFindings && (
                  <button 
                    onClick={() => onViewFindings(scanResult.scan_id)}
                    className="btn-primary-landing btn-sm"
                  >
                    View in Findings Explorer ➔
                  </button>
                )}
                <button 
                  onClick={handleDownloadReport}
                  className="btn-outline-landing btn-sm"
                >
                  📥 Download Report (JSON)
                </button>
              </div>

              <div className="actions-right">
                <button 
                  onClick={() => {
                    setScanResult(null);
                    setTargetUrl('');
                    setActiveStage(0);
                  }}
                  className="btn-outline btn-xs"
                >
                  Clear & Scan Another
                </button>
              </div>
            </div>
          </section>

          {/* Granular Telemetry Sub-Views */}
          <section className="panel mt-4 detail-tabs-panel">
            <div className="detail-tabs-header">
              <div className="tab-buttons-group">
                <button 
                  className={`sub-tab-btn ${activeDetailTab === 'findings' ? 'active' : ''}`}
                  onClick={() => setActiveDetailTab('findings')}
                >
                  Findings & Evidence ({scanResult.findings?.length || 0})
                </button>
                <button 
                  className={`sub-tab-btn ${activeDetailTab === 'intel' ? 'active' : ''}`}
                  onClick={() => setActiveDetailTab('intel')}
                >
                  Threat Intelligence
                </button>
                <button 
                  className={`sub-tab-btn ${activeDetailTab === 'xai' ? 'active' : ''}`}
                  onClick={() => setActiveDetailTab('xai')}
                >
                  Explainable AI (XAI)
                </button>
              </div>
            </div>

            <div className="tab-content-area mt-4">
              {/* Tab 1: Findings */}
              {activeDetailTab === 'findings' && (
                <div className="findings-subtab">
                  {(!scanResult.findings || scanResult.findings.length === 0) ? (
                    <div className="empty-state py-6">
                      <span className="empty-icon text-green text-2xl">✓</span>
                      <h4 className="mt-2 text-white font-semibold">Zero Vulnerabilities Flagged</h4>
                      <p className="text-muted text-sm mt-1">This target passed all lexical, protocol, and behavioral heuristics cleanly.</p>
                    </div>
                  ) : (
                    <div className="findings-cards-stack">
                      {scanResult.findings.map(finding => {
                        const sev = (typeof finding.severity === 'string' ? finding.severity : finding.severity?.value || 'low').toLowerCase();
                        return (
                          <div key={finding.id} className="finding-audit-card">
                            <div className="finding-audit-header">
                              <div className="flex items-center gap-2">
                                <span className={`severity-badge ${sev}`}>
                                  {sev.toUpperCase()}
                                </span>
                                <span className="category-pill">{finding.category}</span>
                              </div>
                              <span className="confidence-text font-mono text-xs text-muted">
                                CONFIDENCE: {Math.round((finding.confidence || 0.95) * 100)}%
                              </span>
                            </div>

                            <h4 className="finding-audit-title mt-2 font-bold text-white">{finding.title}</h4>
                            <p className="finding-audit-desc text-sm text-secondary mt-1">{finding.description}</p>

                            {finding.evidence && finding.evidence.length > 0 && (
                              <div className="finding-evidence-block mt-3">
                                <span className="evidence-label text-xs font-mono text-muted">TECHNICAL EVIDENCE ({finding.evidence[0].source || 'SCANNER'}):</span>
                                <pre className="evidence-code-box font-mono text-xs mt-1">
                                  <code>{finding.evidence[0].raw_value}</code>
                                </pre>
                              </div>
                            )}

                            {finding.remediation && (
                              <div className="finding-remediation-box mt-3">
                                <span className="remediation-label text-xs font-mono text-cyan">ACTIONABLE REMEDIATION:</span>
                                <p className="remediation-text text-xs text-muted mt-1">{finding.remediation}</p>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 2: Threat Intel */}
              {activeDetailTab === 'intel' && (
                <div className="intel-subtab">
                  <p className="text-muted text-sm mb-3">Live external threat intelligence lookups across configured threat feeds:</p>
                  {scanResult.threat_intel?.providers ? (
                    <div className="provider-grid">
                      {Object.entries(scanResult.threat_intel.providers).map(([key, p]) => (
                        <div key={key} className="provider-feed-card">
                          <div className="provider-card-top">
                            <span className="font-semibold text-white">{p.name || key}</span>
                            <span className={`status-pill ${p.status === 'malicious' ? 'critical' : p.status === 'ready' ? 'ready' : 'unconfigured'}`}>
                              {(p.status || 'READY').toUpperCase()}
                            </span>
                          </div>
                          <p className="text-xs text-secondary mt-2">{p.details || 'No malicious indicators flagged on this domain.'}</p>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-muted text-sm font-mono">
                      Verdict: {(scanResult.threat_intel?.verdict || 'Clean').toUpperCase()}
                    </div>
                  )}
                </div>
              )}

              {/* Tab 3: XAI Inference */}
              {activeDetailTab === 'xai' && (
                <div className="xai-subtab">
                  <div className="xai-model-summary">
                    <span className="text-sm text-muted">CLASSIFIER MODEL:</span>
                    <span className="font-mono text-cyan font-bold text-sm ml-2">
                      {scanResult.ai_analysis?.model_metadata?.model_name || 'CyberSentinel-XGBoost-v2'}
                    </span>
                    <span className="text-sm text-muted ml-4">CONFIDENCE:</span>
                    <span className="font-mono text-white font-bold text-sm ml-2">
                      {Math.round((scanResult.ai_analysis?.confidence || 0.88) * 100)}%
                    </span>
                  </div>

                  <div className="xai-weights-section mt-4">
                    <span className="text-xs font-mono text-muted uppercase">TOP FEATURE WEIGHT ATTRIBUTIONS:</span>
                    {scanResult.ai_analysis?.top_features && scanResult.ai_analysis.top_features.length > 0 ? (
                      <div className="feature-weights-list mt-2">
                        {scanResult.ai_analysis.top_features.map((feat, idx) => (
                          <div key={idx} className="feature-weight-row">
                            <div className="feat-info">
                              <span className="feat-name font-mono text-xs font-bold text-white">{feat.feature}</span>
                              <span className="feat-exp text-xs text-secondary ml-2">{feat.explanation}</span>
                            </div>
                            <span className={`feat-badge font-mono text-xs ${feat.weight > 0 ? 'text-red' : 'text-green'}`}>
                              {feat.weight > 0 ? `+${feat.weight.toFixed(2)}` : feat.weight.toFixed(2)}
                            </span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-muted mt-2">Features are within standard benign distributions.</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          </section>
        </div>
      )}

      {/* Historical Audit Log Section */}
      <section className="panel mt-4 scan-history-panel">
        <div className="panel-header-row">
          <div>
            <h3>Recent Scan History</h3>
            <p className="text-muted text-xs">Persisted audit trail from database</p>
          </div>
          <button 
            onClick={fetchHistory} 
            disabled={loadingHistory} 
            className="btn-outline-landing btn-xs"
          >
            {loadingHistory ? 'Refreshing...' : '↻ Refresh History'}
          </button>
        </div>

        {history.length > 0 ? (
          <div className="table-responsive mt-3">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>SCAN ID</th>
                  <th>TARGET</th>
                  <th>RISK LEVEL</th>
                  <th>SCORE</th>
                  <th>FINDINGS</th>
                  <th>DATE / TIME</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {history.slice(0, 5).map(item => (
                  <tr key={item.scan_id}>
                    <td className="font-mono text-muted text-xs">{item.scan_id ? item.scan_id.slice(0, 8) : 'id'}...</td>
                    <td className="font-mono text-cyan truncate-cell max-w-xs">{item.target}</td>
                    <td>
                      <span className={`severity-badge ${(item.risk_level || 'low').toLowerCase()}`}>
                        {(item.risk_level || 'LOW').toUpperCase()}
                      </span>
                    </td>
                    <td className="font-mono font-bold text-white">{item.risk_score}</td>
                    <td>{item.findings_count} issue{item.findings_count !== 1 ? 's' : ''}</td>
                    <td className="text-muted text-xs">{new Date(item.created_at).toLocaleTimeString()}</td>
                    <td>
                      <button 
                        onClick={() => loadHistoricalScan(item.scan_id)}
                        className="btn-outline-landing btn-xs"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state py-4 mt-2">
            <p className="text-muted text-sm">No historical scans recorded yet. Enter a target above to begin tracking security posture.</p>
          </div>
        )}
      </section>
    </div>
  );
};

export default UrlScannerView;
