import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const SAMPLE_URLS = [
  { label: 'Raw IP Host (Phishing)', url: 'http://192.168.1.1:8080/secure/login.php?user=admin' },
  { label: 'Credential Keyword in Query', url: 'https://bank-portal.com/login?redirect=verify-account' },
  { label: 'Clean Benchmark', url: 'https://example.com' }
];

const UrlScannerView = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [history, setHistory] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);

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
  }, []);

  const handleScan = async (e) => {
    if (e) e.preventDefault();
    const url = targetUrl.trim();
    if (!url) {
      setError("Please specify a target URL.");
      return;
    }

    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      setError("Target URL must begin with 'http://' or 'https://'");
      return;
    }

    setError(null);
    setScanning(true);
    setScanResult(null);

    try {
      const result = await api.scanUrl(url);
      setScanResult(result);
      fetchHistory(); // Refresh scan history
    } catch (err) {
      setError(err.message || "Scan execution failed.");
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
    } catch (err) {
      setError("Failed to load historical scan report.");
    } finally {
      setScanning(false);
    }
  };

  return (
    <div className="url-scanner-view">
      <div className="view-header">
        <div>
          <h2>ADVANCED URL & WEB ASSET THREAT SCANNER</h2>
          <p className="text-muted">Multi-layered static feature extraction, rule evaluation, threat intelligence, and explainable ML inference.</p>
        </div>
      </div>

      {/* Target Input Console */}
      <section className="panel mt-4">
        <form onSubmit={handleScan} className="scanner-form">
          <div className="form-group">
            <label htmlFor="target-url-input">INSPECT TARGET URL (HTTP/HTTPS)</label>
            <div className="scanner-input-group">
              <input
                id="target-url-input"
                type="text"
                placeholder="https://example.com/login"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                className="scanner-input"
                disabled={scanning}
              />
              <button 
                type="submit" 
                disabled={scanning} 
                className="btn-primary scanner-btn"
              >
                {scanning ? 'SCANNING PIPELINE...' : 'EXECUTE THREAT SCAN'}
              </button>
            </div>
          </div>
        </form>

        {/* Quick Pick Samples */}
        <div className="sample-picks mt-4">
          <span className="text-muted text-sm">PRESET AUDIT SAMPLES:</span>
          {SAMPLE_URLS.map(sample => (
            <button
              key={sample.label}
              type="button"
              className="btn-outline btn-sm"
              onClick={() => {
                setTargetUrl(sample.url);
                setError(null);
              }}
              disabled={scanning}
            >
              {sample.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="api-response error mt-4">
            <h4>SCANNER ALERT</h4>
            <pre>{error}</pre>
          </div>
        )}
      </section>

      {/* Scanning In-Flight Animation */}
      {scanning && (
        <div className="panel loading-state mt-4">
          <p className="neon-text blink">SECURITY SCAN IN PROGRESS...</p>
          <div className="scanning-steps mt-4">
            <span className="step-tag active">1. VALIDATION</span>
            <span className="step-tag active">2. FEATURE EXTRACTION</span>
            <span className="step-tag active">3. THREAT INTEL</span>
            <span className="step-tag active">4. XAI INFERENCE</span>
            <span className="step-tag active">5. AGGREGATING SCORES</span>
          </div>
        </div>
      )}

      {/* Scan Results Display */}
      {scanResult && (
        <div className="scan-results-container mt-4">
          {/* Top Verdict Bar */}
          <section className="panel verdict-panel">
            <div className="verdict-header">
              <div>
                <span className="verdict-label text-muted">TARGET EVALUATED:</span>
                <h3 className="verdict-target font-mono text-cyan">{scanResult.target || targetUrl}</h3>
                <span className="text-muted text-sm font-mono">SCAN ID: {scanResult.scan_id} • DURATION: {scanResult.execution_duration}s</span>
              </div>
              <div className="verdict-badge-box">
                <span className="text-muted text-sm block">THREAT CLASSIFICATION</span>
                <span className={`verdict-pill ${scanResult.risk_level.toLowerCase()}`}>
                  {scanResult.risk_level.toUpperCase()}
                </span>
              </div>
            </div>

            <div className="verdict-metrics-row mt-4">
              <div className="v-metric">
                <span className="v-metric-label">COMPUTED RISK SCORE</span>
                <span className={`v-metric-val ${scanResult.risk_score > 70 ? 'critical' : scanResult.risk_score > 35 ? 'warning' : 'safe'}`}>
                  {scanResult.risk_score} / 100
                </span>
              </div>
              <div className="v-metric">
                <span className="v-metric-label">DETECTED FINDINGS</span>
                <span className="v-metric-val">{scanResult.findings ? scanResult.findings.length : 0}</span>
              </div>
              <div className="v-metric">
                <span className="v-metric-label">THREAT INTEL VERDICT</span>
                <span className="v-metric-val text-accent">
                  {(scanResult.threat_intel?.verdict || 'clean').toUpperCase()}
                </span>
              </div>
              <div className="v-metric">
                <span className="v-metric-label">AI PREDICTION</span>
                <span className="v-metric-val text-warning">
                  {(scanResult.ai_analysis?.prediction || 'benign').toUpperCase()}
                </span>
              </div>
            </div>
          </section>

          {/* Two-Column Deep Dive: Threat Intel & Explainable AI */}
          <div className="detail-grid mt-4">
            {/* Left: Multi-Source Threat Intelligence */}
            <section className="panel">
              <h3>THREAT INTELLIGENCE RESULTS</h3>
              <p className="text-muted mb-4">Live querying across external intelligence providers.</p>

              {scanResult.threat_intel?.providers ? (
                <div className="provider-results-grid">
                  {Object.entries(scanResult.threat_intel.providers).map(([key, p]) => (
                    <div key={key} className="provider-card">
                      <div className="provider-card-header">
                        <span className="font-bold">{p.name || key}</span>
                        <span className={`status-pill ${p.status === 'malicious' ? 'critical' : p.status === 'unconfigured' ? 'unconfigured' : 'ready'}`}>
                          {p.status.toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-muted mt-2">{p.details || 'No threat flagged.'}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-muted text-sm">Threat intelligence aggregation summary: {JSON.stringify(scanResult.threat_intel)}</div>
              )}
            </section>

            {/* Right: Explainable AI (XAI) Attribution */}
            <section className="panel">
              <div className="panel-header-row">
                <h3>EXPLAINABLE AI ATTRIBUTION</h3>
                <span className="demo-badge">ML INFERENCE</span>
              </div>
              <p className="text-muted mb-4">
                Model: <span className="font-mono text-cyan">{scanResult.ai_analysis?.model_metadata?.model_name || 'CyberSentinel-XGB'}</span> (Confidence: {Math.round((scanResult.ai_analysis?.confidence || 0) * 100)}%)
              </p>

              {scanResult.ai_analysis?.top_features && scanResult.ai_analysis.top_features.length > 0 ? (
                <div className="xai-features-list">
                  {scanResult.ai_analysis.top_features.map((feat, idx) => (
                    <div key={idx} className="xai-feature-row">
                      <div className="xai-feat-header">
                        <span className="font-bold text-sm">{feat.feature}</span>
                        <span className={`feat-weight ${feat.weight > 0 ? 'text-red' : 'text-green'}`}>
                          {feat.weight > 0 ? `+${feat.weight}` : feat.weight}
                        </span>
                      </div>
                      <p className="text-sm text-muted">{feat.explanation}</p>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-muted text-sm">Standard lexical baseline verified. No high-weight adversarial features detected.</p>
              )}
            </section>
          </div>

          {/* Findings & Evidence Details */}
          <section className="panel mt-4">
            <h3>DISCOVERED SECURITY FINDINGS & EVIDENCE</h3>
            <p className="text-muted mb-4">Granular indicators and technical evidence identified by the scanning pipeline.</p>

            {(!scanResult.findings || scanResult.findings.length === 0) ? (
              <div className="empty-state">
                <p className="text-muted">No security findings or anomalous heuristics identified on this target.</p>
              </div>
            ) : (
              <div className="findings-list">
                {scanResult.findings.map(finding => (
                  <div key={finding.id} className="finding-card">
                    <div className="finding-header">
                      <span className={`severity-badge ${finding.severity ? finding.severity.toLowerCase() : 'low'}`}>
                        {typeof finding.severity === 'string' ? finding.severity.toUpperCase() : finding.severity?.value || 'MEDIUM'}
                      </span>
                      <span className="rule-badge">{finding.category}</span>
                      <span className="finding-risk">CONFIDENCE: {Math.round((finding.confidence || 1) * 100)}%</span>
                    </div>
                    <h4 className="finding-title">{finding.title}</h4>
                    <p className="finding-desc">{finding.description}</p>
                    
                    {finding.evidence && finding.evidence.length > 0 && (
                      <div className="evidence-box mt-2">
                        <span className="text-xs text-muted block mb-1">EVIDENCE SOURCE: {finding.evidence[0].source}</span>
                        <pre className="code-snippet"><code>{finding.evidence[0].raw_value}</code></pre>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </section>
        </div>
      )}

      {/* Historical Scans Table */}
      <section className="panel mt-4">
        <div className="panel-header-row">
          <h3>PERSISTED SCAN AUDIT LOG</h3>
          <button onClick={fetchHistory} disabled={loadingHistory} className="btn-outline btn-sm">
            {loadingHistory ? 'LOADING...' : '↻ REFRESH HISTORY'}
          </button>
        </div>

        {history.length > 0 ? (
          <div className="table-responsive mt-4">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>SCAN ID</th>
                  <th>TARGET</th>
                  <th>SEVERITY</th>
                  <th>SCORE</th>
                  <th>FINDINGS</th>
                  <th>TIME</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {history.map(item => (
                  <tr key={item.scan_id}>
                    <td className="font-mono text-muted">{item.scan_id.slice(0, 8)}...</td>
                    <td className="font-mono text-cyan truncate-cell">{item.target}</td>
                    <td>
                      <span className={`severity-badge ${item.risk_level.toLowerCase()}`}>
                        {item.risk_level.toUpperCase()}
                      </span>
                    </td>
                    <td className="font-mono font-bold">{item.risk_score}</td>
                    <td>{item.findings_count} issues</td>
                    <td className="text-muted">{new Date(item.created_at).toLocaleTimeString()}</td>
                    <td>
                      <button 
                        onClick={() => loadHistoricalScan(item.scan_id)}
                        className="btn-outline btn-xs"
                      >
                        VIEW
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state mt-4">
            <p className="text-muted">No prior scans in database. Run a scan above to start building historical telemetry.</p>
          </div>
        )}
      </section>
    </div>
  );
};

export default UrlScannerView;
