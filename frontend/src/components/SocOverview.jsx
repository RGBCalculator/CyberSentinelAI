import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const SocOverview = ({ onNavigate }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('24h');

  const fetchOverview = async () => {
    setLoading(true);
    setError(null);
    try {
      const overview = await api.getSocOverview();
      setData(overview);
    } catch (err) {
      setError(err.message || 'Failed to fetch SOC overview metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOverview();
  }, []);

  if (loading) {
    return (
      <div className="soc-view-loading panel">
        <p className="neon-text blink">INITIALIZING SOC TELEMETRY...</p>
        <p className="text-muted mt-4">Synthesizing threat intelligence, repository posture, and scanner telemetry...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="panel">
        <div className="api-response error">
          <h4>SOC TELEMETRY STREAM OFFLINE</h4>
          <pre>{error}</pre>
        </div>
        <button onClick={fetchOverview} className="btn-primary mt-4">RECONNECT TELEMETRY</button>
      </div>
    );
  }

  const posture = data?.security_posture || {};
  const scansSummary = data?.scans_summary || {};
  const threatIntel = data?.threat_intelligence || {};
  const findings = data?.findings_overview?.findings || [];
  const providers = threatIntel.providers || {};

  return (
    <div className="soc-overview">
      {/* Top Bar Controls */}
      <div className="soc-toolbar">
        <div>
          <h2 className="soc-title">SECURITY OPERATIONS COMMAND CENTER</h2>
          <p className="text-muted">Real-time threat monitoring, posture analytics, and automated detection engines.</p>
        </div>
        <div className="soc-controls">
          <div className="time-range-selector">
            {['24h', '7d', '30d', 'all'].map(range => (
              <button
                key={range}
                type="button"
                className={`time-btn ${timeRange === range ? 'active' : ''}`}
                onClick={() => setTimeRange(range)}
              >
                {range.toUpperCase()}
              </button>
            ))}
          </div>
          <button onClick={fetchOverview} className="btn-outline refresh-btn" title="Refresh Telemetry">
            ↻ REFRESH
          </button>
        </div>
      </div>

      {/* Demo Notice Banner */}
      <div className="demo-notice-banner mt-4">
        <span className="demo-badge">LIVE INTEGRATION + DEMO POSTURE</span>
        <span className="demo-text">
          Live URL scanning and trust intelligence are active. Code posture data is sourced from demo repository fixture (`internal-finance-api`).
        </span>
      </div>

      {/* KPI Metrics Grid */}
      <div className="metrics-grid mt-4">
        <div className="metric-box risk-metric">
          <span className="metric-label">OVERALL POSTURE RISK</span>
          <span className={`metric-value ${posture.overall_risk_score > 80 ? 'critical' : posture.overall_risk_score > 50 ? 'warning' : 'safe'}`}>
            {posture.overall_risk_score ?? 0}
            <span className="metric-sub"> / 100</span>
          </span>
          <span className="metric-footnote text-muted">Demo Repository Posture</span>
        </div>

        <div className="metric-box">
          <span className="metric-label">TOTAL FINDINGS</span>
          <span className="metric-value">{posture.total_findings ?? 0}</span>
          <span className="metric-breakdown">
            <span className="sev-chip critical">{posture.critical_findings ?? 0} CRIT</span>
            <span className="sev-chip warning">{posture.high_findings ?? 0} HIGH</span>
          </span>
        </div>

        <div className="metric-box">
          <span className="metric-label">HISTORICAL SCANS</span>
          <span className="metric-value">{scansSummary.total_scans ?? 0}</span>
          <span className="metric-footnote text-muted">Logged in MongoDB</span>
        </div>

        <div className="metric-box">
          <span className="metric-label">THREAT INTEL ENGINES</span>
          <span className="metric-value text-accent">
            {threatIntel.active_count ?? 0} <span className="metric-sub">/ {threatIntel.total_count ?? 4}</span>
          </span>
          <span className="metric-footnote text-muted">Active Connectors</span>
        </div>
      </div>

      {/* Quick Action Station */}
      <div className="quick-actions-bar mt-4">
        <span className="quick-actions-title">OPERATIONAL DISPATCH:</span>
        <button onClick={() => onNavigate('scanner')} className="btn-action">
          <span>🔍</span> RUN URL SCAN
        </button>
        <button onClick={() => onNavigate('website')} className="btn-action">
          <span>🌐</span> AUDIT WEBSITE / SSL
        </button>
        <button onClick={() => onNavigate('posture')} className="btn-action">
          <span>🛡️</span> CODE SECURITY POSTURE
        </button>
        <button onClick={() => onNavigate('reports')} className="btn-action">
          <span>📑</span> EXPORT SOC REPORT
        </button>
      </div>

      {/* Main Grid: Telemetry Feeds & Status */}
      <div className="soc-grid mt-4">
        {/* Left Column: Threat Intelligence Matrix & Health */}
        <section className="panel">
          <h3>INTELLIGENCE CONNECTOR HEALTH</h3>
          <p className="text-muted mb-4">Multi-source reputation feeds and scanner subsystem statuses.</p>
          
          <div className="providers-list">
            {Object.entries(providers).map(([key, provider]) => (
              <div key={key} className="provider-status-row">
                <div className="provider-info">
                  <span className="provider-name">{provider.name}</span>
                  <span className="provider-desc">{provider.description}</span>
                </div>
                <div className="provider-badge-col">
                  <span className={`status-pill ${provider.configured ? 'ready' : 'unconfigured'}`}>
                    {provider.configured ? '● CONNECTED' : '○ NO API KEY'}
                  </span>
                </div>
              </div>
            ))}
          </div>

          <div className="subsystem-health mt-4">
            <span className="subsystem-title">SCANNER ENGINE STATUS:</span>
            <div className="health-chips">
              <span className="health-chip active">✓ URL SCANNER</span>
              <span className="health-chip active">✓ TRUST ENGINE</span>
              <span className="health-chip active">✓ XAI INFERENCE</span>
              <span className="health-chip active">✓ SSRF FIREWALL</span>
            </div>
          </div>
        </section>

        {/* Right Column: Priority Vulnerability Queue */}
        <section className="panel">
          <div className="panel-header-row">
            <h3>CRITICAL FINDINGS QUEUE</h3>
            <button onClick={() => onNavigate('findings')} className="btn-link">
              VIEW ALL FINDINGS ➔
            </button>
          </div>
          <p className="text-muted mb-4">Highest-severity security findings requiring immediate operator review.</p>

          <div className="findings-stream">
            {findings.length === 0 ? (
              <div className="empty-stream text-muted">No high-risk findings logged. System operating within secure parameters.</div>
            ) : (
              findings.slice(0, 4).map(f => (
                <div key={f.id} className="finding-stream-card" onClick={() => onNavigate('findings', f.id)}>
                  <div className="stream-card-top">
                    <span className={`severity-badge ${f.severity}`}>{f.severity.toUpperCase()}</span>
                    <span className="stream-source">{f.source}</span>
                    <span className="finding-risk">RISK: {f.risk_score}</span>
                  </div>
                  <h4 className="stream-title">{f.title}</h4>
                  <p className="stream-desc">{f.description}</p>
                  <div className="stream-footer">
                    <span className="stream-target text-muted">TARGET: {f.target}</span>
                    <span className="action-text">INSPECT ➔</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </div>

      {/* Bottom Section: Recent Live Scans Feed */}
      <section className="panel mt-4">
        <div className="panel-header-row">
          <h3>RECENT URL & ASSET SCANS</h3>
          <button onClick={() => onNavigate('scanner')} className="btn-link">
            LAUNCH SCANNER ➔
          </button>
        </div>
        
        {scansSummary.recent_scans && scansSummary.recent_scans.length > 0 ? (
          <div className="table-responsive mt-4">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>SCAN ID</th>
                  <th>TARGET</th>
                  <th>TYPE</th>
                  <th>RISK LEVEL</th>
                  <th>SCORE</th>
                  <th>FINDINGS</th>
                  <th>TIMESTAMP</th>
                </tr>
              </thead>
              <tbody>
                {scansSummary.recent_scans.map(scan => (
                  <tr key={scan.scan_id}>
                    <td className="font-mono text-muted">{scan.scan_id.slice(0, 8)}...</td>
                    <td className="font-mono text-cyan">{scan.target}</td>
                    <td>{scan.scan_type.toUpperCase()}</td>
                    <td>
                      <span className={`severity-badge ${scan.risk_level.toLowerCase()}`}>
                        {scan.risk_level.toUpperCase()}
                      </span>
                    </td>
                    <td className="font-mono font-bold">{scan.risk_score}</td>
                    <td>{scan.findings_count} detected</td>
                    <td className="text-muted">{new Date(scan.created_at).toLocaleTimeString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state mt-4">
            <p className="text-muted">No historical scans recorded yet. Enter a target in the URL Scanner to initiate detection.</p>
            <button onClick={() => onNavigate('scanner')} className="btn-primary mt-4">
              PERFORM FIRST SCAN
            </button>
          </div>
        )}
      </section>
    </div>
  );
};

export default SocOverview;
