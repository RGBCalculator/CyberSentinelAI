import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

function useCountUp(target, duration = 800) {
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (typeof target !== 'number' || isNaN(target)) {
      setCount(target);
      return;
    }
    const prefersReducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion) {
      setCount(target);
      return;
    }

    let start = 0;
    const startTime = performance.now();

    const updateCount = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - (1 - progress) * (1 - progress); // easeOutQuad
      const current = Math.round(start + (target - start) * eased);
      setCount(current);

      if (progress < 1) {
        requestAnimationFrame(updateCount);
      }
    };

    requestAnimationFrame(updateCount);
  }, [target, duration]);

  return count;
}

const SocOverview = ({ onNavigate }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [timeRange, setTimeRange] = useState('7d');
  const [showFormulaExplanation, setShowFormulaExplanation] = useState(false);

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

  const posture = data?.security_posture || {};
  const scansSummary = data?.scans_summary || {};
  const statusCounts = scansSummary.status_counts || {};
  const threatIntel = data?.threat_intelligence || {};
  const findingsOverview = data?.findings_overview || {};
  const findingsList = findingsOverview.findings || [];
  const providers = threatIntel.providers || {};
  const recentScans = scansSummary.recent_scans || [];
  const activity7d = scansSummary.activity_7d || [
    { day: 'Mon', count: 0 },
    { day: 'Tue', count: 0 },
    { day: 'Wed', count: 0 },
    { day: 'Thu', count: 0 },
    { day: 'Fri', count: 0 },
    { day: 'Sat', count: 0 },
    { day: 'Sun', count: 0 }
  ];

  // Animated KPI values
  const totalScans = scansSummary.total_scans ?? 0;
  const completedScans = statusCounts.completed ?? Math.max(0, totalScans - (statusCounts.partial ?? 0) - (statusCounts.failed ?? 0));
  const partialScans = statusCounts.partial ?? 0;
  const failedScans = statusCounts.failed ?? 0;

  const animTotal = useCountUp(totalScans, 800);
  const animCompleted = useCountUp(completedScans, 800);
  const animPartial = useCountUp(partialScans, 800);
  const animFailed = useCountUp(failedScans, 800);

  // Severity counts
  const sevCounts = findingsOverview.by_severity || {
    critical: findingsList.filter(f => (f.severity || '').toLowerCase() === 'critical').length,
    high: findingsList.filter(f => (f.severity || '').toLowerCase() === 'high').length,
    medium: findingsList.filter(f => (f.severity || '').toLowerCase() === 'medium').length,
    low: findingsList.filter(f => ['low', 'safe', 'info'].includes((f.severity || '').toLowerCase())).length,
  };
  const totalFindings = sevCounts.critical + sevCounts.high + sevCounts.medium + sevCounts.low;

  // Max value for 7d bar chart scaling
  const maxActivity = Math.max(...activity7d.map(d => d.count), 5);

  if (loading) {
    return (
      <div className="soc-view-loading panel">
        <p className="neon-text blink">SYNCHRONIZING SOC TELEMETRY...</p>
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

  return (
    <div className="soc-overview">
      {/* Top Header Section (matches reference image: Page title and subtitle) */}
      <div className="soc-toolbar">
        <div>
          <h1 className="soc-page-title">SOC Overview</h1>
          <p className="soc-page-subtitle">A summary of your security scans and findings.</p>
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
            ↻ Refresh
          </button>
        </div>
      </div>

      {/* Row of 4 KPI Cards (matches reference image: Total Scans, Completed, Partial, Failed) */}
      <div className="kpi-cards-grid mt-4">
        {/* KPI 1: Total Scans */}
        <div className="soc-kpi-card">
          <div className="kpi-top">
            <span className="kpi-title">Total Scans</span>
            <span className="kpi-icon">📊</span>
          </div>
          <div className="kpi-number">{animTotal}</div>
          <div className="kpi-footnote text-muted">
            Logged across active targets
          </div>
        </div>

        {/* KPI 2: Completed */}
        <div className="soc-kpi-card">
          <div className="kpi-top">
            <span className="kpi-title">Completed</span>
            <span className="kpi-icon text-success">✓</span>
          </div>
          <div className="kpi-number text-success">{animCompleted}</div>
          <div className="kpi-footnote text-success">
            {totalScans > 0 ? `${Math.round((completedScans / totalScans) * 100)}% execution rate` : '100% operational'}
          </div>
        </div>

        {/* KPI 3: Partial */}
        <div className="soc-kpi-card">
          <div className="kpi-top">
            <span className="kpi-title">Partial</span>
            <span className="kpi-icon text-warning">⚠️</span>
          </div>
          <div className="kpi-number text-warning">{animPartial}</div>
          <div className="kpi-footnote text-muted">
            Warning states or timeouts
          </div>
        </div>

        {/* KPI 4: Failed */}
        <div className="soc-kpi-card">
          <div className="kpi-top">
            <span className="kpi-title">Failed</span>
            <span className="kpi-icon text-error">✕</span>
          </div>
          <div className="kpi-number text-error">{animFailed}</div>
          <div className="kpi-footnote text-muted">
            Blocked by firewall or offline
          </div>
        </div>
      </div>

      {/* Middle Grid: Findings by Severity (Donut) & Scan Activity (Bar Chart) */}
      <div className="soc-charts-grid mt-4">
        {/* Findings by Severity Card */}
        <div className="panel chart-panel">
          <div className="panel-header-row">
            <div>
              <h3 className="chart-panel-title">Findings by Severity</h3>
              <p className="text-muted text-xs">Distribution of detected issues across all scanned targets</p>
            </div>
            <button 
              type="button" 
              className="btn-link text-xs text-cyan"
              onClick={() => onNavigate('findings')}
            >
              View all ➔
            </button>
          </div>

          <div className="donut-chart-container mt-4">
            {/* Clean SVG Donut Chart with exact colors */}
            <div className="svg-donut-wrapper">
              <svg viewBox="0 0 100 100" className="donut-svg">
                {totalFindings === 0 ? (
                  <circle cx="50" cy="50" r="38" fill="transparent" stroke="#2B3946" strokeWidth="12" />
                ) : (
                  (() => {
                    const radius = 38;
                    const circumference = 2 * Math.PI * radius;
                    let accumulatedPercent = 0;
                    const segments = [
                      { count: sevCounts.critical, color: '#EF4444', label: 'Critical' },
                      { count: sevCounts.high, color: '#F97316', label: 'High' },
                      { count: sevCounts.medium, color: '#F59E0B', label: 'Medium' },
                      { count: sevCounts.low, color: '#43D9D0', label: 'Low' },
                    ];

                    return segments.map((seg, idx) => {
                      if (seg.count === 0) return null;
                      const percent = seg.count / totalFindings;
                      const strokeDasharray = `${percent * circumference} ${circumference}`;
                      const strokeDashoffset = -(accumulatedPercent * circumference);
                      accumulatedPercent += percent;

                      return (
                        <circle
                          key={idx}
                          cx="50"
                          cy="50"
                          r={radius}
                          fill="transparent"
                          stroke={seg.color}
                          strokeWidth="12"
                          strokeDasharray={strokeDasharray}
                          strokeDashoffset={strokeDashoffset}
                          transform="rotate(-90 50 50)"
                        />
                      );
                    });
                  })()
                )}
              </svg>
              <div className="donut-center-text">
                <span className="donut-total-num">{totalFindings}</span>
                <span className="donut-total-label">Findings</span>
              </div>
            </div>

            {/* Severity Legend */}
            <div className="severity-legend-list">
              <div className="legend-row">
                <span className="legend-dot" style={{ backgroundColor: '#EF4444' }}></span>
                <span className="legend-name">Critical</span>
                <span className="legend-count font-mono font-bold text-error">{sevCounts.critical}</span>
              </div>
              <div className="legend-row">
                <span className="legend-dot" style={{ backgroundColor: '#F97316' }}></span>
                <span className="legend-name">High</span>
                <span className="legend-count font-mono font-bold" style={{ color: '#F97316' }}>{sevCounts.high}</span>
              </div>
              <div className="legend-row">
                <span className="legend-dot" style={{ backgroundColor: '#F59E0B' }}></span>
                <span className="legend-name">Medium</span>
                <span className="legend-count font-mono font-bold text-warning">{sevCounts.medium}</span>
              </div>
              <div className="legend-row">
                <span className="legend-dot" style={{ backgroundColor: '#43D9D0' }}></span>
                <span className="legend-name">Low</span>
                <span className="legend-count font-mono font-bold text-cyan">{sevCounts.low}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Scan Activity Card (7-day Bar Chart) */}
        <div className="panel chart-panel">
          <div className="panel-header-row">
            <div>
              <h3 className="chart-panel-title">Scan Activity</h3>
              <p className="text-muted text-xs">Total scans executed over the last 7 days</p>
            </div>
            <span className="text-muted text-xs font-mono">Real-time DB Counts</span>
          </div>

          <div className="activity-chart-container mt-4">
            <div className="activity-bars-wrapper">
              {activity7d.map((dayItem, idx) => {
                const heightPercent = maxActivity > 0 ? Math.max((dayItem.count / maxActivity) * 100, 6) : 6;
                return (
                  <div key={idx} className="activity-bar-col">
                    <span className="bar-count-label font-mono text-xs text-muted">
                      {dayItem.count > 0 ? dayItem.count : ''}
                    </span>
                    <div className="activity-bar-track">
                      <div 
                        className="activity-bar-fill" 
                        style={{ height: `${heightPercent}%` }}
                        title={`${dayItem.count} scans on ${dayItem.date || dayItem.day}`}
                      ></div>
                    </div>
                    <span className="activity-bar-day font-mono text-xs">{dayItem.day}</span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Section: Recent Scans Table (matches reference image) */}
      <section className="panel mt-4">
        <div className="panel-header-row">
          <div>
            <h3>Recent Scans</h3>
            <p className="text-muted text-xs">Real-time log of the latest targets submitted to the scanner</p>
          </div>
          <div className="flex gap-2">
            <button onClick={() => onNavigate('history')} className="btn-outline btn-xs">
              View full history ➔
            </button>
            <button onClick={() => onNavigate('scanner')} className="btn-primary btn-xs">
              + New Scan
            </button>
          </div>
        </div>
        
        {recentScans.length > 0 ? (
          <div className="table-responsive mt-3">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Findings</th>
                  <th>Scanned At</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map(scan => {
                  const riskLvl = (scan.risk_level || 'safe').toLowerCase();
                  const scanStatus = (scan.status || 'completed').toLowerCase();
                  return (
                    <tr key={scan.scan_id}>
                      <td className="font-mono text-cyan truncate max-w-sm" title={scan.target}>
                        {scan.target}
                      </td>
                      <td>
                        <span className={`status-pill ${scanStatus === 'completed' ? 'ready' : scanStatus === 'partial' ? 'warning' : 'critical'}`}>
                          {scanStatus.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span className={`severity-badge ${riskLvl}`}>
                          {riskLvl.toUpperCase()}
                        </span>
                      </td>
                      <td>
                        {scan.findings_count > 0 ? (
                          <span className="text-warning font-semibold">{scan.findings_count} detected</span>
                        ) : (
                          <span className="text-success text-xs">Clean</span>
                        )}
                      </td>
                      <td className="text-muted text-xs">
                        {scan.created_at ? new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent'}
                      </td>
                      <td>
                        <button 
                          type="button" 
                          className="btn-outline btn-xs"
                          onClick={() => onNavigate('findings', scan.scan_id)}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })}
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

      {/* Tactical Subsystem Status Strip */}
      <div className="tactical-status-strip mt-4">
        <span className="strip-title">CONNECTED DETECTORS:</span>
        <div className="strip-chips">
          <span className="strip-chip active">✓ URL Scanner</span>
          <span className="strip-chip active">✓ Deep TLS Engine</span>
          <span className="strip-chip active">✓ Threat Intelligence</span>
          <span className="strip-chip active">✓ Heuristic Phishing Guard</span>
          <span className="strip-chip active">✓ SSRF Firewall V2</span>
        </div>
      </div>
    </div>
  );
};

export default SocOverview;
