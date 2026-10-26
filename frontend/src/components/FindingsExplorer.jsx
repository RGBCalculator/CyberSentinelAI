import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import FindingDetail from './FindingDetail';

const CATEGORIES = [
  'All Categories',
  'Static Code Analysis',
  'URL & Web Threat',
  'SSL/TLS',
  'DNS & Headers'
];

const SEVERITIES = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

const FindingsExplorer = ({ initialFindingId = null, onSelectFinding = null }) => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('All Categories');
  
  // Selected finding for side drawer inspection
  const [drawerFinding, setDrawerFinding] = useState(null);

  // Dedicated deep-dive view (for posture findings with reasoning engine)
  const [deepDiveFindingId, setDeepDiveFindingId] = useState(initialFindingId);

  const fetchFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      // Query backend unified findings API
      const res = await api.getFindings({
        search: searchQuery || undefined,
        severity: severityFilter !== 'ALL' ? severityFilter : undefined,
        category: categoryFilter !== 'All Categories' ? categoryFilter : undefined,
        limit: 100
      });

      if (res && res.findings && res.findings.length > 0) {
        setFindings(res.findings);
      } else {
        // Fallback aggregation if endpoint returned 0
        const combined = [];
        try {
          const posture = await api.getPosture();
          if (posture && posture.findings) {
            posture.findings.forEach(f => {
              combined.push({
                id: f.id,
                title: f.title,
                description: f.description,
                severity: f.severity.toUpperCase(),
                risk_score: f.risk_score || 85,
                category: 'Static Code Analysis',
                target: f.location?.file_path || 'internal-finance-api',
                rule_id: f.rule_id,
                created_at: new Date().toISOString(),
                is_posture: true,
                evidence: f.evidence || [{ source: 'SAST Engine', raw_value: f.location?.file_path }],
                remediation: f.remediation || 'Sanitize and validate inputs against strict boundary contracts.'
              });
            });
          }
        } catch (e) {
          console.warn("Posture load fallback error:", e);
        }

        try {
          const scansRes = await api.getRecentScans(10);
          if (scansRes && scansRes.scans) {
            scansRes.scans.forEach(s => {
              if (s.findings_count > 0) {
                combined.push({
                  id: s.scan_id,
                  title: `Threat Identified on ${s.target}`,
                  description: `Target returned risk level ${s.risk_level.toUpperCase()} with ${s.findings_count} anomalies.`,
                  severity: s.risk_level.toUpperCase(),
                  risk_score: s.risk_score,
                  category: 'URL & Web Threat',
                  target: s.target,
                  rule_id: 'url-pipeline-v2',
                  created_at: s.created_at || new Date().toISOString(),
                  is_posture: false,
                  evidence: [{ source: 'Live Scanner', raw_value: `Target: ${s.target} | Score: ${s.risk_score}` }],
                  remediation: 'Inspect SSL/TLS cipher suite and review server response headers.'
                });
              }
            });
          }
        } catch (e) {
          console.warn("Scans load fallback error:", e);
        }
        setFindings(combined);
      }
    } catch (err) {
      console.warn("Unified findings error, falling back locally:", err);
      setError(err.message || "Failed to load findings.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFindings();
  }, [severityFilter, categoryFilter]);

  // Client-side search filtering
  const filteredFindings = findings.filter(f => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return true;
    return (
      (f.title && f.title.toLowerCase().includes(q)) ||
      (f.description && f.description.toLowerCase().includes(q)) ||
      (f.target && f.target.toLowerCase().includes(q)) ||
      (f.category && f.category.toLowerCase().includes(q)) ||
      (f.rule_id && f.rule_id.toLowerCase().includes(q))
    );
  });

  // Calculate severity counts
  const severityCounts = {
    ALL: findings.length,
    CRITICAL: findings.filter(f => (f.severity || '').toUpperCase() === 'CRITICAL').length,
    HIGH: findings.filter(f => (f.severity || '').toUpperCase() === 'HIGH').length,
    MEDIUM: findings.filter(f => (f.severity || '').toUpperCase() === 'MEDIUM').length,
    LOW: findings.filter(f => (f.severity || '').toUpperCase() === 'LOW').length,
  };

  // If deep dive is requested for a specific posture finding:
  if (deepDiveFindingId) {
    return (
      <FindingDetail
        findingId={deepDiveFindingId}
        onBack={() => setDeepDiveFindingId(null)}
      />
    );
  }

  return (
    <div className="findings-explorer-view">
      {/* Header matching Panel 4 */}
      <div className="view-header">
        <div>
          <h2>Findings</h2>
          <p className="text-muted">Identified security vulnerabilities, configuration anomalies, and threat signals across audited targets.</p>
        </div>
        <div className="header-actions">
          <button 
            onClick={fetchFindings} 
            disabled={loading} 
            className="btn-outline-landing btn-sm"
          >
            {loading ? 'Refreshing...' : '↻ Refresh Findings'}
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <section className="panel mt-4 findings-filter-panel">
        <div className="filter-controls-bar">
          {/* Search Field */}
          <div className="search-box-wrapper">
            <span className="search-icon">🔍</span>
            <input
              id="findings-search-input"
              type="text"
              placeholder="Search findings, targets, CVEs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="findings-search-input"
            />
            {searchQuery && (
              <button 
                onClick={() => setSearchQuery('')} 
                className="clear-search-btn"
                title="Clear search"
              >
                ✕
              </button>
            )}
          </div>

          {/* Category Filter Dropdown */}
          <div className="category-select-wrapper">
            <select
              id="findings-category-select"
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="category-dropdown"
            >
              {CATEGORIES.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Severity Filter Buttons / Pills */}
        <div className="severity-pills-row mt-3">
          <span className="text-xs font-mono text-muted mr-2">SEVERITY:</span>
          <div className="severity-pills-group">
            {SEVERITIES.map(sev => {
              const count = severityCounts[sev] || 0;
              const isActive = severityFilter === sev;
              let badgeColor = '';
              if (sev === 'CRITICAL') badgeColor = 'pill-crit';
              else if (sev === 'HIGH') badgeColor = 'pill-high';
              else if (sev === 'MEDIUM') badgeColor = 'pill-med';
              else if (sev === 'LOW') badgeColor = 'pill-low';
              else badgeColor = 'pill-all';

              return (
                <button
                  key={sev}
                  type="button"
                  className={`sev-filter-btn ${badgeColor} ${isActive ? 'active' : ''}`}
                  onClick={() => setSeverityFilter(sev)}
                >
                  <span className="sev-btn-label">{sev}</span>
                  <span className="sev-btn-count">{count}</span>
                </button>
              );
            })}
          </div>
        </div>
      </section>

      {/* Loading state */}
      {loading && (
        <div className="panel loading-state mt-4 py-8">
          <span className="mini-spinner"></span>
          <p className="neon-text mt-3">SYNCHRONIZING SECURITY FINDINGS...</p>
        </div>
      )}

      {/* Error state */}
      {error && !loading && (
        <div className="panel mt-4">
          <div className="api-response error">
            <h4>EXPLORER WARNING</h4>
            <p className="text-sm font-mono mt-1">{error}</p>
          </div>
          <button onClick={fetchFindings} className="btn-primary-landing btn-sm mt-3">Retry</button>
        </div>
      )}

      {/* Findings Table */}
      {!loading && (
        <section className="panel mt-4 findings-table-panel">
          {filteredFindings.length === 0 ? (
            <div className="empty-state py-8">
              <span className="text-3xl">🛡️</span>
              <h4 className="mt-2 text-white font-semibold">No Matching Findings</h4>
              <p className="text-muted text-sm mt-1">No security findings matched your active search query and severity filter.</p>
              <button 
                onClick={() => { setSearchQuery(''); setSeverityFilter('ALL'); setCategoryFilter('All Categories'); }}
                className="btn-outline-landing btn-sm mt-4"
              >
                Reset All Filters
              </button>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="soc-table findings-data-table">
                <thead>
                  <tr>
                    <th>TITLE</th>
                    <th>CATEGORY</th>
                    <th>SEVERITY</th>
                    <th>TARGET</th>
                    <th>DETECTED AT</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map(f => {
                    const sev = (f.severity || 'low').toLowerCase();
                    return (
                      <tr 
                        key={f.id} 
                        className={`finding-table-row ${drawerFinding?.id === f.id ? 'row-selected' : ''}`}
                        onClick={() => setDrawerFinding(f)}
                      >
                        <td className="finding-title-td">
                          <div className="finding-main-title font-semibold text-white">{f.title}</div>
                          {f.rule_id && (
                            <span className="finding-rule-sub font-mono text-xs text-muted">RULE: {f.rule_id}</span>
                          )}
                        </td>

                        <td>
                          <span className="category-pill">{f.category || 'Vulnerability'}</span>
                        </td>

                        <td>
                          <span className={`severity-badge ${sev}`}>
                            {sev.toUpperCase()}
                          </span>
                        </td>

                        <td className="font-mono text-cyan text-xs truncate-cell max-w-xs">
                          {f.target}
                        </td>

                        <td className="text-muted text-xs font-mono">
                          {f.created_at ? new Date(f.created_at).toLocaleDateString() : 'Active'}
                        </td>

                        <td>
                          <button 
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setDrawerFinding(f);
                            }}
                            className="btn-outline-landing btn-xs"
                          >
                            Details
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* Slide-In Details Drawer / Modal */}
      {drawerFinding && (
        <div className="drawer-overlay" onClick={() => setDrawerFinding(null)}>
          <div className="drawer-container" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-header">
              <div className="drawer-title-group">
                <span className={`severity-badge ${(drawerFinding.severity || 'low').toLowerCase()}`}>
                  {(drawerFinding.severity || 'LOW').toUpperCase()}
                </span>
                <span className="category-pill ml-2">{drawerFinding.category}</span>
              </div>
              <button 
                onClick={() => setDrawerFinding(null)} 
                className="drawer-close-btn"
                title="Close drawer"
              >
                ✕
              </button>
            </div>

            <div className="drawer-body mt-4">
              <h3 className="drawer-finding-title text-white font-bold">{drawerFinding.title}</h3>
              
              <div className="drawer-meta-grid mt-3">
                <div className="drawer-meta-item">
                  <span className="meta-item-label">TARGET ASSET</span>
                  <span className="meta-item-value font-mono text-cyan text-xs">{drawerFinding.target}</span>
                </div>
                <div className="drawer-meta-item">
                  <span className="meta-item-label">RISK SCORE</span>
                  <span className="meta-item-value font-mono text-white text-xs">{drawerFinding.risk_score || 'N/A'}/100</span>
                </div>
                <div className="drawer-meta-item">
                  <span className="meta-item-label">RULE IDENTIFIER</span>
                  <span className="meta-item-value font-mono text-muted text-xs">{drawerFinding.rule_id || 'CYBER-CHECK'}</span>
                </div>
                <div className="drawer-meta-item">
                  <span className="meta-item-label">TIMESTAMP</span>
                  <span className="meta-item-value font-mono text-muted text-xs">
                    {drawerFinding.created_at ? new Date(drawerFinding.created_at).toLocaleString() : 'Recent'}
                  </span>
                </div>
              </div>

              <div className="drawer-section mt-4">
                <h4 className="drawer-section-heading">Description</h4>
                <p className="drawer-text text-secondary text-sm mt-1">{drawerFinding.description}</p>
              </div>

              {drawerFinding.evidence && drawerFinding.evidence.length > 0 && (
                <div className="drawer-section mt-4">
                  <h4 className="drawer-section-heading">Technical Evidence</h4>
                  <div className="evidence-code-block mt-2">
                    <div className="code-header font-mono text-xs text-muted">
                      SOURCE: {drawerFinding.evidence[0].source || 'SYSTEM'}
                    </div>
                    <pre className="evidence-code font-mono text-xs">
                      <code>{drawerFinding.evidence[0].raw_value}</code>
                    </pre>
                  </div>
                </div>
              )}

              {drawerFinding.remediation && (
                <div className="drawer-section mt-4">
                  <h4 className="drawer-section-heading text-cyan">Actionable Remediation</h4>
                  <div className="remediation-box mt-2">
                    <p className="text-sm text-secondary">{drawerFinding.remediation}</p>
                  </div>
                </div>
              )}

              {drawerFinding.is_posture && (
                <div className="drawer-footer-actions mt-6">
                  <button 
                    onClick={() => {
                      setDeepDiveFindingId(drawerFinding.id);
                      setDrawerFinding(null);
                    }}
                    className="btn-primary-landing w-full"
                  >
                    Open Deep Reasoner & Blast Radius ➔
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FindingsExplorer;
