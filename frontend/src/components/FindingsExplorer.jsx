import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import FindingDetail from './FindingDetail';

const FindingsExplorer = ({ initialFindingId = null, onSelectFinding = null }) => {
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('risk_desc');

  // Selected Detail
  const [selectedFindingId, setSelectedFindingId] = useState(initialFindingId);

  const fetchAllFindings = async () => {
    setLoading(true);
    setError(null);
    try {
      const combined = [];

      // 1. Fetch Code Posture findings
      try {
        const posture = await api.getPosture();
        if (posture && posture.findings) {
          posture.findings.forEach(f => {
            combined.push({
              id: f.id,
              source: 'Repository Posture',
              title: f.title,
              description: f.description,
              severity: f.severity.toUpperCase(),
              risk_score: f.risk_score,
              category: 'Static Code Analysis',
              target: f.location?.file_path || 'internal-finance-api',
              rule_id: f.rule_id,
              is_posture: true,
              raw: f
            });
          });
        }
      } catch (postureErr) {
        console.warn("Posture findings could not be loaded:", postureErr);
      }

      // 2. Fetch Live Scans findings
      try {
        const scansRes = await api.getRecentScans(10);
        if (scansRes && scansRes.scans) {
          scansRes.scans.forEach(s => {
            if (s.findings_count > 0) {
              combined.push({
                id: s.scan_id,
                source: 'Live URL Scanner',
                title: `Threat Identified on ${s.target}`,
                description: `Scan evaluated risk level ${s.risk_level.toUpperCase()} with ${s.findings_count} anomalies.`,
                severity: s.risk_level.toUpperCase(),
                risk_score: s.risk_score,
                category: 'URL & Web Threat',
                target: s.target,
                rule_id: 'url-pipeline',
                is_posture: false,
                raw: s
              });
            }
          });
        }
      } catch (scansErr) {
        console.warn("Scan findings could not be loaded:", scansErr);
      }

      setFindings(combined);
    } catch (err) {
      setError(err.message || 'Failed to aggregate security findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllFindings();
  }, []);

  // Filter and Sort Logic
  const filteredFindings = findings.filter(f => {
    const matchesSearch = 
      f.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      f.target.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (f.rule_id && f.rule_id.toLowerCase().includes(searchQuery.toLowerCase()));

    const matchesSeverity = severityFilter === 'ALL' || f.severity === severityFilter;
    const matchesSource = sourceFilter === 'ALL' || 
      (sourceFilter === 'POSTURE' && f.is_posture) ||
      (sourceFilter === 'SCANNER' && !f.is_posture);

    return matchesSearch && matchesSeverity && matchesSource;
  }).sort((a, b) => {
    if (sortBy === 'risk_desc') return b.risk_score - a.risk_score;
    if (sortBy === 'risk_asc') return a.risk_score - b.risk_score;
    if (sortBy === 'title') return a.title.localeCompare(b.title);
    return 0;
  });

  if (selectedFindingId) {
    // If it's a code posture finding ID, render the dedicated FindingDetail component
    return (
      <FindingDetail
        findingId={selectedFindingId}
        onBack={() => setSelectedFindingId(null)}
      />
    );
  }

  return (
    <div className="findings-explorer-view">
      <div className="view-header">
        <div>
          <h2>ENTERPRISE VULNERABILITY & FINDINGS EXPLORER</h2>
          <p className="text-muted">Unified search, triage, and impact analysis across repository code posture and URL security scans.</p>
        </div>
        <div>
          <button onClick={fetchAllFindings} disabled={loading} className="btn-outline btn-sm">
            {loading ? 'REFRESHING...' : '↻ SYNC FINDINGS'}
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <section className="panel mt-4">
        <div className="explorer-filters-grid">
          <div className="filter-item search-item">
            <label htmlFor="search-findings-input">SEARCH FINDINGS</label>
            <input
              id="search-findings-input"
              type="text"
              placeholder="Filter by title, asset, CVE/rule, or description..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="scanner-input"
            />
          </div>

          <div className="filter-item">
            <label htmlFor="sev-filter">SEVERITY</label>
            <select
              id="sev-filter"
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="soc-select"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="source-filter">SOURCE</label>
            <select
              id="source-filter"
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="soc-select"
            >
              <option value="ALL">All Sources</option>
              <option value="POSTURE">Repository Code Posture</option>
              <option value="SCANNER">Live URL Scanner</option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="sort-filter">SORT BY</label>
            <select
              id="sort-filter"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value)}
              className="soc-select"
            >
              <option value="risk_desc">Risk Score (High to Low)</option>
              <option value="risk_asc">Risk Score (Low to High)</option>
              <option value="title">Title (Alphabetical)</option>
            </select>
          </div>
        </div>

        {/* Quick Count Summary Chips */}
        <div className="filter-summary-row mt-4">
          <span className="text-sm text-muted">SHOWING {filteredFindings.length} OF {findings.length} FINDINGS</span>
          <div className="chip-list">
            <span className="chip crit">CRITICAL: {findings.filter(f => f.severity === 'CRITICAL').length}</span>
            <span className="chip warn">HIGH: {findings.filter(f => f.severity === 'HIGH').length}</span>
            <span className="chip med">MEDIUM: {findings.filter(f => f.severity === 'MEDIUM').length}</span>
            <span className="chip safe">LOW: {findings.filter(f => f.severity === 'LOW').length}</span>
          </div>
        </div>
      </section>

      {/* Loading & Error States */}
      {loading && (
        <div className="panel loading-state mt-4">
          <p className="neon-text blink">LOADING SECURITY FINDINGS...</p>
          <p className="text-muted text-sm mt-2">Aggregating vulnerability data from scanners and code repositories...</p>
        </div>
      )}

      {error && (
        <div className="panel mt-4">
          <div className="api-response error">
            <h4>EXPLORER ERROR</h4>
            <pre>{error}</pre>
          </div>
          <button onClick={fetchAllFindings} className="btn-primary mt-4">RETRY</button>
        </div>
      )}

      {/* Findings Data Table */}
      {!loading && !error && (
        <section className="panel mt-4">
          {filteredFindings.length === 0 ? (
            <div className="empty-state">
              <h3>NO MATCHING FINDINGS</h3>
              <p className="text-muted mt-2">No security findings matched your active search query and severity filter.</p>
              <button 
                onClick={() => { setSearchQuery(''); setSeverityFilter('ALL'); setSourceFilter('ALL'); }}
                className="btn-outline mt-4"
              >
                RESET FILTERS
              </button>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="soc-table findings-table">
                <thead>
                  <tr>
                    <th>SEVERITY</th>
                    <th>VULNERABILITY TITLE</th>
                    <th>AFFECTED ASSET / TARGET</th>
                    <th>SOURCE</th>
                    <th>RULE / CATEGORY</th>
                    <th>RISK SCORE</th>
                    <th>ACTION</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map(finding => (
                    <tr key={finding.id} className="finding-row">
                      <td>
                        <span className={`severity-badge ${finding.severity.toLowerCase()}`}>
                          {finding.severity}
                        </span>
                      </td>
                      <td>
                        <div className="finding-title-cell font-bold">{finding.title}</div>
                        <div className="finding-desc-cell text-xs text-muted truncate-cell">{finding.description}</div>
                      </td>
                      <td className="font-mono text-cyan text-sm">{finding.target}</td>
                      <td>
                        <span className="source-tag">{finding.source}</span>
                      </td>
                      <td>
                        <span className="rule-badge">{finding.rule_id || finding.category}</span>
                      </td>
                      <td>
                        <span className={`risk-pill font-mono font-bold ${finding.risk_score > 80 ? 'critical' : finding.risk_score > 50 ? 'warning' : 'safe'}`}>
                          {finding.risk_score}
                        </span>
                      </td>
                      <td>
                        {finding.is_posture ? (
                          <button 
                            onClick={() => setSelectedFindingId(finding.id)}
                            className="btn-primary btn-xs"
                          >
                            INVESTIGATE ➔
                          </button>
                        ) : (
                          <span className="text-xs text-muted">SCAN RECORD</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  );
};

export default FindingsExplorer;
