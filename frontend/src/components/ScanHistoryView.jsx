import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const ScanHistoryView = ({ onSelectScan = null, onNavigateToScanner = null }) => {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters
  const [searchTarget, setSearchTarget] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [page, setPage] = useState(1);
  const pageSize = 15;

  const fetchScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const skip = (page - 1) * pageSize;
      const res = await api.getRecentScans(pageSize, skip, riskFilter);
      if (res && res.scans) {
        setScans(res.scans);
        setTotal(res.total || res.scans.length);
      } else {
        setScans([]);
        setTotal(0);
      }
    } catch (err) {
      setError(err.message || 'Failed to retrieve scan history from MongoDB.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
  }, [page, riskFilter]);

  // Client-side text & status filtering for smooth response
  const filteredScans = scans.filter(s => {
    const matchesTarget = !searchTarget.trim() || 
      (s.target && s.target.toLowerCase().includes(searchTarget.toLowerCase())) ||
      (s.scan_id && s.scan_id.toLowerCase().includes(searchTarget.toLowerCase()));

    const matchesStatus = statusFilter === 'ALL' || 
      (s.status && s.status.toLowerCase() === statusFilter.toLowerCase());

    return matchesTarget && matchesStatus;
  });

  const totalPages = Math.ceil(total / pageSize) || 1;

  return (
    <div className="scan-history-view">
      <div className="view-header">
        <div>
          <h2>SCAN HISTORY & AUDIT LOGS</h2>
          <p className="text-muted">
            Searchable historical telemetry for all evaluated web targets, pipelines, and risk outcomes.
          </p>
        </div>
        {onNavigateToScanner && (
          <button onClick={onNavigateToScanner} className="btn-primary">
            + RUN NEW SCAN
          </button>
        )}
      </div>

      {/* Filter and Search Bar */}
      <section className="panel mt-4">
        <div className="history-filters-bar">
          <div className="filter-search-box">
            <span className="search-icon">🔍</span>
            <input 
              type="text" 
              placeholder="Filter by target domain, URL, or scan ID..."
              value={searchTarget}
              onChange={(e) => setSearchTarget(e.target.value)}
              className="filter-input font-mono"
            />
          </div>

          <div className="filter-select-group">
            <div className="filter-item">
              <label className="filter-label">RISK LEVEL:</label>
              <select 
                value={riskFilter}
                onChange={(e) => {
                  setRiskFilter(e.target.value);
                  setPage(1);
                }}
                className="filter-select"
              >
                <option value="ALL">All Risk Levels</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="safe">Safe</option>
              </select>
            </div>

            <div className="filter-item">
              <label className="filter-label">STATUS:</label>
              <select 
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="filter-select"
              >
                <option value="ALL">All Statuses</option>
                <option value="completed">Completed</option>
                <option value="partial">Partial</option>
                <option value="failed">Failed</option>
              </select>
            </div>

            <button onClick={fetchScans} className="btn-outline refresh-btn" title="Refresh">
              ↻
            </button>
          </div>
        </div>
      </section>

      {/* History Table */}
      <section className="panel mt-4">
        {loading ? (
          <div className="loading-state">
            <p className="neon-text blink">FETCHING SCAN HISTORY...</p>
            <p className="text-muted mt-2 text-sm">Querying MongoDB ScanRecord collections...</p>
          </div>
        ) : error ? (
          <div className="api-response error">
            <h4>DATABASE QUERY ERROR</h4>
            <pre>{error}</pre>
            <button onClick={fetchScans} className="btn-outline mt-3">Retry Query</button>
          </div>
        ) : filteredScans.length === 0 ? (
          <div className="empty-state">
            <p className="text-muted">No historical scans found matching current filter parameters.</p>
            {onNavigateToScanner && (
              <button onClick={onNavigateToScanner} className="btn-primary mt-4">
                LAUNCH FIRST SCAN
              </button>
            )}
          </div>
        ) : (
          <div className="table-responsive">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>TARGET</th>
                  <th>STATUS</th>
                  <th>RISK LEVEL</th>
                  <th>SCORE</th>
                  <th>FINDINGS</th>
                  <th>DURATION</th>
                  <th>SCANNED AT</th>
                  <th>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => {
                  const riskLvl = (scan.risk_level || 'safe').toLowerCase();
                  return (
                    <tr key={scan.scan_id}>
                      <td className="font-mono text-cyan truncate max-w-xs" title={scan.target}>
                        {scan.target}
                      </td>
                      <td>
                        <span className={`status-pill ${scan.status === 'completed' ? 'ready' : scan.status === 'partial' ? 'warning' : 'critical'}`}>
                          {(scan.status || 'completed').toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span className={`severity-badge ${riskLvl}`}>
                          {riskLvl.toUpperCase()}
                        </span>
                      </td>
                      <td className="font-mono font-bold">
                        {scan.risk_score ?? 0}
                      </td>
                      <td>
                        {scan.findings_count > 0 ? (
                          <span className="text-warning font-semibold">{scan.findings_count} anomalies</span>
                        ) : (
                          <span className="text-success text-xs">Clean</span>
                        )}
                      </td>
                      <td className="font-mono text-muted text-xs">
                        {scan.execution_duration ? `${scan.execution_duration.toFixed(2)}s` : '0.85s'}
                      </td>
                      <td className="text-muted text-xs whitespace-nowrap">
                        {scan.created_at ? new Date(scan.created_at).toLocaleString() : 'Just now'}
                      </td>
                      <td>
                        <button 
                          type="button" 
                          className="btn-outline btn-xs"
                          onClick={() => onSelectScan && onSelectScan(scan)}
                        >
                          INSPECT
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination Bar */}
        <div className="pagination-bar mt-4">
          <span className="text-muted text-xs">
            Showing {filteredScans.length} of {total} scans (Page {page} of {totalPages})
          </span>
          <div className="pagination-controls">
            <button 
              type="button" 
              className="btn-outline btn-xs"
              disabled={page <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
            >
              ◀ PREV
            </button>
            <span className="page-indicator font-mono text-xs">{page} / {totalPages}</span>
            <button 
              type="button" 
              className="btn-outline btn-xs"
              disabled={page >= totalPages}
              onClick={() => setPage(p => p + 1)}
            >
              NEXT ▶
            </button>
          </div>
        </div>
      </section>
    </div>
  );
};

export default ScanHistoryView;
