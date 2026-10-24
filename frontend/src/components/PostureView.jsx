import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import FindingDetail from './FindingDetail';

const PostureView = () => {
  const [posture, setPosture] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  const fetchPosture = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getPosture();
      setPosture(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch security posture data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPosture();
  }, []);

  if (loading) {
    return (
      <div className="posture-view">
        <div className="panel loading-state">
          <p className="neon-text blink">ANALYZING REPOSITORY SECURITY POSTURE...</p>
          <p className="text-muted mt-4">Connecting to security intelligence engine...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="posture-view">
        <div className="panel">
          <div className="api-response error">
            <h4>SECURITY POSTURE API ERROR</h4>
            <pre>{error}</pre>
          </div>
          <p className="text-muted mt-4">
            Could not retrieve posture fixture. Ensure the backend container is running and demo fixture is available.
          </p>
          <button onClick={fetchPosture} className="btn-primary mt-4">
            RETRY REQUEST
          </button>
        </div>
      </div>
    );
  }

  if (!posture || !posture.findings || posture.findings.length === 0) {
    return (
      <div className="posture-view">
        <div className="panel empty-state">
          <h3>SECURITY POSTURE</h3>
          <p className="text-muted mt-4">No security vulnerabilities detected in the analyzed repository.</p>
          <button onClick={fetchPosture} className="btn-outline mt-4">
            REFRESH POSTURE
          </button>
        </div>
      </div>
    );
  }

  if (selectedFindingId) {
    return (
      <FindingDetail
        findingId={selectedFindingId}
        onBack={() => setSelectedFindingId(null)}
      />
    );
  }

  return (
    <div className="posture-view">
      <div className="demo-notice-banner mb-4">
        <span className="demo-badge">DEMO FIXTURE</span>
        <span className="demo-text">
          Simulated demo repository findings for validation. Findings and AI reasoning are deterministic demonstration fixtures.
        </span>
      </div>

      <section className="panel summary-panel">
        <div className="repo-header">
          <div>
            <h2>REPOSITORY: {posture.repository?.name || 'Unknown'}</h2>
            {posture.repository?.branch && (
              <span className="repo-branch text-muted">BRANCH: {posture.repository.branch}</span>
            )}
          </div>
          {posture.repository?.commit_hash && (
            <span className="commit-hash">COMMIT: {posture.repository.commit_hash}</span>
          )}
        </div>

        <div className="metrics-grid">
          <div className="metric-box">
            <span className="metric-label">OVERALL RISK SCORE</span>
            <span className={`metric-value ${posture.overall_risk_score > 80 ? 'critical' : posture.overall_risk_score > 50 ? 'warning' : 'safe'}`}>
              {posture.overall_risk_score ?? 'N/A'}
            </span>
          </div>
          <div className="metric-box">
            <span className="metric-label">TOTAL FINDINGS</span>
            <span className="metric-value">{posture.total_findings ?? posture.findings.length}</span>
          </div>
          <div className="metric-box">
            <span className="metric-label">CRITICAL</span>
            <span className="metric-value critical">{posture.critical_findings ?? 0}</span>
          </div>
          <div className="metric-box">
            <span className="metric-label">HIGH</span>
            <span className="metric-value warning">{posture.high_findings ?? 0}</span>
          </div>
        </div>
      </section>

      <section className="panel findings-panel mt-4">
        <h3>VULNERABILITY INTELLIGENCE QUEUE</h3>
        <p className="text-muted mb-4">Select a finding to inspect source code evidence, blast radius, and AI reasoning.</p>
        <div className="findings-list">
          {posture.findings.map(finding => (
            <div
              key={finding.id}
              className="finding-card"
              onClick={() => setSelectedFindingId(finding.id)}
              role="button"
              tabIndex={0}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  setSelectedFindingId(finding.id);
                }
              }}
            >
              <div className="finding-header">
                <span className={`severity-badge ${finding.severity ? finding.severity.toLowerCase() : 'low'}`}>
                  {finding.severity}
                </span>
                <span className="finding-risk">RISK: {finding.risk_score}</span>
              </div>
              <h4 className="finding-title">{finding.title}</h4>
              <p className="finding-desc">{finding.description}</p>

              {finding.location && (
                <div className="finding-location">
                  <span className="location-icon">📁</span>
                  <span className="location-path">{finding.location.file_path}</span>
                  {finding.location.start_line && (
                    <span className="location-lines">:{finding.location.start_line}-{finding.location.end_line}</span>
                  )}
                </div>
              )}

              <div className="finding-footer">
                <span className="rule-id">{finding.rule_id}</span>
                <span className="action-text">INVESTIGATE ➔</span>
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

export default PostureView;
