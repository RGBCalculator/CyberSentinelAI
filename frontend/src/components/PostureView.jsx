import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import FindingDetail from './FindingDetail';

const PostureView = () => {
  const [posture, setPosture] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  useEffect(() => {
    const fetchPosture = async () => {
      try {
        const data = await api.getPosture();
        setPosture(data);
      } catch (err) {
        setError(err.message || 'Failed to fetch security posture');
      } finally {
        setLoading(false);
      }
    };
    fetchPosture();
  }, []);

  if (loading) return <div className="loading-state">Analyzing Repository Intelligence...</div>;
  if (error) return <div className="api-response error">{error}</div>;
  if (!posture) return null;

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
      <section className="panel summary-panel">
        <div className="repo-header">
          <h2>REPOSITORY: {posture.repository.name}</h2>
          <span className="commit-hash">COMMIT: {posture.repository.commit_hash}</span>
        </div>

        <div className="metrics-grid">
          <div className="metric-box">
            <span className="metric-label">OVERALL RISK SCORE</span>
            <span className={`metric-value ${posture.overall_risk_score > 80 ? 'critical' : 'warning'}`}>
              {posture.overall_risk_score}
            </span>
          </div>
          <div className="metric-box">
            <span className="metric-label">TOTAL FINDINGS</span>
            <span className="metric-value">{posture.total_findings}</span>
          </div>
          <div className="metric-box">
            <span className="metric-label">CRITICAL</span>
            <span className="metric-value critical">{posture.critical_findings}</span>
          </div>
        </div>
      </section>

      <section className="panel findings-panel mt-4">
        <h3>VULNERABILITY INTELLIGENCE QUEUE</h3>
        <div className="findings-list">
          {posture.findings.map(finding => (
            <div key={finding.id} className="finding-card" onClick={() => setSelectedFindingId(finding.id)}>
              <div className="finding-header">
                <span className={`severity-badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span>
                <span className="finding-risk">RISK: {finding.risk_score}</span>
              </div>
              <h4 className="finding-title">{finding.title}</h4>
              <p className="finding-desc">{finding.description}</p>
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
