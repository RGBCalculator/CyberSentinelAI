import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const FindingDetail = ({ findingId, onBack }) => {
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchFinding = async () => {
      try {
        const data = await api.getFinding(findingId);
        setFinding(data);
      } catch (err) {
        setError(err.message || 'Failed to fetch finding details');
      } finally {
        setLoading(false);
      }
    };
    fetchFinding();
  }, [findingId]);

  if (loading) {
    return (
      <div className="finding-detail loading-state">
        <p className="neon-text blink">Connecting to CyberSentinel LLM...</p>
        <p>Analyzing cross-references and synthesizing reasoning...</p>
      </div>
    );
  }

  if (error) return <div className="api-response error">{error}</div>;
  if (!finding) return null;

  return (
    <div className="finding-detail">
      <button onClick={onBack} className="btn-outline mb-4">← BACK TO QUEUE</button>

      <div className="panel detail-header">
        <div className="header-badges">
          <span className={`severity-badge ${finding.severity.toLowerCase()}`}>{finding.severity}</span>
          <span className="rule-badge">{finding.rule_id}</span>
          <span className="risk-score">RISK: {finding.risk_score}</span>
        </div>
        <h2>{finding.title}</h2>
        <p className="text-muted">{finding.description}</p>
      </div>

      <div className="detail-grid mt-4">
        <section className="panel code-panel">
          <h3>EVIDENCE: SOURCE CODE</h3>
          <div className="location-info">
            <span>FILE: {finding.location.file_path}</span>
            <span>LINES: {finding.location.start_line} - {finding.location.end_line}</span>
          </div>
          <pre className="code-snippet"><code>{finding.location.snippet}</code></pre>

          <h3 className="mt-4">BLAST RADIUS</h3>
          <ul className="blast-list">
            {finding.blast_radius.affected_endpoints.map(ep => (
              <li key={ep}>EXPOSED ENDPOINT: {ep}</li>
            ))}
            {finding.blast_radius.dependency_paths.map(dp => (
              <li key={dp.source}>PATH: {dp.source} {dp.relationship} {dp.target}</li>
            ))}
          </ul>
        </section>

        <section className="panel reasoning-panel">
          <h3>CYBERSENTINEL REASONING</h3>
          <div className="reasoning-content">
            <p>{finding.reasoning}</p>
          </div>

          <h3 className="mt-4">SECURITY VERDICT</h3>
          <div className="verdict-content">
            <p>{finding.security_verdict}</p>
          </div>

          <h3 className="mt-4">REMEDIATION</h3>
          <div className="remediation-content">
            <p>{finding.remediation_recommendation}</p>
          </div>
        </section>
      </div>
    </div>
  );
};

export default FindingDetail;
