import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const FindingDetail = ({ findingId, onBack }) => {
  const [finding, setFinding] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchFinding = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getFinding(findingId);
      setFinding(data);
    } catch (err) {
      setError(err.message || 'Failed to fetch finding details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFinding();
  }, [findingId]);

  if (loading) {
    return (
      <div className="finding-detail">
        <button onClick={onBack} className="btn-outline mb-4">← BACK TO FINDINGS LIST</button>
        <div className="panel loading-state">
          <p className="neon-text blink">CONNECTING TO CYBERSENTINEL REASONING ENGINE...</p>
          <p className="text-muted mt-4">Analyzing cross-references, blast radius, and synthesizing remediation guidance...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="finding-detail">
        <button onClick={onBack} className="btn-outline mb-4">← BACK TO FINDINGS LIST</button>
        <div className="panel">
          <div className="api-response error">
            <h4>FAILED TO LOAD FINDING</h4>
            <pre>{error}</pre>
          </div>
          <p className="text-muted mt-4">Could not retrieve finding details from the backend service.</p>
          <button onClick={fetchFinding} className="btn-primary mt-4">RETRY</button>
        </div>
      </div>
    );
  }

  if (!finding) {
    return (
      <div className="finding-detail">
        <button onClick={onBack} className="btn-outline mb-4">← BACK TO FINDINGS LIST</button>
        <div className="panel empty-state">
          <h3>FINDING NOT FOUND</h3>
          <p className="text-muted mt-4">The requested finding ID ({findingId}) was not found in the demo fixture.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="finding-detail">
      <div className="detail-navigation mb-4">
        <button onClick={onBack} className="btn-outline">← BACK TO FINDINGS LIST</button>
        <span className="breadcrumb-info text-muted">ID: {finding.id}</span>
      </div>

      <div className="demo-notice-banner mb-4">
        <span className="demo-badge">DEMO REASONING</span>
        <span className="demo-text">
          Simulated finding analysis and AI reasoning generated from the demo fixture. Not intended for production enforcement.
        </span>
      </div>

      <div className="panel detail-header">
        <div className="header-badges">
          <span className={`severity-badge ${finding.severity ? finding.severity.toLowerCase() : 'low'}`}>
            {finding.severity}
          </span>
          <span className="rule-badge">{finding.rule_id}</span>
          <span className="risk-score">RISK SCORE: {finding.risk_score}</span>
        </div>
        <h2>{finding.title}</h2>
        <p className="text-muted">{finding.description}</p>
      </div>

      <div className="detail-grid mt-4">
        <section className="panel code-panel">
          <h3>EVIDENCE: SOURCE CODE</h3>
          {finding.location && (
            <div className="location-info">
              <span>FILE: {finding.location.file_path}</span>
              <span>LINES: {finding.location.start_line} - {finding.location.end_line}</span>
            </div>
          )}
          {finding.location?.snippet && (
            <pre className="code-snippet"><code>{finding.location.snippet}</code></pre>
          )}

          {finding.blast_radius && (
            <>
              <h3 className="mt-4">BLAST RADIUS IMPACT</h3>

              {finding.blast_radius.affected_endpoints && finding.blast_radius.affected_endpoints.length > 0 && (
                <div className="blast-section mt-4">
                  <span className="blast-subtitle">EXPOSED ENDPOINTS:</span>
                  <ul className="blast-list">
                    {finding.blast_radius.affected_endpoints.map(ep => (
                      <li key={ep}>ENDPOINT: {ep}</li>
                    ))}
                  </ul>
                </div>
              )}

              {finding.blast_radius.affected_files && finding.blast_radius.affected_files.length > 0 && (
                <div className="blast-section mt-4">
                  <span className="blast-subtitle">AFFECTED FILES:</span>
                  <ul className="blast-list">
                    {finding.blast_radius.affected_files.map(file => (
                      <li key={file}>FILE: {file}</li>
                    ))}
                  </ul>
                </div>
              )}

              {finding.blast_radius.dependency_paths && finding.blast_radius.dependency_paths.length > 0 && (
                <div className="blast-section mt-4">
                  <span className="blast-subtitle">DEPENDENCY TRACE:</span>
                  <ul className="blast-list">
                    {finding.blast_radius.dependency_paths.map((dp, idx) => (
                      <li key={idx}>PATH: {dp.source} ➔ [{dp.relationship}] ➔ {dp.target}</li>
                    ))}
                  </ul>
                </div>
              )}
            </>
          )}

          {finding.investigation_plan && finding.investigation_plan.length > 0 && (
            <>
              <h3 className="mt-4">INVESTIGATION PLAN</h3>
              <div className="investigation-tasks mt-4">
                {finding.investigation_plan.map(task => (
                  <div key={task.id} className="task-item">
                    <div className="task-header">
                      <span className="task-title">{task.title}</span>
                      <span className={`task-status ${task.status.toLowerCase()}`}>{task.status}</span>
                    </div>
                    <p className="task-desc">{task.description}</p>
                  </div>
                ))}
              </div>
            </>
          )}
        </section>

        <section className="panel reasoning-panel">
          <h3>CYBERSENTINEL REASONING</h3>
          <div className="reasoning-content">
            <p>{finding.reasoning || 'No AI reasoning synthesized for this finding.'}</p>
          </div>

          <h3 className="mt-4">SECURITY VERDICT</h3>
          <div className="verdict-content">
            <p>{finding.security_verdict || 'Awaiting verdict evaluation.'}</p>
          </div>

          <h3 className="mt-4">REMEDIATION GUIDANCE</h3>
          <div className="remediation-content">
            <p>{finding.remediation_recommendation || 'No remediation instructions specified.'}</p>
          </div>
        </section>
      </div>
    </div>
  );
};

export default FindingDetail;
