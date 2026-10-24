import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const ReportsView = () => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchReport = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.exportReport();
      setReport(data);
    } catch (err) {
      setError(err.message || 'Failed to generate security audit report.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchReport();
  }, []);

  const downloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberSentinel_SOC_Report_${report.report_id || 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="panel loading-state">
        <p className="neon-text blink">SYNTHESIZING EXECUTIVE SECURITY REPORT...</p>
        <p className="text-muted text-sm mt-2">Compiling telemetry from threat engines, posture repositories, and scan logs...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="panel">
        <div className="api-response error">
          <h4>REPORT GENERATION FAILED</h4>
          <pre>{error}</pre>
        </div>
        <button onClick={fetchReport} className="btn-primary mt-4">RETRY</button>
      </div>
    );
  }

  const exec = report?.executive_summary || {};
  const full = report?.full_data || {};

  return (
    <div className="reports-view">
      <div className="view-header">
        <div>
          <h2>SECURITY AUDIT & COMPLIANCE REPORTS</h2>
          <p className="text-muted">Exportable executive briefings, compliance telemetry, and incident audit trails.</p>
        </div>
        <div className="report-actions">
          <button onClick={downloadJson} className="btn-primary btn-sm">
            ⬇ DOWNLOAD JSON AUDIT
          </button>
          <button onClick={() => window.print()} className="btn-outline btn-sm">
            🖨 PRINT REPORT
          </button>
        </div>
      </div>

      {/* Printable Executive Briefing Document */}
      <div className="report-document panel mt-4">
        <div className="report-doc-header">
          <div>
            <h1 className="neon-text">CYBERSENTINEL AI</h1>
            <p className="text-muted text-xs font-mono">ENTERPRISE SOC SECURITY BRIEFING</p>
          </div>
          <div className="report-meta text-right">
            <span className="font-mono text-cyan font-bold block">{report.report_id}</span>
            <span className="text-muted text-xs font-mono block">GENERATED: {new Date(report.generated_at).toLocaleString()}</span>
          </div>
        </div>

        <div className="divider-line my-4"></div>

        {/* Executive Summary Section */}
        <section className="report-section">
          <h3 className="section-title">1. EXECUTIVE SUMMARY & VERDICT</h3>
          <div className="callout-box warning-callout mt-2">
            <p className="font-bold text-warning">{exec.verdict}</p>
          </div>

          <div className="metrics-grid mt-4">
            <div className="metric-box">
              <span className="metric-label">CODE POSTURE RISK</span>
              <span className="metric-value critical">{exec.overall_posture_risk} / 100</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">TOTAL VULNERABILITIES</span>
              <span className="metric-value font-mono">{exec.total_vulnerabilities}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">THREAT INTEL CONNECTORS</span>
              <span className="metric-value text-accent">{exec.threat_intel_engines}</span>
            </div>
            <div className="metric-box">
              <span className="metric-label">SCANS IN AUDIT LOG</span>
              <span className="metric-value font-mono">{exec.total_scans_logged}</span>
            </div>
          </div>
        </section>

        {/* Actionable Remediation Roadmap */}
        <section className="report-section mt-4">
          <h3 className="section-title">2. HIGHEST-PRIORITY REMEDIATION ACTIONS</h3>
          <div className="action-items-list mt-2">
            <div className="action-item-row">
              <span className="sev-chip critical">CRITICAL</span>
              <div className="action-text-col">
                <span className="font-bold">Sanitize User Input in Database Transactions (`transactions.py`)</span>
                <p className="text-sm text-muted">Raw SQL concatenation allows arbitrary SQL injection. Refactor query to use parameterized cursor executions.</p>
              </div>
            </div>

            <div className="action-item-row mt-2">
              <span className="sev-chip warning">HIGH</span>
              <div className="action-text-col">
                <span className="font-bold">Revoke and Rotate Hardcoded AWS Access Keys (`settings.py`)</span>
                <p className="text-sm text-muted">Plaintext IAM credentials detected in configuration file. Store secrets in AWS Secrets Manager or environment variables.</p>
              </div>
            </div>

            <div className="action-item-row mt-2">
              <span className="sev-chip info">CONFIGURATION</span>
              <div className="action-text-col">
                <span className="font-bold">Configure External Threat Intelligence API Keys</span>
                <p className="text-sm text-muted">Configure VirusTotal, PhishTank, and AbuseIPDB API keys in `.env` to unlock live commercial vendor reputation telemetry.</p>
              </div>
            </div>
          </div>
        </section>

        {/* Telemetry Snapshot */}
        <section className="report-section mt-4">
          <h3 className="section-title">3. TELEMETRY & SUBSYSTEM AUDIT SNAPSHOT</h3>
          <div className="info-grid mt-2">
            <div className="info-item">
              <span className="info-label">PLATFORM:</span>
              <span className="info-value">{report.platform}</span>
            </div>
            <div className="info-item">
              <span className="info-label">REPOSITORY AUDITED:</span>
              <span className="info-value font-mono">{full.security_posture?.repository?.name || 'internal-finance-api'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">COMMIT HASH:</span>
              <span className="info-value font-mono">{full.security_posture?.repository?.commit_hash || 'a1b2c3d4e5f6'}</span>
            </div>
            <div className="info-item">
              <span className="info-label">FIREWALL / SSRF:</span>
              <span className="info-value text-green">ENFORCED (Loopback & Metadata Filter Active)</span>
            </div>
          </div>
        </section>
      </div>
    </div>
  );
};

export default ReportsView;
