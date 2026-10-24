import React, { useState } from 'react';
import { api } from '../services/api';

const SAMPLE_DOMAINS = [
  'github.com',
  'cloudflare.com',
  'wikipedia.org'
];

const WebsiteSecurityView = () => {
  const [target, setTarget] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalyze = async (e) => {
    if (e) e.preventDefault();
    const domain = target.trim();
    if (!domain) {
      setError("Please specify a target domain or URL.");
      return;
    }

    setError(null);
    setAnalyzing(true);
    setResult(null);

    try {
      const data = await api.analyzeWebsite(domain);
      setResult(data);
    } catch (err) {
      setError(err.message || "Website security inspection failed.");
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="website-security-view">
      <div className="view-header">
        <div>
          <h2>WEBSITE SECURITY & TRUST INTELLIGENCE INSPECTOR</h2>
          <p className="text-muted">Automated SSL/TLS certificate validation, WHOIS domain provenance, and authoritative DNS audits.</p>
        </div>
      </div>

      {/* Target Input Panel */}
      <section className="panel mt-4">
        <form onSubmit={handleAnalyze} className="scanner-form">
          <div className="form-group">
            <label htmlFor="website-target-input">ENTER DOMAIN OR URL FOR DEEP AUDIT</label>
            <div className="scanner-input-group">
              <input
                id="website-target-input"
                type="text"
                placeholder="example.com or https://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="scanner-input"
                disabled={analyzing}
              />
              <button 
                type="submit" 
                disabled={analyzing} 
                className="btn-primary scanner-btn"
              >
                {analyzing ? 'AUDITING TARGET...' : 'INSPECT WEB TRUST'}
              </button>
            </div>
          </div>
        </form>

        <div className="sample-picks mt-4">
          <span className="text-muted text-sm">SAMPLE TARGETS:</span>
          {SAMPLE_DOMAINS.map(d => (
            <button
              key={d}
              type="button"
              className="btn-outline btn-sm"
              onClick={() => {
                setTarget(d);
                setError(null);
              }}
              disabled={analyzing}
            >
              {d}
            </button>
          ))}
        </div>

        {error && (
          <div className="api-response error mt-4">
            <h4>AUDIT ERROR</h4>
            <pre>{error}</pre>
          </div>
        )}
      </section>

      {/* Loading Animation */}
      {analyzing && (
        <div className="panel loading-state mt-4">
          <p className="neon-text blink">GATHERING TRUST SIGNALS...</p>
          <p className="text-muted mt-4">Connecting to TLS endpoint, authoritative DNS resolvers, and WHOIS registries...</p>
        </div>
      )}

      {/* Inspection Results */}
      {result && (
        <div className="trust-results mt-4">
          {/* Trust Score Header */}
          <section className="panel">
            <div className="repo-header">
              <div>
                <h2>AUDIT TARGET: {target}</h2>
                <span className="text-muted text-sm font-mono">TRUST EVALUATION COMPLETED</span>
              </div>
              <div className="trust-badge-box">
                <span className="text-muted text-sm block">TRUST LEVEL:</span>
                <span className={`status-pill ${result.trust_score >= 75 ? 'ready' : result.trust_score >= 50 ? 'warning' : 'critical'}`}>
                  {(result.trust_level || 'MEDIUM').toUpperCase()}
                </span>
              </div>
            </div>

            <div className="metrics-grid mt-4">
              <div className="metric-box">
                <span className="metric-label">TRUST SCORE</span>
                <span className={`metric-value ${result.trust_score >= 75 ? 'safe' : result.trust_score >= 50 ? 'warning' : 'critical'}`}>
                  {result.trust_score} / 100
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">SSL STATUS</span>
                <span className={`metric-value ${result.certificate?.expired ? 'critical' : 'safe'}`}>
                  {result.certificate?.expired ? 'EXPIRED' : result.certificate?.issuer ? 'VALID' : 'UNVERIFIED'}
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">DOMAIN AGE</span>
                <span className="metric-value font-mono">
                  {result.domain?.domain_age_days ? `${result.domain.domain_age_days}d` : 'N/A'}
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">REPUTATION</span>
                <span className={`metric-value ${result.reputation?.blacklisted ? 'critical' : 'safe'}`}>
                  {result.reputation?.blacklisted ? 'LISTED' : 'CLEAN'}
                </span>
              </div>
            </div>

            {result.reasons && result.reasons.length > 0 && (
              <div className="trust-reasons mt-4">
                <span className="font-bold text-sm text-cyan block mb-2">EVALUATION FINDINGS:</span>
                <ul className="blast-list">
                  {result.reasons.map((r, i) => (
                    <li key={i}>• {r}</li>
                  ))}
                </ul>
              </div>
            )}
          </section>

          {/* Deep Cards Grid: SSL, WHOIS, DNS */}
          <div className="detail-grid mt-4">
            {/* SSL/TLS Certificate Card */}
            <section className="panel">
              <h3>SSL/TLS CERTIFICATE</h3>
              <p className="text-muted text-sm mb-4">Cryptographic identity and validity parameters.</p>
              
              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">ISSUER:</span>
                  <span className="info-value font-mono">{result.certificate?.issuer || 'None/Unresolved'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">SUBJECT:</span>
                  <span className="info-value font-mono">{result.certificate?.subject || 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">VALID FROM:</span>
                  <span className="info-value text-sm">{result.certificate?.valid_from ? new Date(result.certificate.valid_from).toLocaleDateString() : 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">VALID TO (EXPIRATION):</span>
                  <span className="info-value text-sm">{result.certificate?.valid_to ? new Date(result.certificate.valid_to).toLocaleDateString() : 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">ENCRYPTION KEY SIZE:</span>
                  <span className="info-value font-mono">{result.certificate?.key_size ? `${result.certificate.key_size} bits` : 'Standard'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">SELF-SIGNED:</span>
                  <span className="info-value">{result.certificate?.self_signed ? 'YES (HIGH RISK)' : 'NO (STANDARD CA)'}</span>
                </div>
              </div>
            </section>

            {/* WHOIS Domain Provenance Card */}
            <section className="panel">
              <h3>WHOIS & DOMAIN PROVENANCE</h3>
              <p className="text-muted text-sm mb-4">Registration age, registrar identity, and privacy indicators.</p>

              <div className="info-grid">
                <div className="info-item">
                  <span className="info-label">REGISTRAR:</span>
                  <span className="info-value">{result.domain?.registrar || 'Not Disclosed / Privacy Shield'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">ESTABLISHED:</span>
                  <span className="info-value">{result.domain?.creation_date ? new Date(result.domain.creation_date).toLocaleDateString() : 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">REGISTRATION EXPIRES:</span>
                  <span className="info-value">{result.domain?.expiration_date ? new Date(result.domain.expiration_date).toLocaleDateString() : 'N/A'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">COUNTRY CODE:</span>
                  <span className="info-value font-mono">{result.domain?.country || 'GLOBAL'}</span>
                </div>
                <div className="info-item">
                  <span className="info-label">WHOIS PRIVACY:</span>
                  <span className="info-value">{result.domain?.privacy_protected ? 'PROTECTED' : 'PUBLIC'}</span>
                </div>
              </div>
            </section>
          </div>

          {/* DNS Records Panel */}
          <section className="panel mt-4">
            <h3>AUTHORITATIVE DNS RECORDS</h3>
            <p className="text-muted text-sm mb-4">Resolved DNS records for {target}.</p>

            <div className="dns-records-grid">
              <div className="dns-record-col">
                <span className="dns-type-label">A RECORDS (IPv4):</span>
                {result.dns?.a_records && result.dns.a_records.length > 0 ? (
                  <ul className="dns-list">
                    {result.dns.a_records.map((r, i) => <li key={i} className="font-mono">{r}</li>)}
                  </ul>
                ) : <span className="text-muted text-xs">No records</span>}
              </div>

              <div className="dns-record-col">
                <span className="dns-type-label">MX RECORDS (MAIL):</span>
                {result.dns?.mx_records && result.dns.mx_records.length > 0 ? (
                  <ul className="dns-list">
                    {result.dns.mx_records.map((r, i) => <li key={i} className="font-mono">{r}</li>)}
                  </ul>
                ) : <span className="text-muted text-xs">No records</span>}
              </div>

              <div className="dns-record-col">
                <span className="dns-type-label">NS RECORDS (NAMESERVERS):</span>
                {result.dns?.ns_records && result.dns.ns_records.length > 0 ? (
                  <ul className="dns-list">
                    {result.dns.ns_records.map((r, i) => <li key={i} className="font-mono">{r}</li>)}
                  </ul>
                ) : <span className="text-muted text-xs">No records</span>}
              </div>

              <div className="dns-record-col">
                <span className="dns-type-label">TXT RECORDS (SPF/DKIM):</span>
                {result.dns?.txt_records && result.dns.txt_records.length > 0 ? (
                  <ul className="dns-list">
                    {result.dns.txt_records.map((r, i) => <li key={i} className="font-mono text-xs">{r}</li>)}
                  </ul>
                ) : <span className="text-muted text-xs">No records</span>}
              </div>
            </div>
          </section>
        </div>
      )}
    </div>
  );
};

export default WebsiteSecurityView;
