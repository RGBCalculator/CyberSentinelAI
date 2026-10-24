import React, { useState } from 'react';
import { api } from '../services/api';

const BADSSL_TEST_CASES = [
  {
    url: 'http://neverssl.com/',
    label: 'NeverSSL (HTTP-Only)',
    type: 'Plaintext Transport',
    condition: 'Demonstrates lack of HTTPS encryption and vulnerability to interception.'
  },
  {
    url: 'https://expired.badssl.com/',
    label: 'Expired Certificate',
    type: 'Cryptographic Expiry',
    condition: 'Deliberately expired certificate testing expiration checks and date verification.'
  },
  {
    url: 'https://self-signed.badssl.com/',
    label: 'Self-Signed Root',
    type: 'Untrusted Origin',
    condition: 'Self-signed root certificate not anchored in public operating system trust stores.'
  },
  {
    url: 'https://wrong.host.badssl.com/',
    label: 'Hostname Mismatch',
    type: 'SAN / CN Mismatch',
    condition: 'Certificate Subject/SAN does not match requested hostname.'
  },
  {
    url: 'https://untrusted-root.badssl.com/',
    label: 'Untrusted Root CA',
    type: 'Untrusted Hierarchy',
    condition: 'Signed by an untrusted or unknown private Certificate Authority hierarchy.'
  }
];

const STANDARD_SAMPLES = [
  'github.com',
  'cloudflare.com',
  'wikipedia.org'
];

const WebsiteSecurityView = () => {
  const [target, setTarget] = useState('');
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [selectedTestCase, setSelectedTestCase] = useState(null);
  const [showRawEvidence, setShowRawEvidence] = useState(false);

  const handleSelectSample = (sampleUrl, testCase = null) => {
    setTarget(sampleUrl);
    setSelectedTestCase(testCase);
    setError(null);
    setResult(null);
  };

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
          <h2>WEBSITE SECURITY & SSL/TLS CERTIFICATE ANALYZER</h2>
          <p className="text-muted">
            Deep cryptographic audit, X.509 certificate telemetry, authoritative DNS inspection, and WHOIS provenance.
          </p>
        </div>
      </div>

      {/* Authorized Testing Advisory */}
      <div className="advisory-banner mt-4">
        <span className="advisory-icon">⚠️</span>
        <div className="advisory-content">
          <strong>AUTHORIZED TESTING ADVISORY:</strong>
          <span> Only audit systems, domains, and certificates you own or have explicit authorization to test. Use the curated BadSSL test cases below for controlled cryptographic validations.</span>
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
                placeholder="example.com, https://example.com, or select a test case below"
                value={target}
                onChange={(e) => {
                  setTarget(e.target.value);
                  setSelectedTestCase(null);
                }}
                className="scanner-input"
                disabled={analyzing}
              />
              <button 
                type="submit" 
                disabled={analyzing} 
                className="btn-primary scanner-btn"
              >
                {analyzing ? 'AUDITING TARGET...' : 'INSPECT CERTIFICATE & TRUST'}
              </button>
            </div>
          </div>
        </form>

        {/* Curated Test Cases Section */}
        <div className="test-cases-section mt-4">
          <div className="test-cases-header">
            <span className="section-subtitle">CURATED CERTIFICATE TEST CASES</span>
            <span className="test-case-badge">CERTIFICATE TEST CASES — NOT CONFIRMED MALICIOUS</span>
          </div>
          <p className="text-muted text-xs mb-3">
            Officially maintained by BadSSL and NeverSSL to demonstrate specific cryptographic anomalies. Selecting a case populates the target input; click Inspect to initiate the audit.
          </p>

          <div className="test-cases-grid">
            {BADSSL_TEST_CASES.map((tc) => (
              <div
                key={tc.url}
                className={`test-case-card ${target === tc.url ? 'selected' : ''}`}
                onClick={() => handleSelectSample(tc.url, tc)}
              >
                <div className="test-case-top">
                  <span className="test-case-name">{tc.label}</span>
                  <span className="test-case-type">{tc.type}</span>
                </div>
                <div className="test-case-url font-mono">{tc.url}</div>
                <div className="test-case-condition">{tc.condition}</div>
              </div>
            ))}
          </div>

          <div className="standard-samples mt-4">
            <span className="text-muted text-xs">STANDARD BENCHMARKS:</span>
            {STANDARD_SAMPLES.map(d => (
              <button
                key={d}
                type="button"
                className="btn-outline btn-xs"
                onClick={() => handleSelectSample(d, null)}
                disabled={analyzing}
              >
                {d}
              </button>
            ))}
          </div>
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
          <p className="neon-text blink">PERFORMING DEEP CRYPTOGRAPHIC PROBE...</p>
          <p className="text-muted mt-4">
            Negotiating TLS handshake, verifying X.509 certificate chain, testing HTTP redirect, querying authoritative DNS & WHOIS...
          </p>
        </div>
      )}

      {/* Inspection Results */}
      {result && (
        <div className="trust-results mt-4">
          {/* Test Case Context Banner if applicable */}
          {(result.is_test_case || result.certificate?.is_badssl_test_target || selectedTestCase) && (
            <div className="test-case-context-banner panel">
              <div className="test-case-context-header">
                <span className="context-tag">CONTROLLED TEST CASE OBSERVED</span>
                <span className="text-muted text-xs">
                  Expected Condition: {result.test_case_note || selectedTestCase?.condition || 'Controlled certificate misconfiguration'}
                </span>
              </div>
              <p className="test-case-context-text">
                This domain is intentionally configured for automated client validation and does not represent a compromised or phishing host.
              </p>
            </div>
          )}

          {/* Trust Score & Posture Header */}
          <section className="panel">
            <div className="repo-header">
              <div>
                <h2>AUDIT TARGET: {target}</h2>
                <span className="text-muted text-sm font-mono">
                  OBSERVED AT {result.timestamp ? new Date(result.timestamp).toLocaleTimeString() : new Date().toLocaleTimeString()}
                </span>
              </div>
              <div className="trust-badge-box">
                <span className="text-muted text-sm block">TRUST LEVEL:</span>
                <span className={`status-pill ${result.trust_score >= 75 ? 'ready' : result.trust_score >= 50 ? 'warning' : 'critical'}`}>
                  {(result.trust_level || (result.trust_score >= 75 ? 'HIGH' : result.trust_score >= 50 ? 'MEDIUM' : 'LOW')).toUpperCase()}
                </span>
              </div>
            </div>

            <div className="metrics-grid mt-4">
              <div className="metric-box">
                <span className="metric-label">TRUST SCORE</span>
                <span className={`metric-value ${result.trust_score >= 75 ? 'safe' : result.trust_score >= 50 ? 'warning' : 'critical'}`}>
                  {result.trust_score} / 100
                </span>
                <span className="metric-footnote text-muted">Domain & TLS combined</span>
              </div>
              <div className="metric-box">
                <span className="metric-label">TLS CONNECTION</span>
                <span className={`metric-value ${result.certificate?.connection_success !== false ? 'safe' : 'critical'}`}>
                  {result.certificate?.connection_success !== false ? 'ESTABLISHED' : 'FAILED'}
                </span>
                <span className="metric-footnote text-muted">Port 443 Handshake</span>
              </div>
              <div className="metric-box">
                <span className="metric-label">CERTIFICATE STATUS</span>
                <span className={`metric-value ${result.certificate?.expired || result.certificate?.verification_error ? 'critical' : result.certificate?.issuer ? 'safe' : 'warning'}`}>
                  {result.certificate?.expired ? 'EXPIRED' : result.certificate?.verification_error ? 'VERIFY ERROR' : result.certificate?.issuer ? 'VALID' : 'NO TLS'}
                </span>
                <span className="metric-footnote text-muted">
                  {result.certificate?.days_until_expiration !== undefined ? `${result.certificate.days_until_expiration}d to expiry` : 'Status'}
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">HTTP REDIRECT</span>
                <span className={`metric-value ${result.certificate?.http_to_https_redirect ? 'safe' : 'warning'}`}>
                  {result.certificate?.http_to_https_redirect ? 'AUTO-UPGRADED' : 'PLAINTEXT ALLOWED'}
                </span>
                <span className="metric-footnote text-muted">Port 80 → 443 check</span>
              </div>
            </div>

            {/* Crucial Security Distinction Note */}
            <div className="security-distinction-note mt-4">
              <span className="note-icon">ℹ️</span>
              <span className="note-text">
                <strong>Crucial SOC Principle:</strong> A valid TLS certificate and successful encrypted handshake only confirm that transport is encrypted. They do <em>not</em> prove that the destination website is benign, legitimate, or free of phishing.
              </span>
            </div>

            {result.reasons && result.reasons.length > 0 && (
              <div className="trust-reasons mt-4">
                <span className="font-bold text-sm text-cyan block mb-2">AUDIT FINDINGS & FACTORS:</span>
                <ul className="blast-list">
                  {result.reasons.map((r, i) => (
                    <li key={i}>• {r}</li>
                  ))}
                </ul>
              </div>
            )}
          </section>

          {/* Detailed Cards: Deep SSL/TLS Telemetry & Domain Provenance */}
          <div className="detail-grid mt-4">
            {/* Deep SSL/TLS Certificate Card */}
            <section className="panel">
              <div className="panel-header-row">
                <h3>DEEP SSL/TLS CERTIFICATE TELEMETRY</h3>
                {result.certificate?.verification_error && (
                  <span className="sev-chip critical">VERIFICATION ISSUE</span>
                )}
              </div>
              <p className="text-muted text-sm mb-4">Observed cryptographic attributes from server TLS handshake.</p>

              {result.certificate?.verification_error && (
                <div className="verification-error-callout mb-4">
                  <span className="font-bold text-xs block text-error">CERTIFICATE VERIFICATION ERROR:</span>
                  <span className="font-mono text-xs">{result.certificate.verification_error}</span>
                </div>
              )}

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
                  <span className="info-label">HOSTNAME VALIDATION:</span>
                  <span className={`info-value ${result.certificate?.hostname_matched !== false ? 'text-success' : 'text-error'}`}>
                    {result.certificate?.hostname_matched !== false ? '✓ HOSTNAME MATCHED' : '✗ MISMATCH (Subject/SAN)'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">PROTOCOL & CIPHER:</span>
                  <span className="info-value font-mono text-xs">
                    {result.certificate?.tls_version || 'TLS 1.2/1.3'} / {result.certificate?.cipher_suite || 'AES-GCM'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">PUBLIC KEY SPECIFICATION:</span>
                  <span className="info-value font-mono">
                    {result.certificate?.public_key_algorithm || 'RSA'} ({result.certificate?.key_size ? `${result.certificate.key_size} bits` : '2048 bits'})
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">SELF-SIGNED STATUS:</span>
                  <span className={`info-value ${result.certificate?.self_signed ? 'text-error font-bold' : 'text-success'}`}>
                    {result.certificate?.self_signed ? 'YES (HIGH RISK: Untrusted Root)' : 'NO (Publicly Trusted CA)'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">VALID FROM:</span>
                  <span className="info-value text-xs">
                    {result.certificate?.valid_from ? new Date(result.certificate.valid_from).toUTCString() : 'N/A'}
                  </span>
                </div>
                <div className="info-item">
                  <span className="info-label">VALID UNTIL (EXPIRY):</span>
                  <span className={`info-value text-xs ${result.certificate?.expired ? 'text-error font-bold' : ''}`}>
                    {result.certificate?.valid_to ? new Date(result.certificate.valid_to).toUTCString() : 'N/A'}
                  </span>
                </div>
                <div className="info-item full-width">
                  <span className="info-label">SHA-256 FINGERPRINT:</span>
                  <span className="info-value font-mono text-xs hash-box">
                    {result.certificate?.fingerprint_sha256 || 'N/A'}
                  </span>
                </div>
                {result.certificate?.subject_alt_names && result.certificate.subject_alt_names.length > 0 && (
                  <div className="info-item full-width">
                    <span className="info-label">SUBJECT ALTERNATIVE NAMES (SANs):</span>
                    <div className="san-pills-container mt-1">
                      {result.certificate.subject_alt_names.map((san, idx) => (
                        <span key={idx} className="san-pill font-mono">{san}</span>
                      ))}
                    </div>
                  </div>
                )}
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
                  <span className="info-label">DOMAIN AGE:</span>
                  <span className="info-value font-mono">
                    {result.domain?.domain_age_days ? `${result.domain.domain_age_days} days` : 'Unavailable via RDAP'}
                  </span>
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
            <p className="text-muted text-sm mb-4">Authoritative DNS resolution for target host {target}.</p>

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

          {/* Expandable Technical Raw Evidence */}
          <section className="panel mt-4">
            <div className="panel-header-row" style={{ cursor: 'pointer' }} onClick={() => setShowRawEvidence(!showRawEvidence)}>
              <div className="flex items-center gap-2">
                <span>{showRawEvidence ? '▼' : '▶'}</span>
                <h3>RAW TECHNICAL TELEMETRY EVIDENCE</h3>
              </div>
              <span className="text-muted text-xs">{showRawEvidence ? 'CLICK TO COLLAPSE' : 'CLICK TO EXPAND'}</span>
            </div>
            {showRawEvidence && (
              <div className="mt-4">
                <pre className="raw-json-block font-mono text-xs">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  );
};

export default WebsiteSecurityView;
