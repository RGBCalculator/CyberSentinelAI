import React, { useState, useEffect } from 'react';
import { api } from '../services/api';

const ThreatIntelView = () => {
  const [providers, setProviders] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Live lookup state
  const [indicator, setIndicator] = useState('');
  const [indicatorType, setIndicatorType] = useState('url');
  const [lookupRunning, setLookupRunning] = useState(false);
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupError, setLookupError] = useState(null);

  const fetchStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getThreatIntelStatus();
      setProviders(data);
    } catch (err) {
      setError(err.message || "Failed to load threat intelligence status.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleLookup = async (e) => {
    if (e) e.preventDefault();
    const ind = indicator.trim();
    if (!ind) {
      setLookupError("Please specify an indicator to query.");
      return;
    }

    setLookupError(null);
    setLookupRunning(true);
    setLookupResult(null);

    try {
      const res = await api.lookupThreatIntel(ind, indicatorType);
      setLookupResult(res);
    } catch (err) {
      setLookupError(err.message || "Threat intelligence query failed.");
    } finally {
      setLookupRunning(false);
    }
  };

  return (
    <div className="threat-intel-view">
      <div className="view-header">
        <div>
          <h2>GLOBAL THREAT INTELLIGENCE HUB</h2>
          <p className="text-muted">Multi-engine threat feed aggregator querying VirusTotal, PhishTank, OpenPhish, and AbuseIPDB.</p>
        </div>
      </div>

      {/* Provider Integration Matrix */}
      <section className="panel mt-4">
        <div className="panel-header-row">
          <h3>CONNECTOR STATUS MATRIX</h3>
          <button onClick={fetchStatus} disabled={loading} className="btn-outline btn-sm">
            {loading ? 'CHECKING...' : '↻ REFRESH STATUS'}
          </button>
        </div>
        <p className="text-muted text-sm mb-4">
          Credentials are stored in backend environment variables and never exposed to the frontend.
        </p>

        {error && (
          <div className="api-response error mb-4">
            <h4>STATUS ERROR</h4>
            <pre>{error}</pre>
          </div>
        )}

        <div className="providers-grid">
          {Object.entries(providers).map(([key, p]) => (
            <div key={key} className="panel provider-matrix-card">
              <div className="provider-header-row">
                <h4 className="neon-text">{p.name}</h4>
                <span className={`status-pill ${p.configured ? 'ready' : 'unconfigured'}`}>
                  {p.configured ? 'READY' : 'UNCONFIGURED'}
                </span>
              </div>
              <p className="text-sm text-muted mt-2">{p.description}</p>
              
              <div className="provider-meta mt-4">
                <span className="text-xs text-muted block">CAPABILITIES:</span>
                <div className="capabilities-tags mt-1">
                  {p.capabilities?.map(c => (
                    <span key={c} className="cap-tag">{c.toUpperCase()}</span>
                  ))}
                </div>
              </div>

              {!p.configured && (
                <div className="env-tip mt-4">
                  <span className="text-xs text-warning">
                    Set <code className="font-mono">{key.toUpperCase()}_API_KEY</code> in .env to activate live commercial scans.
                  </span>
                </div>
              )}
            </div>
          ))}
        </div>
      </section>

      {/* Live Direct Indicator Query */}
      <section className="panel mt-4">
        <h3>DIRECT THREAT INDICATOR LOOKUP</h3>
        <p className="text-muted text-sm mb-4">
          Query all enabled engines directly for reputation evidence, malware flags, and blacklist verification.
        </p>

        <form onSubmit={handleLookup} className="scanner-form">
          <div className="lookup-controls-row">
            <div className="type-toggle-group">
              {['url', 'domain', 'ip'].map(t => (
                <button
                  key={t}
                  type="button"
                  className={`type-btn ${indicatorType === t ? 'active' : ''}`}
                  onClick={() => setIndicatorType(t)}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="scanner-input-group flex-1">
              <input
                type="text"
                placeholder={indicatorType === 'url' ? 'https://example.com/phish' : indicatorType === 'domain' ? 'suspicious-domain.xyz' : '198.51.100.42'}
                value={indicator}
                onChange={(e) => setIndicator(e.target.value)}
                className="scanner-input"
                disabled={lookupRunning}
              />
              <button 
                type="submit" 
                disabled={lookupRunning}
                className="btn-primary scanner-btn"
              >
                {lookupRunning ? 'QUERYING FEEDS...' : 'LOOKUP INDICATOR'}
              </button>
            </div>
          </div>
        </form>

        {lookupError && (
          <div className="api-response error mt-4">
            <h4>LOOKUP FAILED</h4>
            <pre>{lookupError}</pre>
          </div>
        )}

        {lookupRunning && (
          <div className="loading-state mt-4">
            <p className="neon-text blink">QUERYING GLOBAL THREAT REPOSITORIES...</p>
            <p className="text-muted text-sm mt-2">Checking reputation feeds and blocklists...</p>
          </div>
        )}

        {lookupResult && (
          <div className="lookup-results-box mt-4">
            <div className="repo-header">
              <div>
                <span className="text-muted text-sm font-mono">TARGET EVALUATED:</span>
                <h3 className="font-mono text-cyan">{lookupResult.indicator}</h3>
              </div>
              <div>
                <span className={`verdict-pill ${lookupResult.verdict === 'malicious' ? 'critical' : lookupResult.verdict === 'clean' ? 'safe' : 'warning'}`}>
                  {lookupResult.verdict.toUpperCase()}
                </span>
              </div>
            </div>

            <div className="metrics-grid mt-4">
              <div className="metric-box">
                <span className="metric-label">MALICIOUS VOTES</span>
                <span className={`metric-value ${lookupResult.malicious_count > 0 ? 'critical' : 'safe'}`}>
                  {lookupResult.malicious_count}
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">CLEAN REPORTS</span>
                <span className="metric-value safe">{lookupResult.clean_count}</span>
              </div>
              <div className="metric-box">
                <span className="metric-label">UNCONFIGURED</span>
                <span className="metric-value text-muted">{lookupResult.unconfigured_count}</span>
              </div>
              <div className="metric-box">
                <span className="metric-label">ERRORS / TIMEOUTS</span>
                <span className="metric-value warning">{lookupResult.error_count}</span>
              </div>
            </div>

            {/* Provider Breakdown List */}
            <div className="provider-breakdown-list mt-4">
              {Object.entries(lookupResult.providers || {}).map(([key, item]) => (
                <div key={key} className="provider-result-row">
                  <div className="provider-row-head">
                    <span className="font-bold">{item.name || key}</span>
                    <span className={`status-pill ${item.status === 'malicious' ? 'critical' : item.status === 'clean' ? 'ready' : 'unconfigured'}`}>
                      {item.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-sm text-muted mt-1">{item.details}</p>
                </div>
              ))}
            </div>
          </div>
        )}
      </section>
    </div>
  );
};

export default ThreatIntelView;
