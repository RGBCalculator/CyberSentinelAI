import React, { useState } from 'react';
import { api } from '../services/api';

const SAMPLE_URLS = [
  { label: 'Evasive IP Phishing', url: 'http://192.168.1.1:8080/secure/login.php?user=admin' },
  { label: 'Keyword Query Attack', url: 'https://security-notice.com/login?token=verify-account' },
  { label: 'Standard Safe URL', url: 'https://example.com' }
];

const ExplainableAiView = () => {
  const [testUrl, setTestUrl] = useState('http://192.168.1.1:8080/secure/login.php?user=admin');
  const [analyzing, setAnalyzing] = useState(false);
  const [aiResult, setAiResult] = useState(null);
  const [error, setError] = useState(null);

  const handleExplain = async (e) => {
    if (e) e.preventDefault();
    const url = testUrl.trim();
    if (!url) return;

    setError(null);
    setAnalyzing(true);
    setAiResult(null);

    try {
      const scanRes = await api.scanUrl(url);
      if (scanRes && scanRes.ai_analysis) {
        setAiResult({
          url: url,
          ...scanRes.ai_analysis
        });
      } else {
        setError("AI explanation telemetry was not returned by the backend.");
      }
    } catch (err) {
      setError(err.message || "Failed to execute explainable AI analysis.");
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="xai-view">
      <div className="view-header">
        <div>
          <h2>EXPLAINABLE AI (XAI) & MACHINE LEARNING WORKBENCH</h2>
          <p className="text-muted">Interpretable threat classification, feature attribution vectors, and local decision reasoning (SHAP/LIME).</p>
        </div>
      </div>

      {/* Model Spec & Disclaimer Card */}
      <section className="panel mt-4">
        <div className="repo-header">
          <div>
            <h3>ACTIVE INFERENCE MODEL: CyberSentinel-Ensemble-XGBv2</h3>
            <span className="font-mono text-xs text-muted">FRAMEWORK: scikit-learn / XGBoost • PIPELINE: FeatureEngine + Sigmoid Calibrator</span>
          </div>
          <div>
            <span className="demo-badge">INTERPRETABLE ML</span>
          </div>
        </div>

        <div className="demo-notice-banner mt-3">
          <span className="demo-badge">DISTINCTION NOTICE</span>
          <span className="demo-text">
            Predictions generated here represent probabilistic machine learning inference based on lexical and structural attributes. They are distinct from deterministic signatures and confirmed threat intelligence vendor votes.
          </span>
        </div>
      </section>

      {/* Interactive XAI Console */}
      <section className="panel mt-4">
        <form onSubmit={handleExplain} className="scanner-form">
          <div className="form-group">
            <label htmlFor="xai-target-input">EVALUATE URL THROUGH EXPLAINABILITY ENGINE</label>
            <div className="scanner-input-group">
              <input
                id="xai-target-input"
                type="text"
                value={testUrl}
                onChange={(e) => setTestUrl(e.target.value)}
                placeholder="https://example.com/login"
                className="scanner-input"
                disabled={analyzing}
              />
              <button
                type="submit"
                disabled={analyzing}
                className="btn-primary scanner-btn"
              >
                {analyzing ? 'EXTRACTING ATTRIBUTIONS...' : 'EXPLAIN PREDICTION'}
              </button>
            </div>
          </div>
        </form>

        <div className="sample-picks mt-3">
          <span className="text-muted text-sm">SAMPLE AUDIT URLS:</span>
          {SAMPLE_URLS.map(s => (
            <button
              key={s.label}
              type="button"
              className="btn-outline btn-sm"
              onClick={() => {
                setTestUrl(s.url);
                setError(null);
              }}
              disabled={analyzing}
            >
              {s.label}
            </button>
          ))}
        </div>

        {error && (
          <div className="api-response error mt-4">
            <h4>XAI TELEMETRY ERROR</h4>
            <pre>{error}</pre>
          </div>
        )}
      </section>

      {/* Loading Animation */}
      {analyzing && (
        <div className="panel loading-state mt-4">
          <p className="neon-text blink">EXTRACTING 40+ STRUCTURAL & LEXICAL FEATURES...</p>
          <p className="text-muted text-sm mt-2">Computing feature contribution weights via model attribution engine...</p>
        </div>
      )}

      {/* Results Display */}
      {aiResult && (
        <div className="xai-results mt-4">
          <section className="panel">
            <div className="verdict-header">
              <div>
                <span className="text-muted text-xs font-mono">TARGET EVALUATED:</span>
                <h3 className="font-mono text-cyan">{aiResult.url}</h3>
              </div>
              <div className="verdict-badge-box">
                <span className="text-muted text-xs block">AI CLASSIFICATION</span>
                <span className={`verdict-pill ${aiResult.prediction === 'malicious' ? 'critical' : aiResult.prediction === 'suspicious' ? 'warning' : 'safe'}`}>
                  {aiResult.prediction.toUpperCase()}
                </span>
              </div>
            </div>

            <div className="metrics-grid mt-4">
              <div className="metric-box">
                <span className="metric-label">CALIBRATED PROBABILITY</span>
                <span className={`metric-value ${aiResult.confidence >= 0.6 ? 'critical' : aiResult.confidence >= 0.35 ? 'warning' : 'safe'}`}>
                  {Math.round(aiResult.confidence * 100)}%
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">INFERRED RISK SCORE</span>
                <span className="metric-value font-mono font-bold">
                  {aiResult.risk_score || Math.round(aiResult.confidence * 100)} / 100
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">SHANNON ENTROPY</span>
                <span className="metric-value font-mono text-cyan">
                  {aiResult.feature_summary?.entropy ?? 'N/A'} bits
                </span>
              </div>
              <div className="metric-box">
                <span className="metric-label">KEYWORD ANOMALIES</span>
                <span className="metric-value font-mono text-warning">
                  {aiResult.feature_summary?.suspicious_keywords_found ?? 0}
                </span>
              </div>
            </div>
          </section>

          {/* Feature Attributions Waterfall / Ranked List */}
          <section className="panel mt-4">
            <h3>MOST INFLUENTIAL FEATURE ATTRIBUTIONS (SHAP/LIME EQUIVALENT)</h3>
            <p className="text-muted text-sm mb-4">
              Ranked breakdown of specific lexical and architectural factors driving the model's confidence decision.
            </p>

            {aiResult.top_features && aiResult.top_features.length > 0 ? (
              <div className="attribution-list">
                {aiResult.top_features.map((feat, idx) => {
                  const isPositive = feat.weight > 0;
                  return (
                    <div key={idx} className="attribution-card">
                      <div className="attribution-card-head">
                        <div className="feat-title-group">
                          <span className="feat-rank font-mono text-muted">#{idx + 1}</span>
                          <span className="feat-name font-bold">{feat.feature}</span>
                          <span className="feat-val text-xs text-muted font-mono">[{feat.value}]</span>
                        </div>
                        <div className="feat-badge-group">
                          <span className={`impact-badge ${isPositive ? 'increase' : 'decrease'}`}>
                            {isPositive ? `▲ INCREASES RISK (+${feat.weight})` : `▼ REDUCES RISK (${feat.weight})`}
                          </span>
                        </div>
                      </div>

                      {/* Weight Bar Visualizer */}
                      <div className="weight-bar-bg mt-2">
                        <div 
                          className={`weight-bar-fill ${isPositive ? 'bar-red' : 'bar-green'}`}
                          style={{ width: `${Math.min(Math.abs(feat.weight) * 35, 100)}%` }}
                        />
                      </div>

                      <p className="attribution-expl text-sm text-muted mt-2">
                        {feat.explanation}
                      </p>
                    </div>
                  );
                })}
              </div>
            ) : (
              <p className="text-muted">No anomalous feature deviations observed on this target.</p>
            )}
          </section>
        </div>
      )}
    </div>
  );
};

export default ExplainableAiView;
