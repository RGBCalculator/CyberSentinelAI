import React, { useState } from 'react';
import { api } from '../services/api';

const Dashboard = ({ user, onLogout }) => {
  const [testResult, setTestResult] = useState(null);
  const [testError, setTestError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleTestProtected = async () => {
    setLoading(true);
    setTestResult(null);
    setTestError(null);
    try {
      const data = await api.testProtected();
      setTestResult(data);
    } catch (err) {
      setTestError(err.message || 'Failed to fetch protected data');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dashboard-container">
      <header className="dashboard-header">
        <div>
          <h1 className="neon-text">CyberSentinel AI</h1>
          <p className="status-indicator">SYSTEM ONLINE</p>
        </div>
        <button onClick={onLogout} className="btn-outline">DISCONNECT</button>
      </header>

      <main className="dashboard-main">
        <section className="panel user-info-panel">
          <h3>OPERATOR PROFILE</h3>
          <div className="info-grid">
            <div className="info-item">
              <span className="info-label">USERNAME:</span>
              <span className="info-value">{user?.username}</span>
            </div>
            <div className="info-item">
              <span className="info-label">EMAIL:</span>
              <span className="info-value">{user?.email}</span>
            </div>
            <div className="info-item">
              <span className="info-label">ROLE:</span>
              <span className="info-value role-badge">{user?.role}</span>
            </div>
            <div className="info-item">
              <span className="info-label">STATUS:</span>
              <span className="info-value">{user?.is_active ? 'ACTIVE' : 'INACTIVE'}</span>
            </div>
          </div>
        </section>

        <section className="panel action-panel">
          <h3>SYSTEM DIAGNOSTICS</h3>
          <p>Verify connection to secured backend channels.</p>
          <button 
            onClick={handleTestProtected} 
            disabled={loading} 
            className="btn-primary mt-4"
          >
            {loading ? 'PINGING...' : 'TEST PROTECTED API'}
          </button>

          {testResult && (
            <div className="api-response success">
              <h4>RESPONSE DETECTED:</h4>
              <pre>{JSON.stringify(testResult, null, 2)}</pre>
            </div>
          )}

          {testError && (
            <div className="api-response error">
              <h4>ERROR DETECTED:</h4>
              <pre>{testError}</pre>
            </div>
          )}
        </section>
      </main>
    </div>
  );
};

export default Dashboard;
