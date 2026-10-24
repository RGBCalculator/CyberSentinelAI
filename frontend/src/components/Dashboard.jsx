import React, { useState } from 'react';
import SocOverview from './SocOverview';
import UrlScannerView from './UrlScannerView';
import WebsiteSecurityView from './WebsiteSecurityView';
import ThreatIntelView from './ThreatIntelView';
import FindingsExplorer from './FindingsExplorer';
import ExplainableAiView from './ExplainableAiView';
import PostureView from './PostureView';
import ReportsView from './ReportsView';
import { api } from '../services/api';

const Dashboard = ({ user, onLogout }) => {
  const [activeTab, setActiveTab] = useState('overview'); // 'overview' | 'scanner' | 'website' | 'intel' | 'findings' | 'ai' | 'posture' | 'reports' | 'profile'
  const [globalSearch, setGlobalSearch] = useState('');
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  // Diagnostics state for Operator Profile tab
  const [testResult, setTestResult] = useState(null);
  const [testError, setTestError] = useState(null);
  const [loadingDiagnostics, setLoadingDiagnostics] = useState(false);

  const handleTestProtected = async () => {
    setLoadingDiagnostics(true);
    setTestResult(null);
    setTestError(null);
    try {
      const data = await api.testProtected();
      setTestResult(data);
    } catch (err) {
      setTestError(err.message || 'Failed to fetch protected diagnostics');
    } finally {
      setLoadingDiagnostics(false);
    }
  };

  const handleNavigate = (tab, findingId = null) => {
    if (findingId) {
      setSelectedFindingId(findingId);
    } else {
      setSelectedFindingId(null);
    }
    setActiveTab(tab);
  };

  const handleGlobalSearchSubmit = (e) => {
    e.preventDefault();
    if (globalSearch.trim()) {
      setActiveTab('findings');
    }
  };

  const navItems = [
    { section: 'OPERATIONS', items: [
      { id: 'overview', label: 'SOC OVERVIEW', icon: '📊' },
      { id: 'scanner', label: 'URL THREAT SCANNER', icon: '🔍' },
      { id: 'website', label: 'WEBSITE & SSL AUDIT', icon: '🌐' },
      { id: 'intel', label: 'THREAT INTELLIGENCE', icon: '🛡️' },
    ]},
    { section: 'VULNERABILITY INTELLIGENCE', items: [
      { id: 'findings', label: 'FINDINGS EXPLORER', icon: '📋' },
      { id: 'ai', label: 'EXPLAINABLE AI (XAI)', icon: '🧠' },
      { id: 'posture', label: 'CODE POSTURE (DEMO)', icon: '💻' },
    ]},
    { section: 'GOVERNANCE & SYSTEM', items: [
      { id: 'reports', label: 'SECURITY REPORTS', icon: '📑' },
      { id: 'profile', label: 'OPERATOR & DIAGNOSTICS', icon: '⚙️' },
    ]}
  ];

  return (
    <div className="soc-layout">
      {/* Persistent Left Navigation Sidebar */}
      <aside className="soc-sidebar" aria-label="SOC Navigation">
        <div className="sidebar-brand">
          <div className="brand-logo-icon">🛡️</div>
          <div>
            <h1 className="neon-text brand-title">CyberSentinel</h1>
            <span className="brand-subtitle font-mono">SOC PLATFORM v2.1</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          {navItems.map((sec, idx) => (
            <div key={idx} className="nav-section">
              <span className="nav-section-title">{sec.section}</span>
              {sec.items.map(item => (
                <button
                  key={item.id}
                  type="button"
                  className={`sidebar-nav-item ${activeTab === item.id ? 'active' : ''}`}
                  onClick={() => handleNavigate(item.id)}
                  id={`nav-${item.id}-btn`}
                >
                  <span className="nav-item-icon">{item.icon}</span>
                  <span className="nav-item-text">{item.label}</span>
                </button>
              ))}
            </div>
          ))}
        </nav>

        {/* Sidebar Operator Status Card */}
        <div className="sidebar-operator-card">
          <div className="operator-details">
            <span className="text-xs text-muted block font-mono">OPERATOR</span>
            <span className="font-bold text-sm text-cyan truncate block">{user?.email || 'operator@sentinel'}</span>
            <span className="role-badge mt-1">{user?.role || 'SOC_ANALYST'}</span>
          </div>
          <button onClick={onLogout} className="btn-outline btn-xs w-full mt-3" title="Log out of session">
            DISCONNECT
          </button>
        </div>
      </aside>

      {/* Main Command Center Layout */}
      <div className="soc-main-area">
        {/* Top Header Command Bar */}
        <header className="soc-topbar">
          <div className="topbar-left">
            <span className="active-view-tag font-mono text-cyan">
              COMMAND // {activeTab.toUpperCase()}
            </span>
            <span className="status-indicator">SYSTEM ONLINE</span>
          </div>

          <form onSubmit={handleGlobalSearchSubmit} className="topbar-search">
            <input
              type="text"
              placeholder="Search findings, CVEs, targets..."
              value={globalSearch}
              onChange={(e) => setGlobalSearch(e.target.value)}
              className="topbar-search-input font-mono"
            />
            <button type="submit" className="search-icon-btn">🔍</button>
          </form>

          <div className="topbar-actions">
            <span className="soc-status-badge">
              <span className="pulse-dot"></span> THREAT SHIELD ACTIVE
            </span>
            <button onClick={onLogout} className="btn-outline btn-sm">
              LOGOUT
            </button>
          </div>
        </header>

        {/* Main Routed Content View */}
        <main className="soc-content-container">
          {activeTab === 'overview' && (
            <SocOverview onNavigate={handleNavigate} />
          )}

          {activeTab === 'scanner' && (
            <UrlScannerView />
          )}

          {activeTab === 'website' && (
            <WebsiteSecurityView />
          )}

          {activeTab === 'intel' && (
            <ThreatIntelView />
          )}

          {activeTab === 'findings' && (
            <FindingsExplorer initialFindingId={selectedFindingId} />
          )}

          {activeTab === 'ai' && (
            <ExplainableAiView />
          )}

          {activeTab === 'posture' && (
            <div className="posture-container">
              <PostureView />
            </div>
          )}

          {activeTab === 'reports' && (
            <ReportsView />
          )}

          {activeTab === 'profile' && (
            <div className="operator-profile-view">
              <div className="view-header">
                <div>
                  <h2>OPERATOR PROFILE & BACKEND DIAGNOSTICS</h2>
                  <p className="text-muted">Session credential telemetry and direct channel diagnostic pings.</p>
                </div>
              </div>

              <div className="dashboard-main mt-4" style={{ padding: 0 }}>
                <section className="panel user-info-panel">
                  <h3>OPERATOR PROFILE</h3>
                  <div className="info-grid">
                    <div className="info-item">
                      <span className="info-label">USERNAME:</span>
                      <span className="info-value font-mono">{user?.username}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">EMAIL:</span>
                      <span className="info-value font-mono">{user?.email}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">ROLE:</span>
                      <span className="info-value role-badge">{user?.role}</span>
                    </div>
                    <div className="info-item">
                      <span className="info-label">ACCOUNT STATUS:</span>
                      <span className="info-value">{user?.is_active ? 'ACTIVE' : 'INACTIVE'}</span>
                    </div>
                  </div>
                </section>

                <section className="panel action-panel">
                  <h3>BACKEND CHANNEL DIAGNOSTICS</h3>
                  <p className="text-muted text-sm">Verify JWT signature and connectivity to secured backend API channels.</p>
                  <button 
                    onClick={handleTestProtected} 
                    disabled={loadingDiagnostics} 
                    className="btn-primary mt-4"
                  >
                    {loadingDiagnostics ? 'PINGING CHANNEL...' : 'TEST PROTECTED API'}
                  </button>

                  {testResult && (
                    <div className="api-response success mt-4">
                      <h4>CHANNEL DIAGNOSTIC SUCCESS</h4>
                      <pre>{JSON.stringify(testResult, null, 2)}</pre>
                    </div>
                  )}

                  {testError && (
                    <div className="api-response error mt-4">
                      <h4>DIAGNOSTIC FAILURE</h4>
                      <pre>{testError}</pre>
                    </div>
                  )}
                </section>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default Dashboard;
