import React, { useState } from 'react';
import { api } from '../services/api';

const Login = ({ onLoginSuccess, switchToRegister, switchToHome = null }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const data = await api.login(email, password);
      onLoginSuccess(data.access_token, data.refresh_token, data.user);
    } catch (err) {
      setError(err.message || 'Login failed. Please check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="auth-card">
        {switchToHome && (
          <button 
            type="button" 
            onClick={switchToHome}
            className="auth-back-home-btn"
          >
            ← Back to Home
          </button>
        )}
        <div className="auth-header">
          <h2 className="neon-text">CyberSentinel AI</h2>
          <p>SYSTEM AUTHENTICATION</p>
        </div>
        
        {error && <div className="auth-error">{error}</div>}
        
        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label>EMAIL ADDRESS</label>
            <input 
              type="email" 
              value={email} 
              onChange={(e) => setEmail(e.target.value)} 
              required 
              placeholder="operator@cybersentinel.ai"
            />
          </div>
          
          <div className="form-group">
            <label>PASSWORD</label>
            <input 
              type="password" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              required 
              placeholder="••••••••"
            />
          </div>
          
          <button type="submit" disabled={loading} className="btn-primary-landing w-full">
            {loading ? 'AUTHENTICATING...' : 'INITIALIZE LOGIN'}
          </button>
        </form>
        
        <div className="auth-footer">
          <p>No authorization node? <button className="btn-link" onClick={switchToRegister}>Request Access</button></p>
        </div>
      </div>
    </div>
  );
};

export default Login;
