import React, { useState } from 'react';
import { api } from '../services/api';

const Register = ({ switchToLogin, switchToHome = null }) => {
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');

    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);

    try {
      const payload = {
        username: formData.username,
        email: formData.email,
        full_name: formData.full_name || null,
        profile_picture: null,
        password: formData.password
      };
      
      await api.register(payload);
      setSuccess('Registration successful. You may now authenticate.');
      setTimeout(() => switchToLogin(), 2000);
    } catch (err) {
      setError(err.message || 'Registration failed.');
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
          <p>NEW NODE REGISTRATION</p>
        </div>
        
        {error && <div className="auth-error">{error}</div>}
        {success && <div className="auth-success">{success}</div>}
        
        <form onSubmit={handleSubmit} className="auth-form">
          <div className="form-group">
            <label>USERNAME</label>
            <input 
              type="text" 
              name="username"
              value={formData.username} 
              onChange={handleChange} 
              required 
            />
          </div>

          <div className="form-group">
            <label>EMAIL ADDRESS</label>
            <input 
              type="email" 
              name="email"
              value={formData.email} 
              onChange={handleChange} 
              required 
            />
          </div>

          <div className="form-group">
            <label>FULL NAME (OPTIONAL)</label>
            <input 
              type="text" 
              name="full_name"
              value={formData.full_name} 
              onChange={handleChange} 
            />
          </div>
          
          <div className="form-group">
            <label>PASSWORD</label>
            <input 
              type="password" 
              name="password"
              value={formData.password} 
              onChange={handleChange} 
              required 
            />
          </div>

          <div className="form-group">
            <label>CONFIRM PASSWORD</label>
            <input 
              type="password" 
              name="confirmPassword"
              value={formData.confirmPassword} 
              onChange={handleChange} 
              required 
            />
          </div>
          
          <button type="submit" disabled={loading} className="btn-primary-landing w-full">
            {loading ? 'PROCESSING...' : 'REGISTER NODE'}
          </button>
        </form>
        
        <div className="auth-footer">
          <p>Already have access? <button className="btn-link" onClick={switchToLogin}>Return to Login</button></p>
        </div>
      </div>
    </div>
  );
};

export default Register;
