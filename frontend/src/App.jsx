import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import './styles/index.css';

function App() {
  const [currentView, setCurrentView] = useState('login'); // 'login', 'register', 'dashboard'
  const [user, setUser] = useState(null);

  useEffect(() => {
    // Check for existing session
    const token = localStorage.getItem('access_token');
    const storedUser = localStorage.getItem('user');
    
    if (token && storedUser) {
      try {
        setUser(JSON.parse(storedUser));
        setCurrentView('dashboard');
      } catch (e) {
        // Handle invalid JSON in storage
        handleLogout();
      }
    }
  }, []);

  const handleLoginSuccess = (accessToken, refreshToken, userData) => {
    localStorage.setItem('access_token', accessToken);
    if (refreshToken) localStorage.setItem('refresh_token', refreshToken);
    localStorage.setItem('user', JSON.stringify(userData));
    setUser(userData);
    setCurrentView('dashboard');
  };

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user');
    setUser(null);
    setCurrentView('login');
  };

  return (
    <div className="app-container">
      {currentView === 'login' && (
        <Login 
          onLoginSuccess={handleLoginSuccess} 
          switchToRegister={() => setCurrentView('register')} 
        />
      )}
      
      {currentView === 'register' && (
        <Register 
          switchToLogin={() => setCurrentView('login')} 
        />
      )}
      
      {currentView === 'dashboard' && (
        <Dashboard 
          user={user} 
          onLogout={handleLogout} 
        />
      )}
    </div>
  );
}

export default App;
