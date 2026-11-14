import React from 'react';
import { Link, useNavigate } from 'react-router-dom';

function Navbar() {
  const navigate = useNavigate();

  const handleLogout = async () => {
    try {
      await fetch('/login/logout', { credentials: 'include' });
    } catch {
      // ignore network errors — navigate anyway
    }
    navigate('/login');
  };

  return (
    <nav className="navbar">
      <div className="nav-brand">🔐 USAP FIDO2 Demo</div>
      <div className="nav-links">
        <Link to="/register">Register</Link>
        <Link to="/login">Login</Link>
        <Link to="/dashboard">Dashboard</Link>
        <Link to="/manage-keys">Manage Keys</Link>
        <Link to="/recover-account">Recovery</Link>
        <Link to="/security-testing">Security Testing</Link>
        <button onClick={handleLogout} className="btn-logout">Logout</button>
      </div>
    </nav>
  );
}

export default Navbar;
