import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Register       from './pages/Register';
import Login          from './pages/Login';
import Dashboard      from './pages/Dashboard';
import SecurityTesting from './pages/SecurityTesting';
import Recovery       from './pages/Recovery';
import ManageKeys     from './pages/ManageKeys';
import Navbar         from './components/Navbar';

function App() {
  return (
    <BrowserRouter>
      <Navbar />
      <div className="main-content">
        <Routes>
          <Route path="/"                 element={<Navigate to="/login" />} />
          <Route path="/register"         element={<Register />} />
          <Route path="/login"            element={<Login />} />
          <Route path="/dashboard"        element={<Dashboard />} />
          <Route path="/manage-keys"      element={<ManageKeys />} />
          <Route path="/recover-account"  element={<Recovery />} />
          <Route path="/security-testing" element={<SecurityTesting />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

export default App;
