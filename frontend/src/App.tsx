import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { ToastProvider } from './context/ToastContext';
import { Navbar } from './components/common/Navbar';
import { Footer } from './components/common/Footer';
import { LandingPage } from './pages/LandingPage';
import { ScanDetailPage } from './pages/ScanDetailPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';

export const AppContent: React.FC = () => {
  return (
    <div className="flex flex-col min-h-screen">
      <Navbar />
      <main className="flex-1">
        <Routes>
          {/* Main Application Routes */}
          <Route path="/" element={<LandingPage />} />
          <Route path="/scan" element={<LandingPage />} />
          <Route path="/scans/:id" element={<ScanDetailPage />} />
          <Route path="/history" element={<ScanHistoryPage />} />

          {/* Clean Redirects for Removed Features */}
          <Route path="/dashboard" element={<Navigate to="/" replace />} />
          <Route path="/admin" element={<Navigate to="/" replace />} />
          <Route path="/settings" element={<Navigate to="/" replace />} />
          <Route path="/login" element={<Navigate to="/" replace />} />
          <Route path="/register" element={<Navigate to="/" replace />} />

          {/* 404 Fallback */}
          <Route path="*" element={<NotFoundPage />} />
        </Routes>
      </main>
      <Footer />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ToastProvider>
      <AuthProvider>
        <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
          <AppContent />
        </BrowserRouter>
      </AuthProvider>
    </ToastProvider>
  );
};

export default App;
