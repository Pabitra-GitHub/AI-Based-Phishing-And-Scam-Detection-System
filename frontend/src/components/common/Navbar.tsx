import React from 'react';
import { useLocation } from 'react-router-dom';
import {
  Shield,
  Search,
  Sparkles,
  History
} from 'lucide-react';

export const Navbar: React.FC = () => {
  const location = useLocation();

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/' || location.pathname === '/scan';
    return location.pathname.startsWith(path);
  };

  const navLinks = [
    { name: 'URL Scanner', path: '/', icon: <Search className="w-4 h-4" /> },
    { name: 'Scan History', path: '/history', icon: <History className="w-4 h-4" /> },
  ];

  return (
    <nav className="sticky top-0 z-40 glass-panel-strong border-b border-white/70 transition-all">
      <div className="w-full px-4 sm:px-6 lg:px-8">
        <div className="relative flex justify-between h-16 items-center">
          {/* Brand Logo */}
          <a
            href="/"
            onClick={(e) => { e.preventDefault(); window.location.href = '/'; }}
            className="absolute left-1/2 -translate-x-1/2 flex items-center space-x-2.5 group cursor-pointer"
          >
            <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-[#1D4ED8] to-[#60A5FA] flex items-center justify-center text-white shadow-lg shadow-blue-500/30 ring-1 ring-white/70 group-hover:scale-105 transition-transform">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-1.5">
                <span className="font-extrabold text-lg text-slate-900 tracking-tight">PhishGuard</span>
                <span className="bg-blue-100 text-[#2563EB] text-[10px] font-bold px-1.5 py-0.5 rounded-full uppercase tracking-wider flex items-center gap-0.5">
                  <Sparkles className="w-2.5 h-2.5" /> AI
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-medium -mt-1 hidden sm:block">Intelligent URL Threat Intelligence</p>
            </div>
          </a>

          {/* Navigation Links & Telemetry Status */}
          <div className="ml-auto flex items-center space-x-2">
            {navLinks.map((link) => (
              <a
                key={link.path}
                href={link.path}
                onClick={(e) => { e.preventDefault(); window.location.href = link.path; }}
                className={`flex items-center space-x-1.5 px-3.5 py-2 rounded-xl text-sm font-medium transition-all cursor-pointer ${
                  isActive(link.path)
                    ? 'bg-white/60 text-[#2563EB] font-semibold shadow-sm ring-1 ring-white/70'
                    : 'text-slate-600 hover:text-slate-900 hover:bg-white/40'
                }`}
              >
                {link.icon}
                <span>{link.name}</span>
              </a>
            ))}


          </div>
        </div>
      </div>
    </nav>
  );
};
