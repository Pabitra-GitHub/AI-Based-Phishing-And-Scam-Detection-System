import React from "react";
import { Shield } from "lucide-react";
import { Link } from "react-router-dom";

export const Footer: React.FC = () => {
  return (
    <footer className="bg-slate-900 text-slate-400 border-t border-slate-800 text-sm mt-auto">
      <div className="w-full px-4 sm:px-6 lg:px-8 py-10">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          {/* Brand & Project Info */}
          <div className="md:col-span-2 space-y-3">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center text-white">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-extrabold text-white text-base tracking-tight">
                PhishGuard AI
              </span>
            </div>
            <p className="text-xs text-slate-400 max-w-xl leading-relaxed">
              An intelligent, multi-layered cybersecurity URL analysis system
              combining deterministic security heuristics, lexical feature
              extraction, and supervised machine learning classification.
            </p>
          </div>

          {/* Quick Navigation */}
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-3">
              Navigation
            </h4>
            <ul className="space-y-2 text-xs">
              <li>
                <Link to="/" className="hover:text-white transition-colors">
                  Live URL Scanner
                </Link>
              </li>
            </ul>
          </div>

          {/* Academic / Project details */}
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-3">
              Academic Project
            </h4>
            <p className="text-xs text-slate-400 mb-2 font-medium">
              B.Tech Computer Science & Engineering
            </p>
            <p className="text-xs text-slate-500">
              7th Semester — Minor Project
            </p>
            <div className="mt-3 p-2.5 rounded-lg bg-slate-800/80 border border-slate-700/60 text-[11px] text-slate-300">
              🛡️ Phishing Detection Baseline & Candidate Classification Suite
            </div>
          </div>
        </div>

        <div className="border-t border-slate-800/80 mt-8 pt-6 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-500">
          <p>
            © {new Date().getFullYear()} PhishGuard AI. All rights reserved.
          </p>
          <p className="mt-2 sm:mt-0">
            Designed for educational, security demonstration, and defensive
            threat analysis.
            <br />
            <span className="text-slate-400">By Ch. Pabitra Kumar Nayak(Leader) and Team</span>
          </p>
        </div>
      </div>
    </footer>
  );
};
