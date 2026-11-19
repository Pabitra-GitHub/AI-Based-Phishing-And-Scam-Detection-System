import React, { useState } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles
} from 'lucide-react';
import { ScanForm } from '../components/security/ScanForm';
import { ScanResultCard } from '../components/security/ScanResultCard';
import { Loader } from '../components/common/Loader';
import { Card } from '../components/common/Card';
import { scanApi } from '../services/api';
import { ScanResult } from '../types';
import { useToast } from '../context/ToastContext';

export const LandingPage: React.FC = () => {
  const { addToast } = useToast();
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [sampleUrl, setSampleUrl] = useState<string>('');

  const sampleLinks = [
    { label: '🏛️ India.gov.in', url: 'https://india.gov.in', title: 'Official Government Portal' },
    { label: '🛡️ Google.com', url: 'https://www.google.com', title: 'Verified Authentic Platform' },
    { label: '🛑 Typosquatting', url: 'http://paypa1-security-login.xyz/signin', title: 'Brand Impersonation' },
    { label: '⚠️ Private IP SSRF', url: 'http://192.168.1.1/admin', title: 'Internal Network Target' },
    { label: '🛑 Credential Injection', url: 'https://google.com@attacker-site.top/login', title: '@ Symbol Obfuscation' },
  ];

  const handleScan = async (url: string) => {
    setIsScanning(true);
    setScanResult(null);
    try {
      const result = await scanApi.createScan(url);
      setScanResult(result);
      if (result.classification === 'SAFE') {
        addToast('success', 'URL Verified Safe', 'The link structure is clean and verified.');
      } else {
        addToast('warning', `Threat Detected: ${result.classification}`, `Threat score evaluated at ${result.risk_score}/100.`);
      }
    } catch (err: any) {
      let msg = 'Scan failed. Please verify the URL format and try again.';
      if (err.code === 'ECONNABORTED' || err.message?.includes('timeout')) {
        msg = 'Scan request timed out. The destination website took too long to respond.';
      } else if (err.response?.data?.detail) {
        msg = err.response.data.detail;
      } else if (err.message && !err.response) {
        msg = `Network error: ${err.message}. Please verify the backend server is reachable.`;
      }
      addToast('error', 'Scan Error', msg);
    } finally {
      setIsScanning(false);
    }
  };

  const handleSelectSample = (url: string) => {
    setSampleUrl(url);
    handleScan(url);
  };

  return (
    <div className="w-full px-4 sm:px-6 lg:px-8 py-6 sm:py-8 space-y-8">
      {/* Hero Header */}
      <section className="text-center w-full max-w-6xl mx-auto space-y-4 pt-2">
        <div className="inline-flex items-center space-x-2 px-3.5 py-1 rounded-full bg-blue-50 border border-blue-200 text-blue-700 text-xs font-bold uppercase tracking-wider shadow-xs">
          <Sparkles className="w-3.5 h-3.5 text-blue-600" />
          <span>DSA-Powered Phishing & Scam Detection</span>
        </div>

        <h1 className="text-3xl sm:text-5xl font-extrabold text-slate-900 tracking-tight leading-tight">
          Check Any Link{' '}
          <span className="bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-indigo-600">
            Before You Click
          </span>
        </h1>

        <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-4xl mx-auto">
          Instant cybersecurity inspection powered by Levenshtein edit distance, Trie pattern matching, Shannon entropy, and cryptographic certificate verification.
        </p>

        {/* Real-time Engine Capability Badges */}
        <div className="flex flex-wrap items-center justify-center gap-2 pt-2 text-[11px] font-medium text-slate-500">
          <span className="px-2.5 py-1 rounded-md bg-white border border-slate-200 shadow-xs flex items-center gap-1.5">
            🏛️ Sovereign Govt Whitelist (.gov / .nic.in)
          </span>
          <span className="px-2.5 py-1 rounded-md bg-white border border-slate-200 shadow-xs flex items-center gap-1.5">
            ⚡ O(L) Trie Registry Matcher
          </span>

          <span className="px-2.5 py-1 rounded-md bg-white border border-slate-200 shadow-xs flex items-center gap-1.5">
            🌐 Live Website & Credential Prober
          </span>

        </div>
      </section>

      {/* Main Scan Form Card */}
      <Card className="w-full p-6 sm:p-8 shadow-md border-slate-200">
        <ScanForm onScan={handleScan} isLoading={isScanning} initialUrl={sampleUrl} />

        {/* Quick Click Sample Links */}
        <div className="mt-5 pt-4 border-t border-slate-100">
          <div className="text-xs font-bold text-slate-500 uppercase tracking-wider mb-2 flex items-center justify-between">
            <span>Instant Test Links:</span>
            <span className="text-[11px] font-normal text-slate-400">Click any sample to test immediately</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {sampleLinks.map((item, idx) => (
              <button
                key={idx}
                type="button"
                onClick={() => handleSelectSample(item.url)}
                disabled={isScanning}
                className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-slate-100 hover:bg-blue-50 hover:text-blue-700 text-slate-700 border border-slate-200/80 transition-all flex items-center gap-1.5 disabled:opacity-50"
                title={item.title}
              >
                <span>{item.label}</span>
              </button>
            ))}
          </div>
        </div>
      </Card>

      {/* Loading state */}
      {isScanning && (
        <Card className="p-8 shadow-sm">
          <Loader message="Running DSA safety checks: Levenshtein distance, Trie keyword scan, and SSL verification..." />
        </Card>
      )}

      {/* Scan Results */}
      {scanResult && !isScanning && (
        <div className="space-y-4 animate-in fade-in duration-300">
          <div className="flex items-center justify-between">
            <h3 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-600" />
              Safety Verdict & Inspection Breakdown
            </h3>
            <button
              onClick={() => setScanResult(null)}
              className="text-xs text-blue-600 hover:underline font-semibold"
            >
              Clear Result
            </button>
          </div>
          <ScanResultCard result={scanResult} onRescan={() => handleScan(scanResult.input_value)} />
        </div>
      )}
    </div>
  );
};
