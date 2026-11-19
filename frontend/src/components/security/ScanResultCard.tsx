import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ShieldAlert,
  ShieldCheck,
  Brain,
  ExternalLink,
  Copy,
  Check,
  Info,
  Calendar,
  Layers,
  ArrowRight,
  Globe,
  Server,
  Lock,
  Radio
} from 'lucide-react';
import { ScanResult } from '../../types';
import { RiskGauge } from './RiskGauge';
import { RiskBadge } from './RiskBadge';
import { ReasonCard } from './ReasonCard';
import { RedirectChainView } from './RedirectChainView';
import { Button } from '../common/Button';
import { useToast } from '../../context/ToastContext';
import { formatDateTime, formatShortTime } from '../../utils/date';

export interface ScanResultCardProps {
  result: ScanResult;
  onRescan?: () => void;
  showDeepLink?: boolean;
}

export const ScanResultCard: React.FC<ScanResultCardProps> = ({
  result,
  showDeepLink = true,
}) => {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const [copiedReport, setCopiedReport] = useState(false);
  const [copiedUrl, setCopiedUrl] = useState(false);

  const isSafe = result.classification === 'SAFE';
  const isThreat = !isSafe;

  const handleCopyReport = () => {
    const report = `[PhishGuard AI Scan Report]
Target URL: ${result.input_value}
Safety Verdict: ${result.classification} (Risk Score: ${result.risk_score}/100)
AI ML Probability: ${(result.ml_probability * 100).toFixed(1)}%
Recommendation: ${result.recommendation}
Reasons:
${result.detection_reasons.map((r, i) => ` ${i + 1}. [${r.severity}] ${r.title}: ${r.reason}`).join('\n')}
Date: ${formatDateTime(result.created_at)}`;

    navigator.clipboard.writeText(report);
    setCopiedReport(true);
    addToast('success', 'Report Copied', 'Summary copied to clipboard.');
    setTimeout(() => setCopiedReport(false), 2000);
  };

  const handleCopyUrl = () => {
    navigator.clipboard.writeText(result.input_value);
    setCopiedUrl(true);
    addToast('success', 'URL Copied', 'Destination URL copied to clipboard.');
    setTimeout(() => setCopiedUrl(false), 2000);
  };

  // Helper tags for verified domains and protocol status
  const tags: { label: string; color: string }[] = [];
  if (result.features?.is_government_domain === 1) {
    tags.push({
      label: `🏛️ Official Govt (${result.features.government_entity || 'Portal'})`,
      color: 'bg-emerald-100 text-emerald-800 border-emerald-300'
    });
  }
  if (result.features?.is_authentic_brand === 1) {
    tags.push({
      label: `🛡️ Verified Brand (${result.features.authentic_brand_name || 'Official'})`,
      color: 'bg-blue-100 text-blue-800 border-blue-300'
    });
  }
  if (result.features?.dns_resolvable === 0 || result.features?.dns_resolvable === false) {
    tags.push({ label: '⚠️ NXDOMAIN Unresolvable', color: 'bg-red-100 text-red-700 border-red-200' });
  }
  if (result.features?.is_https === 0) {
    tags.push({ label: '🔓 Insecure HTTP', color: 'bg-amber-100 text-amber-800 border-amber-200' });
  } else if (result.features?.ssl_valid === 0) {
    tags.push({ label: '❌ Invalid SSL Certificate', color: 'bg-red-100 text-red-700 border-red-200' });
  }
  if (result.features?.is_cross_domain_redirect) {
    tags.push({ label: '🔀 Cross-Domain Redirect', color: 'bg-orange-100 text-orange-800 border-orange-200' });
  }

  return (
    <div className="glass-panel-strong rounded-2xl overflow-hidden animate-in fade-in duration-200">
      {/* Top Banner Header */}
      <div
        className={`px-4 sm:px-6 lg:px-8 py-4 border-b flex flex-wrap items-center justify-between gap-3 ${
          isSafe ? 'bg-emerald-50/80 border-emerald-100' : 'bg-red-50/80 border-red-100'
        }`}
      >
        <div className="flex items-center space-x-3.5">
          <div
            className={`w-10 h-10 rounded-xl flex items-center justify-center text-white shadow-xs ${
              isSafe ? 'bg-emerald-600' : 'bg-red-600'
            }`}
          >
            {isSafe ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider">Verdict:</span>
              <RiskBadge classification={result.classification} size="sm" />
            </div>
            <p className="text-xs text-slate-600 font-medium mt-0.5">
              {result.features?.is_government_domain === 1
                ? `🏛️ Sovereign Government Portal (${result.features.government_entity || 'Public Sector'})`
                : result.features?.is_authentic_brand === 1
                ? `🛡️ Verified Authentic Infrastructure for ${result.features.authentic_brand_name || 'Official Brand'}`
                : 'Analyzed with deterministic DSA Security Engine & Heuristics'}
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={handleCopyReport}
            leftIcon={copiedReport ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
          >
            {copiedReport ? 'Copied' : 'Copy Report'}
          </Button>

          {showDeepLink && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate(`/scans/${result.id}`)}
              rightIcon={<ArrowRight className="w-3.5 h-3.5" />}
            >
              Inspection Details
            </Button>
          )}
        </div>
      </div>

      {/* Main Content Layout */}
      <div className="p-4 sm:p-6 lg:p-8 grid grid-cols-1 lg:grid-cols-12 gap-6 lg:gap-8">
        {/* Left Column: Gauge & Risk Breakdown */}
        <div className="lg:col-span-4 xl:col-span-3 flex flex-col items-center justify-start p-6 lg:p-7 bg-slate-50/90 rounded-2xl border border-slate-200/80 text-center">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-4">
            Security Risk Score
          </span>

          <RiskGauge score={result.risk_score} classification={result.classification} size="lg" />

          <div className="mt-6 w-full space-y-2.5 pt-4 border-t border-slate-200 text-xs">
            <div className="flex items-center justify-between text-slate-600">
              <span className="flex items-center gap-1.5 font-medium">
                <Brain className="w-3.5 h-3.5 text-purple-600" /> ML Probability:
              </span>
              <span className="font-mono font-bold text-slate-900">
                {(result.ml_probability * 100).toFixed(1)}%
              </span>
            </div>

            <div className="flex items-center justify-between text-slate-600">
              <span className="flex items-center gap-1.5 font-medium">
                <Layers className="w-3.5 h-3.5 text-blue-600" /> Engine:
              </span>
              <span className="font-mono text-slate-700 text-[11px]">{result.model_version}</span>
            </div>

            <div className="flex items-center justify-between text-slate-600">
              <span className="flex items-center gap-1.5 font-medium">
                <Calendar className="w-3.5 h-3.5 text-slate-500" /> Scanned At:
              </span>
              <span className="text-slate-700 text-[11px]">
                {formatShortTime(result.created_at)}
              </span>
            </div>

            {/* Additional network and host verification parameters */}
            <div className="pt-2.5 border-t border-slate-200/70 space-y-2">
              <div className="flex items-center justify-between text-slate-600">
                <span className="flex items-center gap-1.5 font-medium">
                  <Server className="w-3.5 h-3.5 text-indigo-600" /> Host IP:
                </span>
                <span className="font-mono text-slate-800 text-[11px] font-semibold truncate max-w-[170px]" title={result.features?.resolved_ip || 'Resolved via Socket'}>
                  {result.features?.resolved_ip || (result.features?.dns_resolvable === 0 ? 'NXDOMAIN' : 'Active Socket')}
                </span>
              </div>

              <div className="flex items-center justify-between text-slate-600">
                <span className="flex items-center gap-1.5 font-medium">
                  <Lock className="w-3.5 h-3.5 text-emerald-600" /> Protocol:
                </span>
                <span className="font-mono text-slate-800 text-[11px] font-semibold">
                  {result.features?.is_https === 1 ? 'HTTPS (Port 443)' : 'HTTP (Port 80)'}
                </span>
              </div>

              <div className="flex items-center justify-between text-slate-600">
                <span className="flex items-center gap-1.5 font-medium">
                  <Radio className="w-3.5 h-3.5 text-blue-500" /> Latency:
                </span>
                <span className="font-mono text-slate-800 text-[11px] font-semibold">
                  {result.scan_duration_ms ? `${result.scan_duration_ms} ms` : '< 150 ms'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: Scanned Target, Guidance & Triggered Reasons */}
        <div className="lg:col-span-8 xl:col-span-9 space-y-6">
          {/* Target URL Display */}
          <div>
            <div className="flex flex-wrap items-center justify-between gap-1.5 mb-2">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                Scanned Destination Link
              </span>
              {tags.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5">
                  {tags.map((tag, idx) => (
                    <span
                      key={idx}
                      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-bold border ${tag.color}`}
                    >
                      {tag.label}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center justify-between p-3.5 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs break-all border border-slate-800 shadow-inner">
              <span className="truncate pr-3">{result.input_value}</span>
              <div className="flex items-center space-x-1.5 flex-shrink-0">
                <button
                  type="button"
                  onClick={handleCopyUrl}
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                  title="Copy URL"
                >
                  {copiedUrl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
                <a
                  href={result.input_value}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
                  title="Open URL in new tab (Caution)"
                >
                  <ExternalLink className="w-3.5 h-3.5" />
                </a>
              </div>
            </div>
          </div>

          {/* Live Website Safety & Good/Bad Verdict Box */}
          <div
            className={`p-5 rounded-2xl border flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xs ${
              isSafe
                ? 'bg-emerald-50/90 border-emerald-200 text-emerald-950'
                : 'bg-red-50/90 border-red-200 text-red-950'
            }`}
          >
            <div className="flex items-start md:items-center gap-3.5">
              <div
                className={`w-10 h-10 rounded-xl flex items-center justify-center text-white flex-shrink-0 shadow-xs ${
                  isSafe ? 'bg-emerald-600' : 'bg-red-600'
                }`}
              >
                <Globe className="w-5 h-5" />
              </div>
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500">
                    Live Website Check:
                  </span>
                  <span
                    className={`text-xs font-extrabold px-2.5 py-0.5 rounded-full ${
                      isSafe ? 'bg-emerald-200/70 text-emerald-900' : 'bg-red-200/70 text-red-900'
                    }`}
                  >
                    {isSafe ? '✅ GOOD WEBSITE (AUTHENTIC)' : '🛑 BAD WEBSITE (SECURITY THREAT)'}
                  </span>
                  {result.features?.is_government_domain === 1 && (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-800 border border-emerald-300">
                      🏛️ Official Sovereign Government
                    </span>
                  )}
                  {result.features?.is_authentic_brand === 1 && (
                    <span className="text-[11px] font-bold px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 border border-blue-300">
                      🛡️ Verified Authentic {result.features.authentic_brand_name}
                    </span>
                  )}
                </div>
                <p className="text-xs font-medium text-slate-700 leading-relaxed">
                  {isSafe
                    ? 'Verified authentic destination with valid cryptographic certificates and genuine registry status.'
                    : 'Deceptive or dangerous destination posing risk of credential harvesting, malware, or brand spoofing.'}
                  {result.features?.page_title && (
                    <span className="block text-[11px] text-slate-600 font-medium mt-1">
                      Webpage Title: <span className="font-semibold text-slate-900">"{result.features.page_title}"</span>
                    </span>
                  )}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold flex-shrink-0">
              {result.features?.http_status && (
                <span className="px-3 py-1.5 rounded-lg bg-white border border-slate-200 text-slate-700 font-mono shadow-xs">
                  HTTP {result.features.http_status}
                </span>
              )}
              <span
                className={`px-3 py-1.5 rounded-lg border shadow-xs ${
                  result.features?.dns_resolvable === 0 || result.features?.dns_resolvable === false
                    ? 'bg-red-100 text-red-700 border-red-200'
                    : 'bg-emerald-100 text-emerald-700 border-emerald-200'
                }`}
              >
                {result.features?.dns_resolvable === 0 || result.features?.dns_resolvable === false
                  ? 'Host Inactive / NXDOMAIN'
                  : result.features?.resolved_ip
                  ? `Host Active (${result.features.resolved_ip})`
                  : 'Host Active & Resolvable'}
              </span>
              {result.features?.has_password_input === 1 ? (
                <span className="px-3 py-1.5 rounded-lg bg-red-100 text-red-800 border border-red-200 shadow-xs">
                  ⚠️ Password Input Detected
                </span>
              ) : (
                <span className="px-3 py-1.5 rounded-lg bg-slate-100 text-slate-700 border border-slate-200 shadow-xs">
                  🔒 No Password Lures
                </span>
              )}
            </div>
          </div>

          {/* Action Recommendation */}
          {result.recommendation && (
            <div
              className={`p-5 rounded-2xl border flex items-start space-x-3.5 shadow-xs ${
                isThreat
                  ? 'bg-amber-50/90 border-amber-200 text-amber-900'
                  : 'bg-emerald-50/90 border-emerald-200 text-emerald-900'
              }`}
            >
              <div className="mt-0.5 flex-shrink-0">
                {isThreat ? (
                  <ShieldAlert className="w-5 h-5 text-amber-600" />
                ) : (
                  <ShieldCheck className="w-5 h-5 text-emerald-600" />
                )}
              </div>
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider mb-1">
                  Recommended Action
                </h4>
                <p className="text-xs leading-relaxed">{result.recommendation}</p>
              </div>
            </div>
          )}

          {/* Observed Threat Indicators */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700 flex items-center gap-1.5 mb-2.5">
              <Info className="w-3.5 h-3.5 text-blue-600" />
              Observed Indicators ({result.detection_reasons.length})
            </h4>

            {result.detection_reasons.length > 0 ? (
              <div className="grid grid-cols-1 xl:grid-cols-2 gap-3 max-h-72 overflow-y-auto pr-1">
                {result.detection_reasons.map((reason, idx) => (
                  <ReasonCard key={reason.id || idx} reason={reason} />
                ))}
              </div>
            ) : (
              <p className="text-xs text-slate-500 italic p-3.5 bg-slate-50 rounded-xl border border-slate-100">
                No threat indicators detected for this destination.
              </p>
            )}
          </div>

          {/* Redirect Chain View (if multiple hops exist) */}
          {result.redirect_chain && result.redirect_chain.length > 1 && (
            <RedirectChainView chain={result.redirect_chain} />
          )}
        </div>
      </div>
    </div>
  );
};
