import React from 'react';
import { ArrowDown, ExternalLink, RefreshCw, AlertTriangle, Globe } from 'lucide-react';
import { RedirectHop } from '../../types';

interface RedirectChainViewProps {
  chain: RedirectHop[];
}

function getStatusColor(status: number | string): { bg: string; text: string; label: string } {
  if (typeof status === 'string') {
    if (status === 'META_REFRESH') return { bg: 'bg-amber-100', text: 'text-amber-800', label: 'Meta Refresh' };
    if (status === 'LOOP_DETECTED') return { bg: 'bg-red-100', text: 'text-red-800', label: 'Loop' };
    if (status === 'ERROR') return { bg: 'bg-red-100', text: 'text-red-800', label: 'Error' };
    return { bg: 'bg-slate-100', text: 'text-slate-700', label: String(status) };
  }
  if (status >= 200 && status < 300) return { bg: 'bg-emerald-100', text: 'text-emerald-800', label: `${status} OK` };
  if (status >= 300 && status < 400) return { bg: 'bg-blue-100', text: 'text-blue-800', label: `${status} Redirect` };
  if (status >= 400 && status < 500) return { bg: 'bg-amber-100', text: 'text-amber-800', label: `${status} Client Error` };
  if (status >= 500) return { bg: 'bg-red-100', text: 'text-red-800', label: `${status} Server Error` };
  return { bg: 'bg-slate-100', text: 'text-slate-700', label: String(status) };
}

function extractHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url.slice(0, 40);
  }
}

export const RedirectChainView: React.FC<RedirectChainViewProps> = ({ chain }) => {
  if (!chain || chain.length <= 1) return null;

  const uniqueHosts = new Set(chain.map(h => extractHost(h.url)));
  const isCrossDomain = uniqueHosts.size > 1;

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center shadow-sm">
          <RefreshCw className="w-3.5 h-3.5 text-white" />
        </div>
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-700">
            Redirect Chain
          </h4>
          <p className="text-[10px] text-slate-500">
            {chain.length} hop{chain.length !== 1 ? 's' : ''} traced
            {isCrossDomain && (
              <span className="inline-flex items-center gap-0.5 ml-1.5 text-orange-600 font-semibold">
                <AlertTriangle className="w-2.5 h-2.5" /> Cross-domain
              </span>
            )}
          </p>
        </div>
      </div>

      <div className="relative pl-6">
        {/* Vertical line */}
        <div className="absolute left-3 top-2 bottom-2 w-px bg-gradient-to-b from-blue-300 via-indigo-300 to-purple-300" />

        <div className="space-y-0">
          {chain.map((hop, idx) => {
            const status = getStatusColor(hop.status);
            const host = extractHost(hop.url);
            const isFirst = idx === 0;
            const isLast = idx === chain.length - 1;

            return (
              <div key={idx} className="relative flex items-start gap-3 py-2">
                {/* Node dot */}
                <div className={`absolute -left-3 top-3 w-2.5 h-2.5 rounded-full border-2 border-white shadow-sm z-10 ${
                  isFirst ? 'bg-blue-500' : isLast ? 'bg-purple-500' : 'bg-indigo-400'
                }`} />

                {/* Content */}
                <div className={`flex-1 p-2.5 rounded-xl border transition-all ${
                  isLast ? 'bg-purple-50/50 border-purple-200' : 'bg-white border-slate-200'
                }`}>
                  <div className="flex items-center gap-2 flex-wrap">
                    {/* Hop number */}
                    <span className="text-[9px] font-bold text-slate-400">#{hop.hop}</span>

                    {/* Status badge */}
                    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${status.bg} ${status.text}`}>
                      {status.label}
                    </span>

                    {/* Host */}
                    <span className="text-[10px] font-semibold text-slate-700 flex items-center gap-1">
                      <Globe className="w-2.5 h-2.5 text-slate-400" />
                      {host}
                    </span>

                    {isFirst && (
                      <span className="text-[9px] font-bold text-blue-600 bg-blue-50 px-1.5 py-0.5 rounded-full">ORIGIN</span>
                    )}
                    {isLast && (
                      <span className="text-[9px] font-bold text-purple-600 bg-purple-50 px-1.5 py-0.5 rounded-full">LANDING</span>
                    )}
                  </div>

                  <p className="text-[10px] text-slate-500 font-mono mt-1 truncate max-w-full" title={hop.url}>
                    {hop.url.length > 80 ? hop.url.slice(0, 80) + '...' : hop.url}
                  </p>

                  {hop.server && (
                    <p className="text-[9px] text-slate-400 mt-0.5">Server: {hop.server}</p>
                  )}

                  {hop.error && (
                    <p className="text-[9px] text-red-500 mt-0.5 flex items-center gap-1">
                      <AlertTriangle className="w-2.5 h-2.5" /> {hop.error}
                    </p>
                  )}
                </div>

                {/* Arrow between hops */}
                {!isLast && (
                  <div className="absolute -left-[11px] bottom-0 transform translate-y-1/2 z-10">
                    <ArrowDown className="w-2.5 h-2.5 text-indigo-300" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
