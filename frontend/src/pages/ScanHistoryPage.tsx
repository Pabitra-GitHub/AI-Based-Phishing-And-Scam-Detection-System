import React, { useCallback, useEffect, useState } from 'react';
import { Clock3, ExternalLink, History, RefreshCw, Search, Shield } from 'lucide-react';
import { scanApi } from '../services/api';
import { RiskClassification, ScanResult } from '../types';
import { Loader } from '../components/common/Loader';
import { Button } from '../components/common/Button';
import { Card } from '../components/common/Card';
import { useToast } from '../context/ToastContext';

const classificationStyles: Record<RiskClassification, string> = {
  SAFE: 'bg-emerald-50 text-emerald-700 border-emerald-200',
  SUSPICIOUS: 'bg-amber-50 text-amber-700 border-amber-200',
  'HIGH RISK': 'bg-orange-50 text-orange-700 border-orange-200',
  CRITICAL: 'bg-red-50 text-red-700 border-red-200',
};

export const ScanHistoryPage: React.FC = () => {
  const { addToast } = useToast();
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');

  const loadHistory = useCallback(async () => {
    try {
      setLoading(true);
      const response = await scanApi.getScans({ page: 1, page_size: 100, search: search || undefined });
      setScans(response.items);
    } catch (err: any) {
      addToast('error', 'History unavailable', err.response?.data?.detail || 'Could not load scan history.');
    } finally {
      setLoading(false);
    }
  }, [addToast, search]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  return (
    <div className="w-full max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 space-y-6">
      <section className="flex flex-col sm:flex-row sm:items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-blue-600 text-xs font-bold uppercase tracking-wider">
            <History className="w-4 h-4" />
            Recent activity
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 mt-2">Scan History</h1>
          <p className="text-sm text-slate-500 mt-1">
            Your scan results are kept for up to 2 hours, then removed automatically.
          </p>
        </div>
        <Button
          variant="secondary"
          size="sm"
          onClick={loadHistory}
          disabled={loading}
          leftIcon={<RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />}
        >
          Refresh
        </Button>
      </section>

      <Card className="p-4">
        <label className="relative block">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search history by URL..."
            className="w-full rounded-xl border border-slate-200 bg-slate-50 py-2.5 pl-9 pr-3 text-sm outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100"
          />
        </label>
      </Card>

      {loading ? (
        <Card className="p-10">
          <Loader message="Loading recent scan history..." />
        </Card>
      ) : scans.length === 0 ? (
        <Card className="p-10 text-center">
          <Shield className="w-10 h-10 mx-auto text-slate-300" />
          <h2 className="mt-3 font-bold text-slate-800">No scans in the last 2 hours</h2>
          <p className="mt-1 text-sm text-slate-500">Scanned URLs will appear here automatically.</p>
        </Card>
      ) : (
        <div className="space-y-3">
          {scans.map((scan) => (
            <Card key={scan.id} className="p-4 sm:p-5">
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded-full border px-2.5 py-1 text-[11px] font-bold ${classificationStyles[scan.classification]}`}>
                      {scan.classification}
                    </span>
                    <span className="text-xs text-slate-400 flex items-center gap-1">
                      <Clock3 className="w-3.5 h-3.5" />
                      {new Date(scan.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="mt-2 truncate font-mono text-sm text-slate-800" title={scan.input_value}>
                    {scan.input_value}
                  </p>
                </div>
                <div className="flex items-center justify-between sm:justify-end gap-4">
                  <div className="text-left sm:text-right">
                    <p className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Risk score</p>
                    <p className="text-xl font-extrabold text-slate-900">{scan.risk_score}<span className="text-sm text-slate-400">/100</span></p>
                  </div>
                  <a
                    href={`/scans/${scan.id}`}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-2 text-xs font-semibold text-blue-600 hover:bg-blue-50"
                  >
                    Details
                    <ExternalLink className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </div>
  );
};
