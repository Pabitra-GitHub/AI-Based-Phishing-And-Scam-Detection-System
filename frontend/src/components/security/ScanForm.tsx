import React, { useState } from 'react';
import { Search, ShieldAlert, Clipboard, ArrowRight } from 'lucide-react';
import { Button } from '../common/Button';

export interface ScanFormProps {
  onScan: (url: string) => Promise<void>;
  isLoading?: boolean;
  initialUrl?: string;
  compact?: boolean;
}

export const ScanForm: React.FC<ScanFormProps> = ({
  onScan,
  isLoading = false,
  initialUrl = '',
  compact = false,
}) => {
  const [url, setUrl] = useState<string>(initialUrl);
  const [error, setError] = useState<string | null>(null);

  const handlePaste = async () => {
    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        setUrl(text.trim());
        setError(null);
      }
    } catch (e) {
      // Clipboard access denied
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError('Please enter a URL to analyze.');
      return;
    }
    setError(null);
    await onScan(trimmed);
  };

  return (
    <div className="w-full">
      <form onSubmit={handleSubmit} className="relative">
        <div className="relative flex flex-col sm:flex-row items-stretch gap-2 p-2 glass-panel-strong rounded-2xl focus-within:border-blue-500 focus-within:ring-4 focus-within:ring-blue-100 transition-all">
          <div className="relative flex-1 flex items-center">
            <div className="absolute left-3.5 text-slate-400 flex items-center pointer-events-none">
              <Search className="w-5 h-5 text-blue-600" />
            </div>
            <input
              type="text"
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                if (error) setError(null);
              }}
              placeholder="Paste website URL to inspect (e.g., https://example.com)..."
              className="w-full pl-11 pr-20 py-3 text-sm text-slate-900 placeholder-slate-400 bg-transparent border-0 focus:outline-none focus:ring-0"
              disabled={isLoading}
            />
            <button
              type="button"
              onClick={handlePaste}
              className="absolute right-2 px-2 py-1 text-xs font-semibold text-slate-500 hover:text-blue-600 bg-slate-100 hover:bg-blue-50 rounded-md transition-colors flex items-center gap-1"
              title="Paste from clipboard"
            >
              <Clipboard className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Paste</span>
            </button>
          </div>

          <Button
            type="submit"
            size={compact ? 'md' : 'lg'}
            isLoading={isLoading}
            className="flex-shrink-0 whitespace-nowrap rounded-xl shadow-md"
            rightIcon={<ArrowRight className="w-4 h-4" />}
          >
            Scan Threat
          </Button>
        </div>

        {error && (
          <p className="mt-2 text-xs text-red-600 font-semibold flex items-center gap-1 px-1">
            <ShieldAlert className="w-3.5 h-3.5" /> {error}
          </p>
        )}
      </form>
    </div>
  );
};
