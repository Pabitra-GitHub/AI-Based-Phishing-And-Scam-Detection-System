import React from 'react';
import { Shield, Loader2 } from 'lucide-react';

export interface LoaderProps {
  message?: string;
  size?: 'sm' | 'md' | 'lg';
}

export const Loader: React.FC<LoaderProps> = ({
  message = 'Analyzing security vectors...',
  size = 'md'
}) => {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center">
      <div className="relative flex items-center justify-center mb-4">
        <div className="absolute w-14 h-14 bg-blue-100/60 rounded-full animate-ping" />
        <div className="w-12 h-12 bg-blue-50 text-[#2563EB] rounded-2xl flex items-center justify-center border border-blue-200/60 shadow-inner z-10">
          <Shield className="w-6 h-6 animate-pulse" />
        </div>
      </div>
      <div className="flex items-center space-x-2 text-slate-700 font-medium text-sm">
        <Loader2 className="w-4 h-4 animate-spin text-[#2563EB]" />
        <span>{message}</span>
      </div>
      <p className="text-xs text-slate-400 mt-1 max-w-xs">
        Extracting lexical indicators, querying AI classifier, and validating security heuristics...
      </p>
    </div>
  );
};
