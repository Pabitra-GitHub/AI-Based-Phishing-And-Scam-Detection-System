import React from 'react';
import { ShieldAlert, AlertTriangle, Info, Brain } from 'lucide-react';
import { DetectionReason } from '../../types';
import { Badge } from '../common/Badge';

export interface ReasonCardProps {
  reason: DetectionReason;
}

export const ReasonCard: React.FC<ReasonCardProps> = ({ reason }) => {
  const getSeverityBadge = () => {
    switch (reason.severity) {
      case 'CRITICAL':
        return <Badge variant="critical" size="sm">Critical</Badge>;
      case 'HIGH':
        return <Badge variant="highrisk" size="sm">High Severity</Badge>;
      case 'MEDIUM':
        return <Badge variant="suspicious" size="sm">Medium</Badge>;
      case 'LOW':
        return <Badge variant="safe" size="sm">Low Risk / Safe</Badge>;
    }
  };

  const getIcon = () => {
    if (reason.source === 'ML') {
      return <Brain className="w-4 h-4 text-purple-600" />;
    }
    if (reason.severity === 'CRITICAL' || reason.severity === 'HIGH') {
      return <ShieldAlert className="w-4 h-4 text-red-500" />;
    }
    if (reason.severity === 'MEDIUM') {
      return <AlertTriangle className="w-4 h-4 text-amber-500" />;
    }
    return <Info className="w-4 h-4 text-blue-500" />;
  };

  return (
    <div className="flex items-start space-x-3 p-3.5 rounded-xl bg-slate-50/80 border border-slate-200/80 hover:bg-slate-50 transition-colors">
      <div className="flex-shrink-0 mt-0.5 p-1.5 rounded-lg bg-white shadow-xs border border-slate-100">
        {getIcon()}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between gap-2 mb-1">
          <h4 className="text-xs font-bold text-slate-900 truncate">
            {reason.title || 'Security Indicator'}
          </h4>
          <div className="flex items-center space-x-1.5 flex-shrink-0">
            <span className="text-[10px] text-slate-400 font-mono font-medium">
              [{reason.source}]
            </span>
            {getSeverityBadge()}
          </div>
        </div>
        <p className="text-xs text-slate-600 leading-relaxed">
          {reason.reason}
        </p>
      </div>
    </div>
  );
};
