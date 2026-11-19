import React from 'react';
import { ShieldCheck, AlertTriangle, AlertOctagon, ShieldAlert } from 'lucide-react';
import { RiskClassification } from '../../types';

export interface RiskBadgeProps {
  classification: RiskClassification;
  size?: 'sm' | 'md' | 'lg';
  showIcon?: boolean;
}

export const RiskBadge: React.FC<RiskBadgeProps> = ({
  classification,
  size = 'md',
  showIcon = true,
}) => {
  const getConfig = (cls: RiskClassification) => {
    switch (cls) {
      case 'SAFE':
        return {
          bg: 'bg-emerald-50 text-emerald-700 border-emerald-200',
          icon: <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />,
          label: 'GOOD WEBSITE (SAFE)'
        };
      case 'SUSPICIOUS':
        return {
          bg: 'bg-amber-50 text-amber-700 border-amber-200',
          icon: <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />,
          label: 'SUSPICIOUS WEBSITE'
        };
      case 'HIGH RISK':
        return {
          bg: 'bg-orange-50 text-orange-700 border-orange-200',
          icon: <AlertOctagon className="w-3.5 h-3.5 text-orange-600" />,
          label: 'BAD WEBSITE (HIGH RISK)'
        };
      case 'CRITICAL':
        return {
          bg: 'bg-red-50 text-red-700 border-red-200',
          icon: <ShieldAlert className="w-3.5 h-3.5 text-red-600" />,
          label: 'BAD / PHISHING WEBSITE'
        };
    }
  };

  const config = getConfig(classification);

  const sizeStyles = {
    sm: 'text-[11px] px-2 py-0.5 font-medium rounded-md gap-1',
    md: 'text-xs px-2.5 py-1 font-semibold rounded-lg gap-1.5',
    lg: 'text-sm px-3.5 py-1.5 font-bold rounded-xl gap-2',
  };

  return (
    <span
      className={`inline-flex items-center border tracking-wide uppercase ${config.bg} ${sizeStyles[size]}`}
    >
      {showIcon && <span className="inline-flex">{config.icon}</span>}
      <span>{config.label}</span>
    </span>
  );
};
