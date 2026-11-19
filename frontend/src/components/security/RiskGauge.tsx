import React from 'react';
import { RiskClassification } from '../../types';

export interface RiskGaugeProps {
  score: number; // 0 to 100
  classification: RiskClassification;
  size?: 'sm' | 'md' | 'lg';
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({
  score,
  classification,
  size = 'md',
}) => {
  // SVG gauge constants
  const strokeWidth = size === 'sm' ? 8 : size === 'lg' ? 14 : 10;
  const radius = size === 'sm' ? 36 : size === 'lg' ? 68 : 50;
  const center = radius + strokeWidth;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  const getColor = (cls: RiskClassification) => {
    switch (cls) {
      case 'SAFE':
        return { stroke: '#16A34A', bg: '#DCFCE7', text: 'text-emerald-700', label: 'Low Risk' };
      case 'SUSPICIOUS':
        return { stroke: '#F59E0B', bg: '#FEF3C7', text: 'text-amber-700', label: 'Moderate Risk' };
      case 'HIGH RISK':
        return { stroke: '#F97316', bg: '#FFEDD5', text: 'text-orange-700', label: 'High Risk' };
      case 'CRITICAL':
        return { stroke: '#DC2626', bg: '#FEE2E2', text: 'text-red-700', label: 'Severe Threat' };
    }
  };

  const colorConfig = getColor(classification);

  const dimensionStyles = {
    sm: 'w-24 h-24',
    md: 'w-36 h-36',
    lg: 'w-48 h-48',
  };

  const textStyles = {
    sm: { score: 'text-xl', label: 'text-[9px]' },
    md: { score: 'text-3xl', label: 'text-xs' },
    lg: { score: 'text-5xl', label: 'text-sm' },
  };

  return (
    <div className={`relative flex items-center justify-center ${dimensionStyles[size]}`}>
      <svg
        className="w-full h-full transform -rotate-90"
        viewBox={`0 0 ${center * 2} ${center * 2}`}
      >
        {/* Background Track Circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          stroke="#E2E8F0"
          strokeWidth={strokeWidth}
          fill="transparent"
        />
        {/* Animated Active Score Circle */}
        <circle
          cx={center}
          cy={center}
          r={radius}
          stroke={colorConfig.stroke}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          fill="transparent"
          style={{ transition: 'stroke-dashoffset 1s ease-in-out, stroke 0.5s ease' }}
        />
      </svg>

      {/* Center Score & Classification */}
      <div className="absolute flex flex-col items-center justify-center text-center">
        <span className={`font-extrabold ${textStyles[size].score} text-slate-900 tracking-tight`}>
          {score}
        </span>
        <span className={`font-semibold uppercase tracking-wider ${textStyles[size].label} ${colorConfig.text}`}>
          /100
        </span>
      </div>
    </div>
  );
};
