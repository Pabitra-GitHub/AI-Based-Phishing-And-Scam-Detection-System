import React, { ReactNode } from 'react';

export interface BadgeProps {
  children: ReactNode;
  variant?: 'default' | 'primary' | 'safe' | 'suspicious' | 'highrisk' | 'critical' | 'outline';
  size?: 'sm' | 'md';
  icon?: ReactNode;
  className?: string;
}

export const Badge: React.FC<BadgeProps> = ({
  children,
  variant = 'default',
  size = 'md',
  icon,
  className = ''
}) => {
  const variantStyles = {
    default: 'bg-slate-100 text-slate-700 border-slate-200',
    primary: 'bg-blue-50 text-blue-700 border-blue-200',
    safe: 'bg-emerald-50 text-emerald-700 border-emerald-200',
    suspicious: 'bg-amber-50 text-amber-700 border-amber-200',
    highrisk: 'bg-orange-50 text-orange-700 border-orange-200',
    critical: 'bg-red-50 text-red-700 border-red-200',
    outline: 'bg-transparent text-slate-600 border-slate-300',
  };

  const sizeStyles = {
    sm: 'text-[11px] px-2 py-0.5 font-medium rounded-md gap-1',
    md: 'text-xs px-2.5 py-1 font-semibold rounded-lg gap-1.5',
  };

  return (
    <span
      className={`inline-flex items-center border tracking-wide uppercase ${variantStyles[variant]} ${sizeStyles[size]} ${className}`}
    >
      {icon && <span className="inline-flex">{icon}</span>}
      {children}
    </span>
  );
};
