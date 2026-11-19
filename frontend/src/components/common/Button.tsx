import React, { ButtonHTMLAttributes, ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '../../utils/cn';

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'outline' | 'ghost' | 'dark';
  size?: 'sm' | 'md' | 'lg';
  isLoading?: boolean;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
}

export const Button: React.FC<ButtonProps> = ({
  children,
  variant = 'primary',
  size = 'md',
  isLoading = false,
  leftIcon,
  rightIcon,
  className = '',
  disabled,
  ...props
}) => {
  const baseStyles = 'inline-flex items-center justify-center font-medium rounded-xl transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-sm active:scale-[0.98]';

  const variantStyles = {
    primary: 'bg-[#2563EB] hover:bg-[#1D4ED8] text-white focus:ring-blue-500 shadow-blue-500/20',
    secondary: 'bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 focus:ring-slate-400',
    danger: 'bg-[#DC2626] hover:bg-[#B91C1C] text-white focus:ring-red-500 shadow-red-500/20',
    outline: 'bg-transparent hover:bg-blue-50 text-[#2563EB] border border-blue-200 focus:ring-blue-400',
    ghost: 'bg-transparent hover:bg-slate-100 text-slate-600 focus:ring-slate-300 shadow-none',
    dark: 'bg-slate-800 hover:bg-slate-700 text-white border border-slate-700 focus:ring-slate-500',
  };

  const sizeStyles = {
    sm: 'text-xs px-3 py-1.5 gap-1.5',
    md: 'text-sm px-4 py-2.5 gap-2',
    lg: 'text-base px-6 py-3.5 gap-2.5',
  };

  return (
    <button
      className={cn(baseStyles, variantStyles[variant], sizeStyles[size], className)}
      disabled={disabled || isLoading}
      {...props}
    >
      {isLoading ? (
        <Loader2 className="w-4 h-4 animate-spin mr-1" />
      ) : (
        leftIcon && <span className="inline-flex">{leftIcon}</span>
      )}
      {children}
      {!isLoading && rightIcon && <span className="inline-flex">{rightIcon}</span>}
    </button>
  );
};
