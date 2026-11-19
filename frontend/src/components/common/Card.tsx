import React, { HTMLAttributes, ReactNode } from 'react';

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  children: ReactNode;
  hoverable?: boolean;
  padded?: boolean;
}

export const Card: React.FC<CardProps> = ({
  children,
  hoverable = false,
  padded = true,
  className = '',
  ...props
}) => {
  return (
    <div
      className={`glass-panel rounded-2xl ${
        padded ? 'p-6' : ''
      } ${
        hoverable
          ? 'transition-all duration-300 hover:shadow-card-hover hover:border-blue-100 hover:-translate-y-0.5'
          : ''
      } ${className}`}
      {...props}
    >
      {children}
    </div>
  );
};
