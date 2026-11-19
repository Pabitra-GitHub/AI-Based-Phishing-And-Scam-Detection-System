import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldAlert, Home, ArrowLeft } from 'lucide-react';
import { Button } from '../components/common/Button';

export const NotFoundPage: React.FC = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-[70vh] flex flex-col items-center justify-center p-6 text-center">
      <div className="w-16 h-16 rounded-3xl bg-blue-50 text-blue-600 flex items-center justify-center mb-4 border border-blue-100 shadow-inner">
        <ShieldAlert className="w-8 h-8" />
      </div>
      <h1 className="text-4xl font-extrabold text-slate-900 tracking-tight">404</h1>
      <h2 className="text-lg font-bold text-slate-800 mt-1 mb-2">Security Route Not Found</h2>
      <p className="text-xs text-slate-500 max-w-sm mb-6 leading-relaxed">
        The requested URL page does not exist or has been relocated to another security partition.
      </p>
      <div className="flex items-center space-x-3">
        <Button variant="secondary" size="sm" onClick={() => navigate(-1)} leftIcon={<ArrowLeft className="w-4 h-4" />}>
          Go Back
        </Button>
        <Button variant="primary" size="sm" onClick={() => navigate('/')} leftIcon={<Home className="w-4 h-4" />}>
          Home Overview
        </Button>
      </div>
    </div>
  );
};
