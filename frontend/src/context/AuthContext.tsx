import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { User } from '../types';
import { authApi } from '../services/api';
import { useToast } from './ToastContext';

interface AuthContextType {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isAdmin: boolean;
  loading: boolean;
  register: (name: string, email: string, password: string) => Promise<void>;
  logout: () => void;
  refreshUser: () => Promise<void>;
}

const defaultUser: User = {
  id: 'analyst-default',
  name: 'Security Analyst',
  email: 'analyst@phishguard.local',
  role: 'ADMIN',
  is_active: true,
  created_at: new Date().toISOString()
};

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User>(() => {
    const saved = localStorage.getItem('phishguard_user');
    return saved ? JSON.parse(saved) : defaultUser;
  });
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('phishguard_token');
  });
  const [loading, setLoading] = useState<boolean>(false);
  const { addToast } = useToast();

  useEffect(() => {
    const verifyAuth = async () => {
      const savedToken = localStorage.getItem('phishguard_token');
      if (savedToken) {
        try {
          const freshUser = await authApi.getMe();
          setUser(freshUser);
          localStorage.setItem('phishguard_user', JSON.stringify(freshUser));
        } catch (err) {
          // Token expired / invalid, retain default user
          localStorage.removeItem('phishguard_token');
          localStorage.removeItem('phishguard_user');
          setUser(defaultUser);
          setToken(null);
        }
      }
    };

    verifyAuth();
  }, []);

  const register = async (name: string, email: string, password: string) => {
    try {
      const data = await authApi.register({ name, email, password });
      setToken(data.access_token);
      setUser(data.user);
      localStorage.setItem('phishguard_token', data.access_token);
      localStorage.setItem('phishguard_user', JSON.stringify(data.user));
      addToast('success', 'Account created', 'Registration successful! Welcome to PhishGuard.');
    } catch (err: any) {
      const msg = err.response?.data?.detail || 'Registration failed. Please try again.';
      addToast('error', 'Registration Error', msg);
      throw err;
    }
  };

  const logout = () => {
    setToken(null);
    setUser(defaultUser);
    localStorage.removeItem('phishguard_token');
    localStorage.removeItem('phishguard_user');
    addToast('info', 'Session Reset', 'Session reset to default analyst profile.');
  };

  const refreshUser = async () => {
    if (token) {
      try {
        const freshUser = await authApi.getMe();
        setUser(freshUser);
        localStorage.setItem('phishguard_user', JSON.stringify(freshUser));
      } catch (err) {
        console.error('Failed to refresh user profile:', err);
      }
    }
  };

  const isAuthenticated = true;
  const isAdmin = user?.role === 'ADMIN';

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated,
        isAdmin,
        loading,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
