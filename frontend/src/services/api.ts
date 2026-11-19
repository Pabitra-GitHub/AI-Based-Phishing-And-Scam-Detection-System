import axios from 'axios';
import {
  AuthResponse,
  ScanResult,
  PaginatedScans,
  DashboardSummary,
  AdminStats,
  AuditLog,
  User
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL 
  ? `${import.meta.env.VITE_API_BASE_URL}/api/v1` 
  : '/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 60000,
});

// Request interceptor to attach JWT token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('phishguard_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor for session expiration
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // If token expired, clear invalid session
      if (localStorage.getItem('phishguard_token')) {
        localStorage.removeItem('phishguard_token');
        localStorage.removeItem('phishguard_user');
      }
    }
    return Promise.reject(error);
  }
);

// Auth API
export const authApi = {
  register: async (data: { name: string; email: string; password: string }): Promise<AuthResponse> => {
    const res = await apiClient.post<AuthResponse>('/auth/register', data);
    return res.data;
  },
  getMe: async (): Promise<User> => {
    const res = await apiClient.get<User>('/auth/me');
    return res.data;
  },
  updateProfile: async (data: { name?: string; current_password?: string; new_password?: string }): Promise<User> => {
    const res = await apiClient.put<User>('/auth/me', data);
    return res.data;
  }
};

// Scan API
export const scanApi = {
  createScan: async (url: string): Promise<ScanResult> => {
    const res = await apiClient.post<ScanResult>('/scans', { url });
    return res.data;
  },
  getScans: async (params?: { page?: number; page_size?: number; classification?: string; search?: string }): Promise<PaginatedScans> => {
    const res = await apiClient.get<PaginatedScans>('/scans', { params });
    return res.data;
  },
  getScanById: async (id: string): Promise<ScanResult> => {
    const res = await apiClient.get<ScanResult>(`/scans/${id}`);
    return res.data;
  },
  deleteScan: async (id: string): Promise<void> => {
    await apiClient.delete(`/scans/${id}`);
  }
};

// Dashboard API
export const dashboardApi = {
  getSummary: async (): Promise<DashboardSummary> => {
    const res = await apiClient.get<DashboardSummary>('/dashboard/summary');
    return res.data;
  }
};

// Admin API
export const adminApi = {
  getStats: async (): Promise<AdminStats> => {
    const res = await apiClient.get<AdminStats>('/admin/stats');
    return res.data;
  },
  getUsers: async (): Promise<User[]> => {
    const res = await apiClient.get<User[]>('/admin/users');
    return res.data;
  },
  toggleUserStatus: async (userId: string): Promise<User> => {
    const res = await apiClient.patch<User>(`/admin/users/${userId}/status`);
    return res.data;
  },
  getAuditLogs: async (limit = 50): Promise<AuditLog[]> => {
    const res = await apiClient.get<AuditLog[]>('/admin/audit-logs', { params: { limit } });
    return res.data;
  },
  reloadModel: async (): Promise<{ status: string; message: string; model_version: string }> => {
    const res = await apiClient.post('/admin/reload-model');
    return res.data;
  }
};

// Health API
export const healthApi = {
  check: async () => {
    const res = await apiClient.get('/health');
    return res.data;
  }
};
