import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { antivirusApi, clearAuthCredentials, setAuthCredentials } from '../api/client';

const AuthContext = createContext(null);

function readStoredUser() {
  return sessionStorage.getItem('auth_user');
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readStoredUser);
  const [isAuthenticated, setIsAuthenticated] = useState(false);

  const login = useCallback(async (username, password) => {
    setAuthCredentials(username, password);
    try {
      await antivirusApi.get('/system/status');
      sessionStorage.setItem('auth_user', username);
      setUser(username);
      setIsAuthenticated(true);
      return { success: true };
    } catch (error) {
      clearAuthCredentials();
      sessionStorage.removeItem('auth_user');
      setUser(null);
      setIsAuthenticated(false);
      return {
        success: false,
        message: error.response?.status === 401
          ? 'Invalid username or password'
          : 'Unable to reach the server. Is the backend running?',
      };
    }
  }, []);

  useEffect(() => {
    if (!hasStoredSession()
        && import.meta.env.VITE_API_USERNAME
        && import.meta.env.VITE_API_PASSWORD) {
      login(import.meta.env.VITE_API_USERNAME, import.meta.env.VITE_API_PASSWORD);
    }
  }, [login]);

  const logout = useCallback(() => {
    sessionStorage.removeItem('auth_user');
    clearAuthCredentials();
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  const value = useMemo(
    () => ({ user, isAuthenticated, login, logout }),
    [user, isAuthenticated, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
}
