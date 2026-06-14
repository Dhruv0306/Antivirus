import React, { createContext, useCallback, useContext, useMemo, useState } from 'react';
import {
  antivirusApi,
  authApi,
  clearCsrfCredentials,
  setCsrfCredentials
} from '../api/client';

const AuthContext = createContext(null);

function readStoredUser() {
  return sessionStorage.getItem('auth_user');
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readStoredUser);
  const [isAuthenticated, setIsAuthenticated] = useState(() => Boolean(readStoredUser()));

  const login = useCallback(async (username, password) => {
    try {
      const { data: preLoginCsrf } = await authApi.get('/csrf');
      setCsrfCredentials(preLoginCsrf);
      const body = new URLSearchParams({ username, password });
      await authApi.post(
        '/login',
        body,
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
        }
      );
      const { data: postLoginCsrf } = await authApi.get('/csrf');
      setCsrfCredentials(postLoginCsrf);
      await antivirusApi.get('/system/status');
      sessionStorage.setItem('auth_user', username);
      setUser(username);
      setIsAuthenticated(true);
      return { success: true };
    } catch (error) {
      clearCsrfCredentials();
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

  const logout = useCallback(() => {
    authApi.post('/logout').catch(() => {});
    sessionStorage.removeItem('auth_user');
    clearCsrfCredentials();
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
