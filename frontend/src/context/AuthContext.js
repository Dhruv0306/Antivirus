import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  authApi,
  clearCsrfCredentials,
  setCsrfCredentials,
} from '../api/client';

const AuthContext = createContext(null);

function readStoredUser() {
  return sessionStorage.getItem('auth_user');
}

function readStoredRole() {
  return sessionStorage.getItem('auth_role');
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(readStoredUser);
  const [role, setRole] = useState(readStoredRole);
  const [isAuthenticated, setIsAuthenticated] = useState(() => Boolean(readStoredUser()));

  /**
   * On every app load, validate the stored session against the server.
   * If /me returns a different role than what is stored (stale), correct it.
   * If /me returns 401 (session expired), force re-login and wipe storage.
   * This also covers the cross-origin stale sessionStorage bug where a USER
   * session from one origin leaks into an ADMIN session on another.
   */
  useEffect(() => {
    if (!isAuthenticated) return;

    authApi.get('/me')
      .then(({ data }) => {
        sessionStorage.setItem('auth_user', data.username);
        sessionStorage.setItem('auth_role', data.role);
        setUser(data.username);
        setRole(data.role);
      })
      .catch(() => {
        sessionStorage.removeItem('auth_user');
        sessionStorage.removeItem('auth_role');
        clearCsrfCredentials();
        setUser(null);
        setRole(null);
        setIsAuthenticated(false);
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  const login = useCallback(async (username, password) => {
    try {
      // Step 1: fetch CSRF before the login POST
      const { data: preLoginCsrf } = await authApi.get('/csrf');
      setCsrfCredentials(preLoginCsrf);

      // Step 2: form login
      const body = new URLSearchParams({ username, password });
      await authApi.post('/login', body, {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      });

      // Step 3: refresh CSRF — Spring regenerates it after session creation
      const { data: postLoginCsrf } = await authApi.get('/csrf');
      setCsrfCredentials(postLoginCsrf);

      // Step 4: fetch role from /auth/me — also confirms the session is live
      const { data: me } = await authApi.get('/me');
      const resolvedRole = me.role || 'USER';

      // Step 5: persist
      sessionStorage.setItem('auth_user', me.username || username);
      sessionStorage.setItem('auth_role', resolvedRole);

      setUser(me.username || username);
      setRole(resolvedRole);
      setIsAuthenticated(true);

      return { success: true };
    } catch (error) {
      clearCsrfCredentials();
      sessionStorage.removeItem('auth_user');
      sessionStorage.removeItem('auth_role');
      setUser(null);
      setRole(null);
      setIsAuthenticated(false);
      return {
        success: false,
        message:
          error.response?.status === 401
            ? 'Invalid username or password'
            : 'Unable to reach the server. Is the backend running?',
      };
    }
  }, []);

  const logout = useCallback(() => {
    authApi.post('/logout').catch(() => { });
    sessionStorage.removeItem('auth_user');
    sessionStorage.removeItem('auth_role');
    clearCsrfCredentials();
    setUser(null);
    setRole(null);
    setIsAuthenticated(false);
  }, []);

  const value = useMemo(
    () => ({
      user,
      role,
      isAdmin: role === 'ADMIN',
      isAuthenticated,
      login,
      logout,
    }),
    [user, role, isAuthenticated, login, logout]
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