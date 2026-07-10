import React from 'react';
import { act, renderHook, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import { AuthProvider, useAuth } from './AuthContext';
import { authApi, setCsrfCredentials, clearCsrfCredentials } from '../api/client';

vi.mock('../api/client', () => ({
    authApi: {
        get: vi.fn(),
        post: vi.fn(),
    },
    setCsrfCredentials: vi.fn(),
    clearCsrfCredentials: vi.fn(),
}));

function wrapper({ children }) {
    return <AuthProvider>{children}</AuthProvider>;
}

describe('AuthContext', () => {
    beforeEach(() => {
        sessionStorage.clear();
        vi.clearAllMocks();
    });

    test('useAuth throws when used outside AuthProvider', () => {
        expect(() => renderHook(() => useAuth())).toThrow(
            'useAuth must be used within AuthProvider'
        );
    });

    test('starts unauthenticated when sessionStorage is empty', () => {
        const { result } = renderHook(() => useAuth(), { wrapper });

        expect(result.current.isAuthenticated).toBe(false);
        expect(result.current.user).toBeNull();
        expect(result.current.role).toBeNull();
        expect(result.current.isAdmin).toBe(false);
    });

    test('login sets authenticated state and persists user/role on success', async () => {
        authApi.get.mockImplementation((url) => {
            if (url === '/csrf') return Promise.resolve({ data: { token: 'csrf-token' } });
            if (url === '/me') return Promise.resolve({ data: { username: 'testuser', role: 'USER' } });
            return Promise.reject(new Error(`unexpected GET ${url}`));
        });
        authApi.post.mockResolvedValue({ data: {} });

        const { result } = renderHook(() => useAuth(), { wrapper });

        let loginResult;
        await act(async () => {
            loginResult = await result.current.login('testuser', 'password123');
        });

        expect(loginResult).toEqual({ success: true });
        expect(result.current.isAuthenticated).toBe(true);
        expect(result.current.user).toBe('testuser');
        expect(result.current.role).toBe('USER');
        expect(result.current.isAdmin).toBe(false);
        expect(sessionStorage.getItem('auth_user')).toBe('testuser');
        expect(sessionStorage.getItem('auth_role')).toBe('USER');
        expect(setCsrfCredentials).toHaveBeenCalledWith({ token: 'csrf-token' });
    });

    test('login marks isAdmin true when /me resolves an ADMIN role', async () => {
        authApi.get.mockImplementation((url) => {
            if (url === '/csrf') return Promise.resolve({ data: { token: 'csrf-token' } });
            if (url === '/me') return Promise.resolve({ data: { username: 'admin', role: 'ADMIN' } });
            return Promise.reject(new Error(`unexpected GET ${url}`));
        });
        authApi.post.mockResolvedValue({ data: {} });

        const { result } = renderHook(() => useAuth(), { wrapper });

        await act(async () => {
            await result.current.login('admin', 'password123');
        });

        expect(result.current.isAdmin).toBe(true);
    });

    test('login returns a friendly message and stays unauthenticated on invalid credentials', async () => {
        authApi.get.mockResolvedValue({ data: { token: 'csrf-token' } });
        authApi.post.mockRejectedValue({ response: { status: 401 } });

        const { result } = renderHook(() => useAuth(), { wrapper });

        let loginResult;
        await act(async () => {
            loginResult = await result.current.login('testuser', 'wrongpassword');
        });

        expect(loginResult).toEqual({
            success: false,
            message: 'Invalid username or password',
        });
        expect(result.current.isAuthenticated).toBe(false);
        expect(sessionStorage.getItem('auth_user')).toBeNull();
    });

    test('login returns a network message when the backend is unreachable', async () => {
        authApi.get.mockResolvedValue({ data: { token: 'csrf-token' } });
        authApi.post.mockRejectedValue(new Error('Network Error'));

        const { result } = renderHook(() => useAuth(), { wrapper });

        let loginResult;
        await act(async () => {
            loginResult = await result.current.login('testuser', 'password123');
        });

        expect(loginResult).toEqual({
            success: false,
            message: 'Unable to reach the server. Is the backend running?',
        });
    });

    test('logout clears session storage and resets state', async () => {
        sessionStorage.setItem('auth_user', 'testuser');
        sessionStorage.setItem('auth_role', 'USER');
        authApi.get.mockResolvedValue({ data: { username: 'testuser', role: 'USER' } });
        authApi.post.mockResolvedValue({ data: {} });

        const { result } = renderHook(() => useAuth(), { wrapper });

        await waitFor(() => expect(result.current.isAuthenticated).toBe(true));

        act(() => {
            result.current.logout();
        });

        expect(result.current.isAuthenticated).toBe(false);
        expect(result.current.user).toBeNull();
        expect(result.current.role).toBeNull();
        expect(sessionStorage.getItem('auth_user')).toBeNull();
        expect(sessionStorage.getItem('auth_role')).toBeNull();
        expect(clearCsrfCredentials).toHaveBeenCalled();
        expect(authApi.post).toHaveBeenCalledWith('/logout');
    });

    test('a stored session is invalidated when /me returns 401 on mount', async () => {
        sessionStorage.setItem('auth_user', 'staleuser');
        sessionStorage.setItem('auth_role', 'USER');
        authApi.get.mockRejectedValue({ response: { status: 401 } });

        const { result } = renderHook(() => useAuth(), { wrapper });

        await waitFor(() => expect(result.current.isAuthenticated).toBe(false));

        expect(result.current.user).toBeNull();
        expect(sessionStorage.getItem('auth_user')).toBeNull();
    });
});