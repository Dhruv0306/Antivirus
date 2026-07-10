import React from 'react';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, test, vi } from 'vitest';
import ProtectedRoute, { AdminRoute } from './ProtectedRoute';
import { useAuth } from '../context/AuthContext';

vi.mock('../context/AuthContext', () => ({
    useAuth: vi.fn(),
}));

function renderWithRouter(ui, initialEntries = ['/dashboard']) {
    return render(
        <MemoryRouter initialEntries={initialEntries}>
            <Routes>
                <Route path="/login" element={<div>Login Page</div>} />
                <Route path="/" element={<div>Home Page</div>} />
                <Route path="/dashboard" element={ui} />
            </Routes>
        </MemoryRouter>
    );
}

describe('ProtectedRoute', () => {
    test('renders children when authenticated', () => {
        useAuth.mockReturnValue({ isAuthenticated: true, isAdmin: false });

        renderWithRouter(
            <ProtectedRoute>
                <div>Protected Content</div>
            </ProtectedRoute>
        );

        expect(screen.getByText('Protected Content')).toBeInTheDocument();
    });

    test('redirects to /login when not authenticated', () => {
        useAuth.mockReturnValue({ isAuthenticated: false, isAdmin: false });

        renderWithRouter(
            <ProtectedRoute>
                <div>Protected Content</div>
            </ProtectedRoute>
        );

        expect(screen.getByText('Login Page')).toBeInTheDocument();
        expect(screen.queryByText('Protected Content')).not.toBeInTheDocument();
    });
});

describe('AdminRoute', () => {
    test('renders children when authenticated and admin', () => {
        useAuth.mockReturnValue({ isAuthenticated: true, isAdmin: true });

        renderWithRouter(
            <AdminRoute>
                <div>Admin Content</div>
            </AdminRoute>
        );

        expect(screen.getByText('Admin Content')).toBeInTheDocument();
    });

    test('redirects to /login when not authenticated', () => {
        useAuth.mockReturnValue({ isAuthenticated: false, isAdmin: false });

        renderWithRouter(
            <AdminRoute>
                <div>Admin Content</div>
            </AdminRoute>
        );

        expect(screen.getByText('Login Page')).toBeInTheDocument();
    });

    test('redirects to / when authenticated but not admin', () => {
        useAuth.mockReturnValue({ isAuthenticated: true, isAdmin: false });

        renderWithRouter(
            <AdminRoute>
                <div>Admin Content</div>
            </AdminRoute>
        );

        expect(screen.getByText('Home Page')).toBeInTheDocument();
        expect(screen.queryByText('Admin Content')).not.toBeInTheDocument();
    });
});