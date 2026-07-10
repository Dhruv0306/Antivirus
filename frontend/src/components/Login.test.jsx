import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import Login from './Login';
import { useAuth } from '../context/AuthContext';

vi.mock('../context/AuthContext', () => ({
    useAuth: vi.fn(),
}));

function renderLogin(initialEntries = ['/login']) {
    return render(
        <MemoryRouter initialEntries={initialEntries}>
            <Routes>
                <Route path="/login" element={<Login />} />
                <Route path="/" element={<div>Dashboard Page</div>} />
            </Routes>
        </MemoryRouter>
    );
}

describe('Login', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    test('renders username and password fields', () => {
        useAuth.mockReturnValue({ login: vi.fn(), isAuthenticated: false });

        renderLogin();

        expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/^password/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /sign in/i })).toBeInTheDocument();
    });

    test('shows a success banner when redirected here after registration', () => {
        useAuth.mockReturnValue({ login: vi.fn(), isAuthenticated: false });

        renderLogin(['/login?registered=true']);

        expect(screen.getByText(/account created/i)).toBeInTheDocument();
    });

    test('submit button is disabled until both fields are filled', async () => {
        useAuth.mockReturnValue({ login: vi.fn(), isAuthenticated: false });
        const user = userEvent.setup();

        renderLogin();

        const submitButton = screen.getByRole('button', { name: /sign in/i });
        expect(submitButton).toBeDisabled();

        await user.type(screen.getByLabelText(/username/i), 'testuser');
        expect(submitButton).toBeDisabled();

        await user.type(screen.getByLabelText(/^password/i), 'password123');
        expect(submitButton).toBeEnabled();
    });

    test('calls login with trimmed username and navigates to / on success', async () => {
        const loginMock = vi.fn().mockResolvedValue({ success: true });
        useAuth.mockReturnValue({ login: loginMock, isAuthenticated: false });
        const user = userEvent.setup();

        renderLogin();

        await user.type(screen.getByLabelText(/username/i), '  testuser  ');
        await user.type(screen.getByLabelText(/^password/i), 'password123');
        await user.click(screen.getByRole('button', { name: /sign in/i }));

        expect(loginMock).toHaveBeenCalledWith('testuser', 'password123');
        await waitFor(() => expect(screen.getByText('Dashboard Page')).toBeInTheDocument());
    });

    test('shows the returned error message when login fails', async () => {
        const loginMock = vi.fn().mockResolvedValue({
            success: false,
            message: 'Invalid username or password',
        });
        useAuth.mockReturnValue({ login: loginMock, isAuthenticated: false });
        const user = userEvent.setup();

        renderLogin();

        await user.type(screen.getByLabelText(/username/i), 'testuser');
        await user.type(screen.getByLabelText(/^password/i), 'wrongpassword');
        await user.click(screen.getByRole('button', { name: /sign in/i }));

        expect(await screen.findByText('Invalid username or password')).toBeInTheDocument();
    });

    test('redirects immediately to / when already authenticated', () => {
        useAuth.mockReturnValue({ login: vi.fn(), isAuthenticated: true });

        renderLogin();

        expect(screen.getByText('Dashboard Page')).toBeInTheDocument();
    });
});