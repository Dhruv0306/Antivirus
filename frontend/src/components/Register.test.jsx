import React from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, test, vi } from 'vitest';
import Register from './Register';
import { authApi, setCsrfCredentials } from '../api/client';

vi.mock('../api/client', () => ({
    authApi: {
        get: vi.fn(),
        post: vi.fn(),
    },
    setCsrfCredentials: vi.fn(),
}));

function renderRegister() {
    return render(
        <MemoryRouter initialEntries={['/register']}>
            <Routes>
                <Route path="/register" element={<Register />} />
                <Route path="/login" element={<div>Login Page</div>} />
            </Routes>
        </MemoryRouter>
    );
}

async function fillValidForm(user) {
    await user.type(screen.getByLabelText(/username/i), 'testuser');
    await user.type(screen.getByLabelText(/email/i), 'testuser@example.com');
    await user.type(screen.getByLabelText(/^password/i), 'password123');
    await user.type(screen.getByLabelText(/confirm password/i), 'password123');
}

describe('Register', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    test('renders all form fields', () => {
        renderRegister();

        expect(screen.getByLabelText(/username/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/email/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/^password/i)).toBeInTheDocument();
        expect(screen.getByLabelText(/confirm password/i)).toBeInTheDocument();
        expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument();
    });

    test('submit button is disabled until every field has a value', async () => {
        const user = userEvent.setup();
        renderRegister();

        const submitButton = screen.getByRole('button', { name: /create account/i });
        expect(submitButton).toBeDisabled();

        await fillValidForm(user);

        expect(submitButton).toBeEnabled();
    });

    test('rejects a username with disallowed characters before calling the API', async () => {
        const user = userEvent.setup();
        renderRegister();

        await user.type(screen.getByLabelText(/username/i), 'bad username!');
        await user.type(screen.getByLabelText(/email/i), 'testuser@example.com');
        await user.type(screen.getByLabelText(/^password/i), 'password123');
        await user.type(screen.getByLabelText(/confirm password/i), 'password123');
        await user.click(screen.getByRole('button', { name: /create account/i }));

        expect(
            await screen.findByText(/username may only contain letters, digits, and underscores/i)
        ).toBeInTheDocument();
        expect(authApi.post).not.toHaveBeenCalled();
    });

    test('rejects a password shorter than 8 characters before calling the API', async () => {
        const user = userEvent.setup();
        renderRegister();

        await user.type(screen.getByLabelText(/username/i), 'testuser');
        await user.type(screen.getByLabelText(/email/i), 'testuser@example.com');
        await user.type(screen.getByLabelText(/^password/i), 'short1');
        await user.type(screen.getByLabelText(/confirm password/i), 'short1');
        await user.click(screen.getByRole('button', { name: /create account/i }));

        expect(
            await screen.findByText(/password must be at least 8 characters/i)
        ).toBeInTheDocument();
        expect(authApi.post).not.toHaveBeenCalled();
    });

    test('rejects mismatched passwords before calling the API', async () => {
        const user = userEvent.setup();
        renderRegister();

        await user.type(screen.getByLabelText(/username/i), 'testuser');
        await user.type(screen.getByLabelText(/email/i), 'testuser@example.com');
        await user.type(screen.getByLabelText(/^password/i), 'password123');
        await user.type(screen.getByLabelText(/confirm password/i), 'differentPassword');
        await user.click(screen.getByRole('button', { name: /create account/i }));

        expect(await screen.findByText(/passwords do not match/i)).toBeInTheDocument();
        expect(authApi.post).not.toHaveBeenCalled();
    });

    test('submits the trimmed username and email payload and navigates to login on success', async () => {
        authApi.get.mockResolvedValue({ data: { token: 'csrf-token' } });
        authApi.post.mockResolvedValue({ data: {} });
        const user = userEvent.setup();

        renderRegister();

        // Username and email are both trimmed before validation and before
        // being sent, so stray whitespace (autofill, accidental spaces)
        // doesn't trip the "letters/digits/underscores only" check.
        await user.type(screen.getByLabelText(/username/i), '  testuser  ');
        await user.type(screen.getByLabelText(/email/i), '  testuser@example.com  ');
        await user.type(screen.getByLabelText(/^password/i), 'password123');
        await user.type(screen.getByLabelText(/confirm password/i), 'password123');
        await user.click(screen.getByRole('button', { name: /create account/i }));

        await waitFor(() =>
            expect(authApi.post).toHaveBeenCalledWith('/register', {
                username: 'testuser',
                email: 'testuser@example.com',
                password: 'password123',
                confirmPassword: 'password123',
            })
        );
        expect(setCsrfCredentials).toHaveBeenCalledWith({ token: 'csrf-token' });
        await waitFor(() => expect(screen.getByText('Login Page')).toBeInTheDocument());
    });

    test('shows the server message on a 409 duplicate account conflict', async () => {
        authApi.get.mockResolvedValue({ data: { token: 'csrf-token' } });
        authApi.post.mockRejectedValue({
            response: { status: 409, data: { message: 'Username is already taken' } },
        });
        const user = userEvent.setup();

        renderRegister();
        await fillValidForm(user);
        await user.click(screen.getByRole('button', { name: /create account/i }));

        expect(await screen.findByText('Username is already taken')).toBeInTheDocument();
    });

    test('shows a fallback message on a 400 response with no server message', async () => {
        authApi.get.mockResolvedValue({ data: { token: 'csrf-token' } });
        authApi.post.mockRejectedValue({ response: { status: 400 } });
        const user = userEvent.setup();

        renderRegister();
        await fillValidForm(user);
        await user.click(screen.getByRole('button', { name: /create account/i }));

        expect(
            await screen.findByText(/please check your input and try again/i)
        ).toBeInTheDocument();
    });

    test('shows a network error message when the backend is unreachable', async () => {
        authApi.get.mockResolvedValue({ data: { token: 'csrf-token' } });
        authApi.post.mockRejectedValue(new Error('Network Error'));
        const user = userEvent.setup();

        renderRegister();
        await fillValidForm(user);
        await user.click(screen.getByRole('button', { name: /create account/i }));

        expect(
            await screen.findByText(/unable to reach the server/i)
        ).toBeInTheDocument();
    });
});