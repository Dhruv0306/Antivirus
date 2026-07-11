import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import {
    Alert,
    Box,
    Button,
    Card,
    CardContent,
    CircularProgress,
    TextField,
    Typography,
} from '@mui/material';
import { Security as SecurityIcon } from '@mui/icons-material';
import { authApi, setCsrfCredentials } from '../api/client';

function Register() {
    const navigate = useNavigate();

    const [form, setForm] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: '',
    });
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);

    const handleChange = (field) => (e) => {
        setForm((prev) => ({ ...prev, [field]: e.target.value }));
        setError(null);
    };

    // Validates the same trimmed values that get sent to the server, so a
    // username like " bob " (stray leading/trailing whitespace from autofill
    // or a typo) is judged on "bob", not rejected for whitespace that never
    // reaches the backend anyway.
    const validate = (username) => {
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return 'Username may only contain letters, digits, and underscores';
        }
        if (form.password.length < 8) {
            return 'Password must be at least 8 characters';
        }
        if (form.password !== form.confirmPassword) {
            return 'Passwords do not match';
        }
        return null;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);

        const trimmedUsername = form.username.trim();
        const trimmedEmail = form.email.trim();

        const validationError = validate(trimmedUsername);
        if (validationError) {
            setError(validationError);
            return;
        }

        setLoading(true);
        try {
            const { data: csrf } = await authApi.get('/csrf');
            setCsrfCredentials(csrf);

            await authApi.post('/register', {
                username: trimmedUsername,
                email: trimmedEmail,
                password: form.password,
                confirmPassword: form.confirmPassword,
            });

            navigate('/login?registered=true', { replace: true });
        } catch (err) {
            const serverMessage = err.response?.data?.message;
            if (err.response?.status === 409) {
                setError(serverMessage || 'Username or email is already taken');
            } else if (err.response?.status === 400) {
                setError(serverMessage || 'Please check your input and try again');
            } else {
                setError('Unable to reach the server. Is the backend running?');
            }
        } finally {
            setLoading(false);
        }
    };

    const isSubmittable =
        form.username && form.email && form.password && form.confirmPassword && !loading;

    return (
        <Box
            sx={{
                minHeight: '100vh',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                bgcolor: 'background.default',
                p: 2,
            }}
        >
            <Card sx={{ width: '100%', maxWidth: 420 }}>
                <CardContent sx={{ p: { xs: 3, sm: 4 } }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', mb: 3, gap: 1 }}>
                        <SecurityIcon color="primary" />
                        <Typography variant="h5" component="h1" fontWeight={600}>
                            Create account
                        </Typography>
                    </Box>

                    <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
                        Register for file and directory scanning access.
                    </Typography>

                    <Box component="form" onSubmit={handleSubmit}>
                        <TextField
                            fullWidth
                            label="Username"
                            margin="normal"
                            value={form.username}
                            onChange={handleChange('username')}
                            autoComplete="username"
                            inputProps={{ maxLength: 30 }}
                            required
                        />
                        <TextField
                            fullWidth
                            label="Email"
                            type="email"
                            margin="normal"
                            value={form.email}
                            onChange={handleChange('email')}
                            autoComplete="email"
                            required
                        />
                        <TextField
                            fullWidth
                            label="Password"
                            type="password"
                            margin="normal"
                            value={form.password}
                            onChange={handleChange('password')}
                            autoComplete="new-password"
                            helperText="Minimum 8 characters"
                            required
                        />
                        <TextField
                            fullWidth
                            label="Confirm password"
                            type="password"
                            margin="normal"
                            value={form.confirmPassword}
                            onChange={handleChange('confirmPassword')}
                            autoComplete="new-password"
                            required
                        />

                        {error && (
                            <Alert severity="error" sx={{ mt: 2 }}>
                                {error}
                            </Alert>
                        )}

                        <Button
                            fullWidth
                            type="submit"
                            variant="contained"
                            size="large"
                            disabled={!isSubmittable}
                            sx={{ mt: 3 }}
                        >
                            {loading ? <CircularProgress size={24} color="inherit" /> : 'Create account'}
                        </Button>

                        <Typography variant="body2" color="text.secondary" sx={{ mt: 2, textAlign: 'center' }}>
                            Already have an account?{' '}
                            <Link to="/login" style={{ color: 'inherit', fontWeight: 500 }}>
                                Sign in
                            </Link>
                        </Typography>
                    </Box>
                </CardContent>
            </Card>
        </Box>
    );
}

export default Register;