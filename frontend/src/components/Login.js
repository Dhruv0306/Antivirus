import React, { useState } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  TextField,
  Typography,
} from '@mui/material';
import { Security as SecurityIcon } from '@mui/icons-material';
import { useAuth } from '../context/AuthContext';
import { logError } from '../utils/logger';

function Login() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { login, isAuthenticated } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  // Show a success banner when redirected here after registration
  const justRegistered = searchParams.get('registered') === 'true';

  React.useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError(null);
    setLoading(true);

    const result = await login(username.trim(), password);
    setLoading(false);

    if (result.success) {
      navigate('/', { replace: true });
    } else {
      logError('Login failed', result.message);
      setError(result.message);
    }
  };

  return (
    <Box
      sx={{
        minHeight: '100dvh',
        display: 'flex',
        bgcolor: 'background.default',
      }}
    >
      {/* Brand panel — hidden below sm. A hairline divider separates it from
          the form panel rather than a shadow, consistent with the flat,
          border-driven Night Watch surface treatment. */}
      <Box
        sx={{
          display: { xs: 'none', sm: 'flex' },
          flexDirection: 'column',
          justifyContent: 'space-between',
          width: { sm: '38%', md: '34%' },
          p: 5,
          bgcolor: 'var(--secondary-dark)',
          borderRight: '1px solid var(--border-main)',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SecurityIcon sx={{ color: 'var(--primary-main)' }} />
          <Typography variant="subtitle1" fontWeight={600} letterSpacing="-0.01em" sx={{ color: 'var(--text-primary)' }}>
            SecureGuard
          </Typography>
        </Box>
        <Box>
          <Typography variant="h4" fontWeight={600} sx={{ mb: 2, letterSpacing: '-0.01em', color: 'var(--text-primary)' }}>
            Scan first. Trust after.
          </Typography>
          <Typography variant="body2" sx={{ color: 'var(--text-secondary)', maxWidth: 340 }}>
            File, directory, and network scanning backed by a weighted
            detection engine and MITRE ATT&amp;CK-mapped signals.
          </Typography>
        </Box>
        <Typography variant="caption" sx={{ color: 'var(--text-disabled)' }}>
          &copy; {new Date().getFullYear()} SecureGuard Antivirus
        </Typography>
      </Box>

      {/* Form panel */}
      <Box
        sx={{
          flex: 1,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          p: 2,
        }}
      >
        <Box sx={{ width: '100%', maxWidth: 360 }}>
          <Typography variant="h5" component="h1" fontWeight={600} sx={{ mb: 1 }}>
            Sign in
          </Typography>

          <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
            Enter your application credentials to access the dashboard.
          </Typography>

          {justRegistered && (
            <Alert severity="success" sx={{ mb: 2 }}>
              Account created. You can now sign in.
            </Alert>
          )}

          <Box component="form" onSubmit={handleSubmit}>
            <TextField
              fullWidth
              label="Username"
              margin="normal"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              required
            />
            <TextField
              fullWidth
              label="Password"
              type="password"
              margin="normal"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
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
              disabled={loading || !username || !password}
              sx={{ mt: 3 }}
            >
              {loading ? <CircularProgress size={24} color="inherit" /> : 'Sign In'}
            </Button>

            <Typography variant="body2" color="text.secondary" sx={{ mt: 2, textAlign: 'center' }}>
              Don't have an account?{' '}
              <Link to="/register" style={{ color: 'inherit', fontWeight: 500 }}>
                Register
              </Link>
            </Typography>
          </Box>
        </Box>
      </Box>
    </Box>
  );
}

export default Login;
