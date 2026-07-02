import React, { useMemo, useState } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import IconButton from '@mui/material/IconButton';
import Typography from '@mui/material/Typography';
import MenuIcon from '@mui/icons-material/Menu';
import SecurityIcon from '@mui/icons-material/Security';
import { getThemeColors } from './theme/colors';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute, { AdminRoute } from './components/ProtectedRoute';
import Login from './components/Login';
import Register from './components/Register';
import Dashboard from './components/Dashboard';
import FileScan from './components/FileScan';
import DirectoryScan from './components/DirectoryScan';
import SystemScan from './components/SystemScan';
import NetworkScan from './components/NetworkScan';
import AutoScanGuide from './components/AutoScanGuide';
import Sidebar, { SIDEBAR_MOBILE_BREAKPOINT } from './components/Sidebar';

// Only rendered below the md breakpoint. Desktop/laptop layout never mounts
// this — the sidebar stays permanently visible there, same as before.
function MobileAppBar({ onMenuClick }) {
  return (
    <AppBar
      position="sticky"
      elevation={0}
      sx={{
        display: { xs: 'flex', [SIDEBAR_MOBILE_BREAKPOINT]: 'none' },
        top: 0,
        backgroundColor: 'var(--background-paper)',
        color: 'var(--text-primary)',
        borderBottom: '1px solid var(--border-main)',
      }}
    >
      <Toolbar>
        <IconButton
          edge="start"
          color="inherit"
          aria-label="open navigation menu"
          onClick={onMenuClick}
          sx={{ mr: 1 }}
        >
          <MenuIcon />
        </IconButton>
        <SecurityIcon sx={{ color: 'var(--primary-main)', mr: 1 }} />
        <Typography
          variant="h6"
          component="div"
          sx={{
            fontWeight: 600,
            background: 'linear-gradient(45deg, var(--primary-main), var(--primary-light))',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent',
          }}
        >
          SecureGuard
        </Typography>
      </Toolbar>
    </AppBar>
  );
}

function AppLayout() {
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <Box sx={{
      bgcolor: 'background.default',
      minHeight: '100vh',
      pt: { xs: 0, [SIDEBAR_MOBILE_BREAKPOINT]: 2 },
      pb: 2,
    }}>
      <MobileAppBar onMenuClick={() => setMobileOpen(true)} />

      <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
        <Sidebar
          mobileOpen={mobileOpen}
          onMobileClose={() => setMobileOpen(false)}
        />
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            p: { xs: 1, sm: 2 },
            width: { xs: '100%', [SIDEBAR_MOBILE_BREAKPOINT]: 'calc(100% - 240px)' },
            minWidth: 0,
          }}
        >
          <Container maxWidth="xl" sx={{ mt: 0, mb: 0 }}>
            <Routes>
              {/* Available to all authenticated users */}
              <Route path="/" element={<Dashboard />} />
              <Route path="/file-scan" element={<FileScan />} />
              <Route path="/directory-scan" element={<DirectoryScan />} />

              {/* Admin only — non-admin users are redirected to / by AdminRoute */}
              <Route path="/system-scan" element={<AdminRoute><SystemScan /></AdminRoute>} />
              <Route path="/network-security" element={<AdminRoute><NetworkScan /></AdminRoute>} />
              <Route path="/auto-scan-guide" element={<AdminRoute><AutoScanGuide /></AdminRoute>} />
            </Routes>
          </Container>
        </Box>
      </Box>
    </Box>
  );
}

function App() {
  const theme = useMemo(() => {
    const colors = getThemeColors();
    return createTheme({
      palette: {
        mode: 'light',
        ...colors,
      },
      typography: {
        fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
      },
      shape: {
        borderRadius: 8,
      },
    });
  }, []);

  return (
    <AuthProvider>
      <Router>
        <ThemeProvider theme={theme}>
          <CssBaseline />
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<Login />} />
            <Route path="/register" element={<Register />} />

            {/* Protected shell — Sidebar + nested routes */}
            <Route
              path="/*"
              element={(
                <ProtectedRoute>
                  <AppLayout />
                </ProtectedRoute>
              )}
            />
          </Routes>
        </ThemeProvider>
      </Router>
    </AuthProvider>
  );
}

export default App;
