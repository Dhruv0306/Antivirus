import React, { useMemo } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import { getThemeColors } from './theme/colors';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './components/Login';
import Dashboard from './components/Dashboard';
import FileScan from './components/FileScan';
import DirectoryScan from './components/DirectoryScan';
import SystemScan from './components/SystemScan';
import NetworkScan from './components/NetworkScan';
import AutoScanGuide from './components/AutoScanGuide';
import Sidebar from './components/Sidebar';

function AppLayout() {
  return (
    <Box sx={{
      bgcolor: 'background.default',
      minHeight: '100vh',
      pt: 2,
      pb: 2,
    }}>
      <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
        <Sidebar />
        <Box
          component="main"
          sx={{
            flexGrow: 1,
            p: 2,
            width: { sm: 'calc(100% - 240px)' },
          }}
        >
          <Container maxWidth="xl" sx={{ mt: 0, mb: 0 }}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/file-scan" element={<FileScan />} />
              <Route path="/directory-scan" element={<DirectoryScan />} />
              <Route path="/system-scan" element={<SystemScan />} />
              <Route path="/network-security" element={<NetworkScan />} />
              <Route path="/auto-scan-guide" element={<AutoScanGuide />} />
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
            <Route path="/login" element={<Login />} />
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
