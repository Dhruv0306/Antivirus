import React, { useMemo } from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import { getThemeColors } from './theme/colors';

// Components
import Dashboard from './components/Dashboard';
import FileScan from './components/FileScan';
import DirectoryScan from './components/DirectoryScan';
import SystemScan from './components/SystemScan';
import NetworkScan from './components/NetworkScan';
import AutoScanGuide from './components/AutoScanGuide';
import Sidebar from './components/Sidebar';

function App() {
  // Create theme with dynamic colors from CSS variables
  const theme = useMemo(() => {
    const colors = getThemeColors();
    return createTheme({
      palette: {
        mode: 'light',
        ...colors,
      },
      typography: {
        fontFamily: '"Inter", "Roboto", "Helvetica", "Arial", sans-serif',
        h1: {
          fontWeight: 700,
          fontSize: '2.5rem',
        },
        h2: {
          fontWeight: 600,
          fontSize: '2rem',
        },
        h3: {
          fontWeight: 600,
          fontSize: '1.75rem',
        },
        h4: {
          fontWeight: 600,
          fontSize: '1.5rem',
        },
        body1: {
          fontSize: '1rem',
          lineHeight: 1.5,
        },
      },
      shape: {
        borderRadius: 8,
      },
      components: {
        MuiButton: {
          styleOverrides: {
            root: {
              textTransform: 'none',
              borderRadius: 8,
              padding: '8px 16px',
              fontWeight: 500,
            },
          },
        },
        MuiCard: {
          styleOverrides: {
            root: {
              borderRadius: 12,
              boxShadow: '0 4px 15px rgba(0, 170, 255, 0.15)', // Blue glow
              background: 'var(--background-paper)',
              border: '1px solid var(--border-main)',
            },
          },
        },
        MuiLinearProgress: {
          styleOverrides: {
            root: {
              backgroundColor: 'var(--background-dark)',
              '& .MuiLinearProgress-bar': {
                backgroundImage: 'linear-gradient(90deg, var(--primary-main), var(--primary-light))',
              },
            },
          },
        },
        MuiAlert: {
          styleOverrides: {
            standardSuccess: {
              backgroundColor: 'var(--success-transparent)',
              color: 'var(--success-main)',
            },
            standardError: {
              backgroundColor: 'var(--error-transparent)',
              color: 'var(--error-main)',
            },
          },
        },
      },
    });
  }, []);

  return (
    <Router>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <Box sx={{ 
          bgcolor: 'background.default',
          minHeight: '100vh',
          position: 'relative',
          pt: 2,
          pb: 2,
        }}>
          <Box sx={{
            display: 'flex',
            alignItems: 'flex-start', // Align items to the top
          }}>
            <Sidebar />
            <Box 
              component="main" 
              sx={{ 
                flexGrow: 1,
                p: 2,
                width: { sm: `calc(100% - 240px)` },
                ml: { sm: '0px' },
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
      </ThemeProvider>
    </Router>
  );
}

export default App;
