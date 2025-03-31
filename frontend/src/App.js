import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import Box from '@mui/material/Box';
import Container from '@mui/material/Container';

// Components
import Navigation from './components/Navigation';
import Dashboard from './components/Dashboard';
import FileScan from './components/FileScan';
import DirectoryScan from './components/DirectoryScan';
import SystemScan from './components/SystemScan';
import NetworkScan from './components/NetworkScan';
import Sidebar from './components/Sidebar';

// Create a modern theme with improved colors and typography
const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00ffff', // Bright cyan
      light: '#80ffff',
      dark: '#00cccc',
    },
    secondary: {
      main: '#ff1493', // Bright pink
      light: '#ff69b4',
      dark: '#c71585',
    },
    success: {
      main: '#00ff00', // Bright green
      light: '#66ff66',
      dark: '#00cc00',
    },
    error: {
      main: '#ff3d00', // Bright orange-red
      light: '#ff7539',
      dark: '#c30000',
    },
    background: {
      default: '#001529', // Darker blue background
      paper: '#002140', // Slightly lighter blue for cards
    },
    text: {
      primary: '#ffffff',
      secondary: 'rgba(255, 255, 255, 0.85)',
    },
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
          boxShadow: '0 4px 15px rgba(0, 255, 255, 0.15)', // Cyan glow
          background: 'linear-gradient(145deg, rgba(0, 33, 64, 0.9), rgba(0, 21, 41, 0.9))',
          backdropFilter: 'blur(10px)',
          border: '1px solid rgba(0, 255, 255, 0.1)',
        },
      },
    },
    MuiLinearProgress: {
      styleOverrides: {
        root: {
          backgroundColor: 'rgba(255, 255, 255, 0.1)',
          '& .MuiLinearProgress-bar': {
            backgroundImage: 'linear-gradient(90deg, #00ffff, #80ffff)',
          },
        },
      },
    },
    MuiAlert: {
      styleOverrides: {
        standardSuccess: {
          backgroundColor: 'rgba(0, 255, 0, 0.1)',
          color: '#00ff00',
        },
        standardError: {
          backgroundColor: 'rgba(255, 61, 0, 0.1)',
          color: '#ff3d00',
        },
      },
    },
  },
});

function App() {
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
