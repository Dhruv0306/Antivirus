import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  CircularProgress,
  Alert,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Grid,
  Switch,
  FormControlLabel,
  Card,
  IconButton,
  TextField,
  Stack,
  Chip
} from '@mui/material';
import {
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon,
  Wifi as WifiIcon,
  Language as LanguageIcon,
  Lock as LockIcon,
  LockOpen as LockOpenIcon,
  Shield as ShieldIcon,
  Block as BlockIcon,
  NetworkCheck as NetworkCheckIcon,
  Add as AddIcon,
  Delete as DeleteIcon
} from '@mui/icons-material';
import axios from 'axios';
import { styled } from '@mui/material/styles';

// Styled components
const StyledCard = styled(Card)(({ theme }) => ({
  padding: 'var(--spacing-lg)',
  backgroundColor: 'var(--background-paper)',
  color: 'var(--text-primary)',
  border: '1px solid var(--border-main)',
  borderRadius: 'var(--border-radius-medium)',
  transition: 'all 0.2s ease-in-out',
  '&:hover': {
    borderColor: 'var(--primary-main)',
    boxShadow: 'var(--shadow-large)'
  }
}));

const StyledButton = styled(Button)(({ theme }) => ({
  backgroundColor: 'var(--button-primary)',
  color: 'var(--button-text)',
  '&:hover': {
    backgroundColor: 'var(--primary-dark)',
    boxShadow: 'var(--shadow-medium)'
  }
}));

const StyledTextField = styled(TextField)(({ theme }) => ({
  '& .MuiOutlinedInput-root': {
    backgroundColor: 'var(--input-background)',
    color: 'var(--text-primary)',
    '& fieldset': {
      borderColor: 'var(--input-border)'
    },
    '&:hover fieldset': {
      borderColor: 'var(--primary-light)'
    },
    '&.Mui-focused fieldset': {
      borderColor: 'var(--primary-main)'
    }
  },
  '& .MuiInputLabel-root': {
    color: 'var(--text-secondary)'
  }
}));

const StyledChip = styled(Chip)(({ theme }) => ({
  backgroundColor: 'var(--primary-main)',
  color: 'var(--primary-contrast)',
  '&:hover': {
    backgroundColor: 'var(--primary-dark)'
  }
}));

// API configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api/network-security';

axios.defaults.withCredentials = true;
axios.defaults.headers.common['Accept'] = 'application/json';
axios.defaults.headers.common['Access-Control-Allow-Origin'] = 'http://localhost:5000';

function NetworkScan() {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [networkStatus, setNetworkStatus] = useState({
    firewallEnabled: true,
    webProtectionEnabled: true,
    activeThreats: 0,
    activeConnections: 0,
    blockedAttempts: 0,
    blockedDomains: [],
    recentConnections: []
  });
  const [newDomain, setNewDomain] = useState('');
  const [domainError, setDomainError] = useState('');

  // Fetch initial network status
  useEffect(() => {
    fetchNetworkStatus();
    const interval = setInterval(fetchNetworkStatus, 30000); // Update every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const fetchNetworkStatus = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/status`, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      setNetworkStatus(response.data);
    } catch (error) {
      console.error('Error fetching network status:', error);
      if (error.response?.status === 403) {
        setError('Access denied. Please check server configuration.');
      } else {
        setError('Error connecting to server. Please ensure the server is running.');
      }
    }
  };

  const handleScan = async () => {
    setScanning(true);
    setError(null);
    setScanResult(null);

    try {
      const response = await axios.post(`${API_BASE_URL}/scan`, {}, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      setScanResult(response.data);
      await fetchNetworkStatus();
    } catch (err) {
      console.error('Network scan error:', err);
      setError('Error during network scan: ' + (err.response?.data?.error || err.message));
    } finally {
      setScanning(false);
    }
  };

  const toggleFirewall = async () => {
    try {
      await axios.post(`${API_BASE_URL}/firewall/toggle`, {
        enabled: !networkStatus.firewallEnabled
      }, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      await fetchNetworkStatus();
    } catch (error) {
      console.error('Error toggling firewall:', error);
      setError('Error toggling firewall: ' + (error.response?.data?.error || error.message));
    }
  };

  const toggleWebProtection = async () => {
    try {
      await axios.post(`${API_BASE_URL}/web-protection/toggle`, {
        enabled: !networkStatus.webProtectionEnabled
      }, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      await fetchNetworkStatus();
    } catch (error) {
      console.error('Error toggling web protection:', error);
      setError('Error toggling web protection: ' + (error.response?.data?.error || error.message));
    }
  };

  const handleAddDomain = async () => {
    if (!newDomain) {
      setDomainError('Please enter a domain');
      return;
    }

    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-_.]+\.[a-zA-Z]{2,}$/;
    if (!domainRegex.test(newDomain)) {
      setDomainError('Please enter a valid domain name');
      return;
    }

    try {
      await axios.post(`${API_BASE_URL}/domains/block`, {
        domain: newDomain
      }, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      await fetchNetworkStatus();
      setNewDomain('');
      setDomainError('');
    } catch (error) {
      console.error('Error blocking domain:', error);
      setDomainError('Error blocking domain: ' + (error.response?.data?.message || error.message));
    }
  };

  const handleRemoveDomain = async (domain) => {
    try {
      await axios.delete(`${API_BASE_URL}/domains/${domain}`, {
        withCredentials: true,
        headers: {
          'Content-Type': 'application/json'
        }
      });
      await fetchNetworkStatus();
    } catch (error) {
      console.error('Error removing domain:', error);
      setError('Error removing domain: ' + (error.response?.data?.message || error.message));
    }
  };

  return (
    <Box sx={{ p: 3, color: 'var(--text-primary)' }}>
      <Typography 
        variant="h3" 
        gutterBottom 
        align="center" 
        sx={{ 
          color: 'var(--text-primary)',
          mb: 4,
          fontWeight: 600
        }}
      >
        Network Security
      </Typography>

      <Grid container spacing={3}>
        {/* Security Controls Card */}
        <Grid item xs={12} md={6}>
          <StyledCard>
            <Box sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              mb: 2 
            }}>
              <ShieldIcon sx={{ 
                fontSize: 30, 
                mr: 1, 
                color: 'var(--primary-main)' 
              }} />
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Security Controls
              </Typography>
            </Box>
            <List>
              <ListItem>
                <ListItemIcon>
                  <LockIcon sx={{ 
                    color: networkStatus.firewallEnabled 
                      ? 'var(--success-main)' 
                      : 'var(--error-main)' 
                  }} />
                </ListItemIcon>
                <ListItemText 
                  primary={
                    <Typography sx={{ fontWeight: 500 }}>
                      Firewall Protection
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.firewallEnabled ? 'Enabled' : 'Disabled'}
                    </Typography>
                  }
                />
                <Switch
                  checked={networkStatus.firewallEnabled}
                  onChange={toggleFirewall}
                  sx={{
                    '& .MuiSwitch-switchBase.Mui-checked': {
                      color: 'var(--success-main)',
                      '& + .MuiSwitch-track': {
                        backgroundColor: 'var(--success-light)'
                      }
                    }
                  }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <LanguageIcon sx={{ 
                    color: networkStatus.webProtectionEnabled 
                      ? 'var(--success-main)' 
                      : 'var(--error-main)' 
                  }} />
                </ListItemIcon>
                <ListItemText 
                  primary={
                    <Typography sx={{ fontWeight: 500 }}>
                      Web Protection
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.webProtectionEnabled ? 'Enabled' : 'Disabled'}
                    </Typography>
                  }
                />
                <Switch
                  checked={networkStatus.webProtectionEnabled}
                  onChange={toggleWebProtection}
                  sx={{
                    '& .MuiSwitch-switchBase.Mui-checked': {
                      color: 'var(--success-main)',
                      '& + .MuiSwitch-track': {
                        backgroundColor: 'var(--success-light)'
                      }
                    }
                  }}
                />
              </ListItem>
            </List>
          </StyledCard>
        </Grid>

        {/* Network Status Card */}
        <Grid item xs={12} md={6}>
          <StyledCard>
            <Box sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              mb: 2 
            }}>
              <NetworkCheckIcon sx={{ 
                fontSize: 30, 
                mr: 1, 
                color: 'var(--primary-main)' 
              }} />
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Network Status
              </Typography>
            </Box>
            <List>
              <ListItem>
                <ListItemIcon>
                  <WifiIcon sx={{ color: 'var(--primary-main)' }} />
                </ListItemIcon>
                <ListItemText 
                  primary={
                    <Typography sx={{ fontWeight: 500 }}>
                      Active Connections
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.activeConnections}
                    </Typography>
                  }
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <BlockIcon sx={{ color: 'var(--warning-main)' }} />
                </ListItemIcon>
                <ListItemText 
                  primary={
                    <Typography sx={{ fontWeight: 500 }}>
                      Blocked Attempts
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.blockedAttempts}
                    </Typography>
                  }
                />
              </ListItem>
            </List>
          </StyledCard>
        </Grid>

        {/* Blocked Domains Card */}
        <Grid item xs={12}>
          <StyledCard>
            <Box sx={{ 
              display: 'flex', 
              alignItems: 'center', 
              mb: 2 
            }}>
              <BlockIcon sx={{ 
                fontSize: 30, 
                mr: 1, 
                color: 'var(--primary-main)' 
              }} />
              <Typography variant="h6" sx={{ fontWeight: 600 }}>
                Blocked Domains
              </Typography>
            </Box>
            <Box sx={{ mb: 2 }}>
              <StyledTextField
                fullWidth
                label="Add Domain to Block"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                error={!!domainError}
                helperText={domainError}
                InputProps={{
                  endAdornment: (
                    <IconButton 
                      onClick={handleAddDomain}
                      sx={{ color: 'var(--primary-main)' }}
                    >
                      <AddIcon />
                    </IconButton>
                  ),
                }}
              />
            </Box>
            <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
              {networkStatus.blockedDomains.map((domain) => (
                <StyledChip
                  key={domain}
                  label={domain}
                  onDelete={() => handleRemoveDomain(domain)}
                  deleteIcon={<DeleteIcon />}
                />
              ))}
            </Stack>
          </StyledCard>
        </Grid>

        {/* Scan Button */}
        <Grid item xs={12} sx={{ textAlign: 'center', mt: 2 }}>
          <StyledButton
            variant="contained"
            size="large"
            onClick={handleScan}
            disabled={scanning}
            startIcon={scanning ? <CircularProgress size={20} /> : <SecurityIcon />}
          >
            {scanning ? 'Scanning Network...' : 'Start Network Scan'}
          </StyledButton>
        </Grid>

        {/* Error Alert */}
        {error && (
          <Grid item xs={12}>
            <Alert 
              severity="error" 
              sx={{ 
                backgroundColor: 'var(--error-main)',
                color: '#FFFFFF',
                '& .MuiAlert-icon': {
                  color: '#FFFFFF'
                }
              }}
            >
              {error}
            </Alert>
          </Grid>
        )}

        {/* Scan Results */}
        {scanResult && (
          <Grid item xs={12}>
            <StyledCard>
              <Box sx={{ 
                display: 'flex', 
                alignItems: 'center', 
                mb: 2 
              }}>
                <CheckCircleIcon sx={{ 
                  fontSize: 30, 
                  mr: 1, 
                  color: 'var(--success-main)' 
                }} />
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  Scan Results
                </Typography>
              </Box>
              {/* Add your scan results display here */}
            </StyledCard>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}

export default NetworkScan; 