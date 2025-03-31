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

// API base URL configuration
const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api/network-security';

// Axios default configuration
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
    <Box sx={{ p: 3 }}>
      <Typography variant="h3" gutterBottom align="center" sx={{ color: 'white', mb: 4 }}>
        Network Security
      </Typography>

      <Grid container spacing={3}>
        {/* Security Controls Card */}
        <Grid item xs={12} md={6}>
          <Card sx={{ p: 3, bgcolor: '#333', color: 'white' }}>
            <Typography variant="h5" gutterBottom>
              Security Controls
            </Typography>
            <List>
              <ListItem>
                <ListItemIcon>
                  <SecurityIcon sx={{ color: '#1976d2' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Firewall"
                  secondary={networkStatus.firewallEnabled ? "Active protection enabled" : "Protection disabled"}
                  secondaryTypographyProps={{ sx: { color: 'grey.500' } }}
                />
                <Switch
                  checked={networkStatus.firewallEnabled}
                  onChange={toggleFirewall}
                  color="primary"
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <LanguageIcon sx={{ color: '#1976d2' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Web Protection"
                  secondary={networkStatus.webProtectionEnabled ? "Browsing protection active" : "Protection disabled"}
                  secondaryTypographyProps={{ sx: { color: 'grey.500' } }}
                />
                <Switch
                  checked={networkStatus.webProtectionEnabled}
                  onChange={toggleWebProtection}
                  color="primary"
                />
              </ListItem>
            </List>
          </Card>
        </Grid>

        {/* Network Status Card */}
        <Grid item xs={12} md={6}>
          <Card sx={{ p: 3, bgcolor: '#333', color: 'white' }}>
            <Typography variant="h5" gutterBottom>
              Network Status
            </Typography>
            <List>
              <ListItem>
                <ListItemIcon>
                  <WarningIcon sx={{ color: '#f44336' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Active Threats"
                  secondary={networkStatus.activeThreats}
                  secondaryTypographyProps={{ sx: { color: 'grey.500' } }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <NetworkCheckIcon sx={{ color: '#4caf50' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Active Connections"
                  secondary={networkStatus.activeConnections}
                  secondaryTypographyProps={{ sx: { color: 'grey.500' } }}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <BlockIcon sx={{ color: '#ff9800' }} />
                </ListItemIcon>
                <ListItemText 
                  primary="Blocked Attempts"
                  secondary={networkStatus.blockedAttempts}
                  secondaryTypographyProps={{ sx: { color: 'grey.500' } }}
                />
              </ListItem>
            </List>
          </Card>
        </Grid>

        {/* Blocked Domains Card */}
        <Grid item xs={12}>
          <Card sx={{ p: 3, bgcolor: '#333', color: 'white' }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
              <Typography variant="h5">
                Blocked Domains
              </Typography>
              <Button
                variant="contained"
                color="primary"
                startIcon={<AddIcon />}
                onClick={() => document.getElementById('domain-input').focus()}
              >
                Add Domain
              </Button>
            </Box>

            {/* Domain Input */}
            <Box sx={{ mb: 3 }}>
              <TextField
                id="domain-input"
                fullWidth
                variant="outlined"
                size="small"
                placeholder="Enter domain to block (e.g., malicious-site.com)"
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                error={!!domainError}
                helperText={domainError}
                onKeyPress={(e) => {
                  if (e.key === 'Enter') {
                    handleAddDomain();
                  }
                }}
                sx={{
                  '& .MuiOutlinedInput-root': {
                    color: 'white',
                    bgcolor: 'rgba(0, 0, 0, 0.2)',
                    '& fieldset': {
                      borderColor: 'rgba(255, 255, 255, 0.23)',
                    },
                    '&:hover fieldset': {
                      borderColor: 'rgba(255, 255, 255, 0.5)',
                    },
                    '&.Mui-focused fieldset': {
                      borderColor: '#1976d2',
                    },
                  },
                  '& .MuiFormHelperText-root': {
                    color: theme => domainError ? '#f44336' : 'grey.500',
                  },
                }}
              />
            </Box>

            {/* Blocked Domains List */}
            <Box sx={{ 
              display: 'flex', 
              flexWrap: 'wrap', 
              gap: 1,
              minHeight: 50
            }}>
              {networkStatus.blockedDomains.map((domain, index) => (
                <Chip
                  key={index}
                  label={domain}
                  onDelete={() => handleRemoveDomain(domain)}
                  icon={<BlockIcon />}
                  sx={{
                    bgcolor: 'rgba(255, 87, 34, 0.15)',
                    color: '#ff9800',
                    '& .MuiChip-icon': {
                      color: '#ff9800',
                    },
                    '& .MuiChip-deleteIcon': {
                      color: '#ff9800',
                      '&:hover': {
                        color: '#f57c00',
                      },
                    },
                  }}
                />
              ))}
              {networkStatus.blockedDomains.length === 0 && (
                <Typography 
                  variant="body2" 
                  sx={{ 
                    color: 'grey.500',
                    fontStyle: 'italic',
                    width: '100%',
                    textAlign: 'center',
                    py: 2
                  }}
                >
                  No domains blocked
                </Typography>
              )}
            </Box>
          </Card>
        </Grid>

        {/* Recent Connections Card */}
        <Grid item xs={12}>
          <Card sx={{ p: 3, bgcolor: '#333', color: 'white' }}>
            <Typography variant="h5" gutterBottom>
              Recent Connections
            </Typography>
            <List>
              {networkStatus.recentConnections.map((connection, index) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    <NetworkCheckIcon sx={{ color: '#4caf50' }} />
                  </ListItemIcon>
                  <ListItemText 
                    primary={connection.domain}
                    secondary={`${connection.ip} - ${connection.timestamp}`}
                    secondaryTypographyProps={{ sx: { color: 'grey.500' } }}
                  />
                </ListItem>
              ))}
              {networkStatus.recentConnections.length === 0 && (
                <ListItem>
                  <ListItemText primary="No recent connections" sx={{ color: 'grey.500' }} />
                </ListItem>
              )}
            </List>
          </Card>
        </Grid>
      </Grid>
    </Box>
  );
}

export default NetworkScan; 