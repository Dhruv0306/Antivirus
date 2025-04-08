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
  Delete as DeleteIcon,
  Info as InfoIcon
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

// Configure axios defaults
axios.defaults.withCredentials = true;
axios.defaults.headers.common['Accept'] = 'application/json';
axios.defaults.headers.common['Content-Type'] = 'application/json';

function NetworkScan() {
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [networkStatus, setNetworkStatus] = useState({
    firewallEnabled: false,
    webProtectionEnabled: false,
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
      console.log('Fetching network status from:', `${API_BASE_URL}/status`);
      const response = await axios.get(`${API_BASE_URL}/status`);
      console.log('Network status response:', response.data);
      
      // Ensure blockedDomains is always an array
      const blockedDomains = Array.isArray(response.data.blockedDomains) 
        ? response.data.blockedDomains 
        : [];
        
      setNetworkStatus({
        ...response.data,
        blockedDomains,
        firewallEnabled: Boolean(response.data.securityControls?.firewallEnabled),
        webProtectionEnabled: Boolean(response.data.securityControls?.webProtectionEnabled)
      });
    } catch (error) {
      console.error('Error fetching network status:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        headers: error.response?.headers
      });
      
      if (error.response?.status === 403) {
        setError('Access denied. Please check server configuration.');
      } else if (error.code === 'ERR_NETWORK') {
        setError('Could not connect to the server. Please ensure the server is running and accessible.');
      } else {
        setError('Error connecting to server: ' + (error.response?.data?.message || error.message));
      }
    }
  };

  const handleScan = async () => {
    setScanning(true);
    setError(null);
    setScanResult(null);

    try {
      const response = await axios.post(`${API_BASE_URL}/scan`);
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
      console.log('Toggling firewall. Current state:', networkStatus.firewallEnabled);
      const response = await axios.post(`${API_BASE_URL}/firewall/toggle`, {
        enabled: !networkStatus.firewallEnabled
      });
      console.log('Firewall toggle response:', response.data);
      
      // Update local state immediately for better UX
      setNetworkStatus(prevStatus => ({
        ...prevStatus,
        firewallEnabled: !prevStatus.firewallEnabled
      }));
      
      // Fetch updated status from server
      await fetchNetworkStatus();
    } catch (error) {
      console.error('Error toggling firewall:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      
      // Revert the local state if the API call failed
      setNetworkStatus(prevStatus => ({
        ...prevStatus,
        firewallEnabled: !prevStatus.firewallEnabled
      }));
      
      setError('Error toggling firewall: ' + (error.response?.data?.error || error.message));
    }
  };

  const toggleWebProtection = async () => {
    try {
      console.log('Toggling web protection. Current state:', networkStatus.webProtectionEnabled);
      const response = await axios.post(`${API_BASE_URL}/web-protection/toggle`, {
        enabled: !networkStatus.webProtectionEnabled
      });
      console.log('Web protection toggle response:', response.data);
      
      // Update local state immediately for better UX
      setNetworkStatus(prevStatus => ({
        ...prevStatus,
        webProtectionEnabled: !prevStatus.webProtectionEnabled
      }));
      
      // Fetch updated status from server
      await fetchNetworkStatus();
    } catch (error) {
      console.error('Error toggling web protection:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status
      });
      
      // Revert the local state if the API call failed
      setNetworkStatus(prevStatus => ({
        ...prevStatus,
        webProtectionEnabled: !prevStatus.webProtectionEnabled
      }));
      
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
      console.log('Blocking domain:', newDomain);
      const response = await axios.post(`${API_BASE_URL}/block`, {
        domain: newDomain,
        reason: 'Manually blocked by user'
      });
      console.log('Block domain response:', response.data);
      
      await fetchNetworkStatus();
      setNewDomain('');
      setDomainError('');
    } catch (error) {
      console.error('Error blocking domain:', error);
      console.error('Error details:', {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
        headers: error.response?.headers
      });
      
      if (error.code === 'ERR_NETWORK') {
        setDomainError('Could not connect to the server. Please ensure the server is running.');
      } else {
        setDomainError('Error blocking domain: ' + (error.response?.data?.message || error.message));
      }
    }
  };

  const handleRemoveDomain = async (domain) => {
    try {
      await axios.post(`${API_BASE_URL}/unblock`, {
        domain: domain
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
                    <Typography component="div" sx={{ fontWeight: 500 }}>
                      Firewall Protection
                    </Typography>
                  }
                  secondary={
                    <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.firewallEnabled ? 'Enabled' : 'Disabled'}
                    </Typography>
                  }
                />
                <Switch
                  checked={Boolean(networkStatus.firewallEnabled)}
                  onChange={toggleFirewall}
                  inputProps={{ 'aria-label': 'Firewall toggle' }}
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
                    <Typography component="div" sx={{ fontWeight: 500 }}>
                      Web Protection
                    </Typography>
                  }
                  secondary={
                    <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.webProtectionEnabled ? 'Enabled' : 'Disabled'}
                    </Typography>
                  }
                />
                <Switch
                  checked={Boolean(networkStatus.webProtectionEnabled)}
                  onChange={toggleWebProtection}
                  inputProps={{ 'aria-label': 'Web protection toggle' }}
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
                    <Typography component="div" sx={{ fontWeight: 500 }}>
                      Active Connections
                    </Typography>
                  }
                  secondary={
                    <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
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
                    <Typography component="div" sx={{ fontWeight: 500 }}>
                      Blocked Attempts
                    </Typography>
                  }
                  secondary={
                    <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
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
              {networkStatus.blockedDomains?.map((item) => {
                // Convert the domain item to string if it's an object
                const domain = typeof item === 'object' ? item.domain : item;
                return domain ? (
                  <StyledChip
                    key={domain}
                    label={domain}
                    onDelete={() => handleRemoveDomain(domain)}
                    deleteIcon={<DeleteIcon />}
                    sx={{ m: 0.5 }}
                  />
                ) : null;
              })}
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
                {scanResult.threats > 0 ? (
                  <ErrorIcon sx={{ 
                    fontSize: 30, 
                    mr: 1, 
                    color: 'var(--error-main)' 
                  }} />
                ) : (
                  <CheckCircleIcon sx={{ 
                    fontSize: 30, 
                    mr: 1, 
                    color: 'var(--success-main)' 
                  }} />
                )}
                <Typography variant="h6" sx={{ fontWeight: 600 }}>
                  Network Scan Report
                </Typography>
              </Box>
              
              {/* Scan Summary */}
              <Box sx={{ mb: 3, p: 2, bgcolor: 'var(--background-default)', borderRadius: 1 }}>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ 
                        color: scanResult.threats > 0 ? 'var(--error-main)' : 'var(--success-main)',
                        fontWeight: 'bold'
                      }}>
                        {scanResult.threats}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Threats Detected
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: 'var(--primary-main)', fontWeight: 'bold' }}>
                        {scanResult.activeThreats}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Active Threats
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: 'var(--warning-main)', fontWeight: 'bold' }}>
                        {scanResult.blockedAttempts}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Blocked Attempts
                      </Typography>
                    </Box>
                  </Grid>
                  <Grid item xs={12} sm={6} md={3}>
                    <Box sx={{ textAlign: 'center' }}>
                      <Typography variant="h4" sx={{ color: 'var(--info-main)', fontWeight: 'bold' }}>
                        {scanResult.openPorts?.length || 0}
                      </Typography>
                      <Typography variant="body2" color="text.secondary">
                        Open Ports
                      </Typography>
                    </Box>
                  </Grid>
                </Grid>
              </Box>
              
              {/* Scan Details */}
              <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                Scan Details
              </Typography>
              <Box sx={{ mb: 3 }}>
                <Grid container spacing={2}>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary">
                      Scan Time: {new Date(scanResult.scanTime).toLocaleString()}
                    </Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary" component="div">
                      Status: <Chip 
                        label={scanResult.status} 
                        size="small" 
                        color={scanResult.status === 'COMPLETED' ? 'success' : 'warning'} 
                      />
                    </Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary" component="div">
                      Firewall: <Chip 
                        label={scanResult.firewallEnabled ? 'Enabled' : 'Disabled'} 
                        size="small" 
                        color={scanResult.firewallEnabled ? 'success' : 'error'} 
                      />
                    </Typography>
                  </Grid>
                  <Grid item xs={12} sm={6}>
                    <Typography variant="body2" color="text.secondary" component="div">
                      Web Protection: <Chip 
                        label={scanResult.webProtectionEnabled ? 'Enabled' : 'Disabled'} 
                        size="small" 
                        color={scanResult.webProtectionEnabled ? 'success' : 'error'} 
                      />
                    </Typography>
                  </Grid>
                </Grid>
              </Box>
              
              {/* Vulnerabilities */}
              {scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0 && (
                <>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Vulnerabilities
                  </Typography>
                  <Box sx={{ mb: 3 }}>
                    {scanResult.vulnerabilities.map((vuln, index) => (
                      <Paper 
                        key={index} 
                        sx={{ 
                          p: 2, 
                          mb: 1, 
                          bgcolor: 'var(--background-default)',
                          borderLeft: `4px solid ${
                            vuln.severity === 'CRITICAL' ? 'var(--error-main)' :
                            vuln.severity === 'HIGH' ? 'var(--error-light)' :
                            vuln.severity === 'MEDIUM' ? 'var(--warning-main)' :
                            'var(--info-main)'
                          }`
                        }}
                      >
                        <Box sx={{ display: 'flex', alignItems: 'flex-start' }}>
                          <Box sx={{ mr: 1 }}>
                            {vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH' ? (
                              <ErrorIcon sx={{ color: 'var(--error-main)' }} />
                            ) : vuln.severity === 'MEDIUM' ? (
                              <WarningIcon sx={{ color: 'var(--warning-main)' }} />
                            ) : (
                              <InfoIcon sx={{ color: 'var(--info-main)' }} />
                            )}
                          </Box>
                          <Box sx={{ flex: 1 }}>
                            <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                              {vuln.type.replace(/_/g, ' ')}
                            </Typography>
                            <Typography variant="body2" color="text.secondary">
                              {vuln.description}
                            </Typography>
                            <Typography variant="body2" sx={{ mt: 1, color: 'var(--primary-main)' }}>
                              <strong>Recommendation:</strong> {vuln.recommendation}
                            </Typography>
                          </Box>
                          <Chip 
                            label={vuln.severity} 
                            size="small" 
                            color={
                              vuln.severity === 'CRITICAL' || vuln.severity === 'HIGH' ? 'error' :
                              vuln.severity === 'MEDIUM' ? 'warning' : 'info'
                            } 
                          />
                        </Box>
                      </Paper>
                    ))}
                  </Box>
                </>
              )}
              
              {/* Open Ports */}
              {scanResult.openPorts && scanResult.openPorts.length > 0 && (
                <>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Open Ports
                  </Typography>
                  <Box sx={{ mb: 3 }}>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {scanResult.openPorts.map((port, index) => (
                        <Chip 
                          key={index}
                          label={`Port ${port}`}
                          color="warning"
                          variant="outlined"
                          sx={{ m: 0.5 }}
                        />
                      ))}
                    </Stack>
                  </Box>
                </>
              )}
              
              {/* Suspicious Connections */}
              {scanResult.suspiciousConnections && scanResult.suspiciousConnections.length > 0 && (
                <>
                  <Typography variant="subtitle1" sx={{ fontWeight: 600, mb: 1 }}>
                    Suspicious Connections
                  </Typography>
                  <Box sx={{ mb: 3 }}>
                    <Stack direction="row" spacing={1} flexWrap="wrap" useFlexGap>
                      {scanResult.suspiciousConnections.map((ip, index) => (
                        <Chip 
                          key={index}
                          label={ip}
                          color="error"
                          icon={<BlockIcon />}
                          sx={{ m: 0.5 }}
                        />
                      ))}
                    </Stack>
                  </Box>
                </>
              )}
              
              {/* Action Buttons */}
              <Box sx={{ display: 'flex', justifyContent: 'flex-end', mt: 2 }}>
                <Button 
                  variant="outlined" 
                  color="primary" 
                  onClick={() => setScanResult(null)}
                  sx={{ mr: 1 }}
                >
                  Close Report
                </Button>
                <Button 
                  variant="contained" 
                  color="primary" 
                  onClick={handleScan}
                  startIcon={<SecurityIcon />}
                >
                  Run New Scan
                </Button>
              </Box>
            </StyledCard>
          </Grid>
        )}
      </Grid>
    </Box>
  );
}

export default NetworkScan; 