import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Grid,
  Switch,
  FormControlLabel,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemSecondaryAction,
  IconButton,
  Alert,
  Chip,
} from '@mui/material';
import {
  Security as SecurityIcon,
  Language as WebIcon,
  Block as BlockIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Delete as DeleteIcon,
} from '@mui/icons-material';
import axios from 'axios';

function NetworkSecurity() {
  const [firewallEnabled, setFirewallEnabled] = useState(true);
  const [webProtectionEnabled, setWebProtectionEnabled] = useState(true);
  const [networkStatus, setNetworkStatus] = useState({
    threats: 0,
    connections: 0,
    blockedAttempts: 0,
    lastUpdate: new Date().toISOString(),
  });
  const [blockedDomains, setBlockedDomains] = useState([]);
  const [recentConnections, setRecentConnections] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Fetch initial network status
    fetchNetworkStatus();
    // Set up periodic updates
    const interval = setInterval(fetchNetworkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchNetworkStatus = async () => {
    try {
      const response = await axios.get('http://localhost:8080/api/antivirus/network/status');
      setNetworkStatus(response.data);
      setBlockedDomains(response.data.blockedDomains || []);
      setRecentConnections(response.data.recentConnections || []);
    } catch (error) {
      setError('Error fetching network status: ' + (error.response?.data?.message || error.message));
    }
  };

  const handleFirewallToggle = async () => {
    try {
      await axios.post('http://localhost:8080/api/antivirus/network/firewall', {
        enabled: !firewallEnabled
      });
      setFirewallEnabled(!firewallEnabled);
    } catch (error) {
      setError('Error toggling firewall: ' + (error.response?.data?.message || error.message));
    }
  };

  const handleWebProtectionToggle = async () => {
    try {
      await axios.post('http://localhost:8080/api/antivirus/network/web-protection', {
        enabled: !webProtectionEnabled
      });
      setWebProtectionEnabled(!webProtectionEnabled);
    } catch (error) {
      setError('Error toggling web protection: ' + (error.response?.data?.message || error.message));
    }
  };

  const handleRemoveBlockedDomain = async (domain) => {
    try {
      await axios.delete(`http://localhost:8080/api/antivirus/network/blocked-domains/${domain}`);
      setBlockedDomains(blockedDomains.filter(d => d !== domain));
    } catch (error) {
      setError('Error removing blocked domain: ' + (error.response?.data?.message || error.message));
    }
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        Network Security
      </Typography>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Security Controls
            </Typography>
            <List>
              <ListItem>
                <ListItemIcon>
                  <SecurityIcon color={firewallEnabled ? "primary" : "disabled"} />
                </ListItemIcon>
                <ListItemText
                  primary="Firewall"
                  secondary={firewallEnabled ? "Active protection enabled" : "Protection disabled"}
                />
                <ListItemSecondaryAction>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={firewallEnabled}
                        onChange={handleFirewallToggle}
                        color="primary"
                      />
                    }
                    label=""
                  />
                </ListItemSecondaryAction>
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <WebIcon color={webProtectionEnabled ? "primary" : "disabled"} />
                </ListItemIcon>
                <ListItemText
                  primary="Web Protection"
                  secondary={webProtectionEnabled ? "Browsing protection active" : "Protection disabled"}
                />
                <ListItemSecondaryAction>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={webProtectionEnabled}
                        onChange={handleWebProtectionToggle}
                        color="primary"
                      />
                    }
                    label=""
                  />
                </ListItemSecondaryAction>
              </ListItem>
            </List>
          </Paper>
        </Grid>

        <Grid item xs={12} md={6}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Network Status
            </Typography>
            <List>
              <ListItem>
                <ListItemIcon>
                  <WarningIcon color={networkStatus.threats > 0 ? "error" : "success"} />
                </ListItemIcon>
                <ListItemText
                  primary="Active Threats"
                  secondary={networkStatus.threats}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <WebIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Active Connections"
                  secondary={networkStatus.connections}
                />
              </ListItem>
              <ListItem>
                <ListItemIcon>
                  <BlockIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Blocked Attempts"
                  secondary={networkStatus.blockedAttempts}
                />
              </ListItem>
            </List>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Blocked Domains
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {blockedDomains && blockedDomains.map((domain) => (
                <Chip
                  key={domain}
                  label={domain}
                  onDelete={() => handleRemoveBlockedDomain(domain)}
                  color="error"
                  variant="outlined"
                />
              ))}
            </Box>
          </Paper>
        </Grid>

        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Typography variant="h6" gutterBottom>
              Recent Connections
            </Typography>
            <List>
              {recentConnections.map((connection, index) => (
                <ListItem key={index}>
                  <ListItemIcon>
                    {connection.secure ? <CheckCircleIcon color="success" /> : <WarningIcon color="warning" />}
                  </ListItemIcon>
                  <ListItemText
                    primary={connection.domain}
                    secondary={`${connection.timestamp} - ${connection.protocol}`}
                  />
                  <ListItemSecondaryAction>
                    <IconButton
                      edge="end"
                      onClick={() => handleRemoveBlockedDomain(connection.domain)}
                    >
                      <BlockIcon />
                    </IconButton>
                  </ListItemSecondaryAction>
                </ListItem>
              ))}
            </List>
          </Paper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default NetworkSecurity; 