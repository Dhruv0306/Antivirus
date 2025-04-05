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
import { styled } from '@mui/material/styles';

// Styled components
const StyledPaper = styled(Paper)(({ theme }) => ({
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

const StyledListItem = styled(ListItem)(({ theme }) => ({
  borderRadius: 'var(--border-radius-small)',
  '&:hover': {
    backgroundColor: 'var(--background-dark)'
  }
}));

const StyledSwitch = styled(Switch)(({ theme }) => ({
  '& .MuiSwitch-switchBase.Mui-checked': {
    color: 'var(--success-main)',
    '& + .MuiSwitch-track': {
      backgroundColor: 'var(--success-light)'
    }
  }
}));

const StyledChip = styled(Chip)(({ theme }) => ({
  backgroundColor: 'var(--error-main)',
  color: '#FFFFFF',
  border: '1px solid var(--error-dark)',
  '&:hover': {
    backgroundColor: 'var(--error-dark)'
  },
  '& .MuiChip-deleteIcon': {
    color: '#FFFFFF',
    '&:hover': {
      color: 'rgba(255, 255, 255, 0.7)'
    }
  }
}));

const StyledIconButton = styled(IconButton)(({ theme }) => ({
  color: 'var(--warning-main)',
  '&:hover': {
    backgroundColor: 'var(--warning-transparent)',
    color: 'var(--warning-dark)'
  }
}));

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
      <Typography 
        variant="h4" 
        gutterBottom 
        sx={{ 
          mb: 4,
          color: 'var(--text-primary)',
          fontWeight: 600 
        }}
      >
        Network Security
      </Typography>

      {error && (
        <Alert 
          severity="error" 
          sx={{ 
            mb: 3,
            backgroundColor: 'var(--error-main)',
            color: '#FFFFFF',
            '& .MuiAlert-icon': {
              color: '#FFFFFF'
            }
          }}
        >
          {error}
        </Alert>
      )}

      <Grid container spacing={3}>
        <Grid item xs={12} md={6}>
          <StyledPaper sx={{ p: 3 }}>
            <Typography 
              variant="h6" 
              gutterBottom
              sx={{ 
                color: 'var(--text-primary)',
                fontWeight: 600 
              }}
            >
              Security Controls
            </Typography>
            <List>
              <StyledListItem>
                <ListItemIcon>
                  <SecurityIcon sx={{ 
                    color: firewallEnabled 
                      ? 'var(--primary-main)' 
                      : 'var(--text-disabled)' 
                  }} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography sx={{ color: 'var(--text-primary)' }}>
                      Firewall
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {firewallEnabled ? "Active protection enabled" : "Protection disabled"}
                    </Typography>
                  }
                />
                <ListItemSecondaryAction>
                  <FormControlLabel
                    control={
                      <StyledSwitch
                        checked={firewallEnabled}
                        onChange={handleFirewallToggle}
                      />
                    }
                    label=""
                  />
                </ListItemSecondaryAction>
              </StyledListItem>
              <StyledListItem>
                <ListItemIcon>
                  <WebIcon sx={{ 
                    color: webProtectionEnabled 
                      ? 'var(--primary-main)' 
                      : 'var(--text-disabled)' 
                  }} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography sx={{ color: 'var(--text-primary)' }}>
                      Web Protection
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {webProtectionEnabled ? "Browsing protection active" : "Protection disabled"}
                    </Typography>
                  }
                />
                <ListItemSecondaryAction>
                  <FormControlLabel
                    control={
                      <StyledSwitch
                        checked={webProtectionEnabled}
                        onChange={handleWebProtectionToggle}
                      />
                    }
                    label=""
                  />
                </ListItemSecondaryAction>
              </StyledListItem>
            </List>
          </StyledPaper>
        </Grid>

        <Grid item xs={12} md={6}>
          <StyledPaper sx={{ p: 3 }}>
            <Typography 
              variant="h6" 
              gutterBottom
              sx={{ 
                color: 'var(--text-primary)',
                fontWeight: 600 
              }}
            >
              Network Status
            </Typography>
            <List>
              <StyledListItem>
                <ListItemIcon>
                  <WarningIcon sx={{ 
                    color: networkStatus.threats > 0 
                      ? 'var(--error-main)' 
                      : 'var(--success-main)' 
                  }} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography sx={{ color: 'var(--text-primary)' }}>
                      Active Threats
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.threats}
                    </Typography>
                  }
                />
              </StyledListItem>
              <StyledListItem>
                <ListItemIcon>
                  <WebIcon sx={{ color: 'var(--primary-main)' }} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography sx={{ color: 'var(--text-primary)' }}>
                      Active Connections
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.connections}
                    </Typography>
                  }
                />
              </StyledListItem>
              <StyledListItem>
                <ListItemIcon>
                  <BlockIcon sx={{ color: 'var(--warning-main)' }} />
                </ListItemIcon>
                <ListItemText
                  primary={
                    <Typography sx={{ color: 'var(--text-primary)' }}>
                      Blocked Attempts
                    </Typography>
                  }
                  secondary={
                    <Typography sx={{ color: 'var(--text-secondary)' }}>
                      {networkStatus.blockedAttempts}
                    </Typography>
                  }
                />
              </StyledListItem>
            </List>
          </StyledPaper>
        </Grid>

        <Grid item xs={12}>
          <StyledPaper sx={{ p: 3 }}>
            <Typography 
              variant="h6" 
              gutterBottom
              sx={{ 
                color: 'var(--text-primary)',
                fontWeight: 600 
              }}
            >
              Blocked Domains
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {blockedDomains && blockedDomains.map((domain) => (
                <StyledChip
                  key={domain}
                  label={domain}
                  onDelete={() => handleRemoveBlockedDomain(domain)}
                  variant="outlined"
                />
              ))}
            </Box>
          </StyledPaper>
        </Grid>

        <Grid item xs={12}>
          <StyledPaper sx={{ p: 3 }}>
            <Typography 
              variant="h6" 
              gutterBottom
              sx={{ 
                color: 'var(--text-primary)',
                fontWeight: 600 
              }}
            >
              Recent Connections
            </Typography>
            <List>
              {recentConnections.map((connection, index) => (
                <StyledListItem key={index}>
                  <ListItemIcon>
                    {connection.secure ? (
                      <CheckCircleIcon sx={{ color: 'var(--success-main)' }} />
                    ) : (
                      <WarningIcon sx={{ color: 'var(--warning-main)' }} />
                    )}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Typography sx={{ color: 'var(--text-primary)' }}>
                        {connection.domain}
                      </Typography>
                    }
                    secondary={
                      <Typography sx={{ color: 'var(--text-secondary)' }}>
                        {connection.timestamp} - {connection.protocol}
                      </Typography>
                    }
                  />
                  <ListItemSecondaryAction>
                    <StyledIconButton
                      edge="end"
                      onClick={() => handleRemoveBlockedDomain(connection.domain)}
                    >
                      <BlockIcon />
                    </StyledIconButton>
                  </ListItemSecondaryAction>
                </StyledListItem>
              ))}
            </List>
          </StyledPaper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default NetworkSecurity; 