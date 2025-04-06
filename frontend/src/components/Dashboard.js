import React, { useState, useEffect } from 'react';
import {
  Box,
  Typography,
  Grid,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  LinearProgress,
  Alert,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Card,
  CardContent,
  IconButton,
  Tooltip,
  Fade,
  CircularProgress,
} from '@mui/material';
import {
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Storage as StorageIcon,
  Speed as SpeedIcon,
  Refresh as RefreshIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import axios from 'axios';
import { styled } from '@mui/material/styles';

// Styled components using our theme
const StyledCard = styled(Card)(({ theme }) => ({
  backgroundColor: 'var(--background-paper)',
  borderRadius: 'var(--border-radius-medium)',
  border: '2px solid var(--border-main)',
  boxShadow: 'var(--shadow-medium)',
  transition: 'all 0.2s ease-in-out',
  '&:hover': {
    borderColor: 'var(--primary-main)',
    boxShadow: 'var(--shadow-large)',
    transform: 'translateY(-2px)'
  }
}));

const StyledAlert = styled(Alert)(({ theme }) => ({
  borderRadius: 'var(--border-radius-medium)',
  '&.MuiAlert-standardError': {
    backgroundColor: 'var(--error-main)',
    color: '#FFFFFF'
  },
  '&.MuiAlert-standardSuccess': {
    backgroundColor: 'var(--success-main)',
    color: '#FFFFFF'
  },
  '&.MuiAlert-standardWarning': {
    backgroundColor: 'var(--warning-main)',
    color: '#FFFFFF'
  }
}));

const StyledProgress = styled(LinearProgress)(({ theme }) => ({
  height: 8,
  borderRadius: 'var(--border-radius-small)',
  backgroundColor: 'var(--background-dark)',
  '& .MuiLinearProgress-bar': {
    backgroundColor: 'var(--primary-main)'
  }
}));

const StyledIconButton = styled(IconButton)(({ theme }) => ({
  color: 'var(--primary-main)',
  '&:hover': {
    backgroundColor: 'rgba(33, 150, 243, 0.1)'
  }
}));

function Dashboard() {
  const [systemStatus, setSystemStatus] = useState({
    diskUsage: [],
    realtimeProtection: true,
    systemProtected: true,
    suspiciousProcesses: [],
  });

  const [scanHistory, setScanHistory] = useState([]);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    fetchSystemStatus();
    fetchScanHistory();

    const statusInterval = setInterval(fetchSystemStatus, 5000);
    const historyInterval = setInterval(fetchScanHistory, 10000);

    return () => {
      clearInterval(statusInterval);
      clearInterval(historyInterval);
    };
  }, []);

  const fetchSystemStatus = async () => {
    try {
      const response = await axios.get('http://localhost:8080/api/antivirus/system/status');
      setSystemStatus(response.data);
      setError(null);
    } catch (err) {
      setError('Error fetching system status: ' + (err.response?.data || err.message));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const fetchScanHistory = async () => {
    try {
      const response = await axios.get('http://localhost:8080/api/antivirus/history');
      setScanHistory(response.data);
    } catch (err) {
      setError('Error fetching scan history: ' + (err.response?.data || err.message));
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    fetchSystemStatus();
    fetchScanHistory();
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return 'N/A';
    try {
      // Handle ISO date string format from backend
      return new Date(timestamp).toLocaleString();
    } catch (error) {
      console.error('Error formatting date:', error);
      return 'Invalid Date';
    }
  };

  const formatBytes = (bytes) => {
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 Byte';
    const i = parseInt(Math.floor(Math.log(bytes) / Math.log(1024)));
    return Math.round(bytes / Math.pow(1024, i), 2) + ' ' + sizes[i];
  };

  return (
    <Box sx={{ 
      width: '100%', 
      maxWidth: 1200, 
      margin: '0 auto', 
      p: 1,
      color: 'var(--text-primary)'
    }}>
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center', 
        mb: 2 
      }}>
        <Typography 
          variant="h4" 
          component="div"
          sx={{ 
            fontWeight: 600,
            color: 'var(--text-primary)'
          }}
        >
          System Dashboard
        </Typography>
        <StyledIconButton
          onClick={handleRefresh}
          disabled={refreshing}
          sx={{
            transition: 'transform 0.2s',
            '&:hover': { transform: 'rotate(180deg)' }
          }}
        >
          <RefreshIcon className={refreshing ? 'loading-spinner' : ''} />
        </StyledIconButton>
      </Box>

      {error && (
        <StyledAlert 
          severity="error" 
          sx={{ mb: 3 }}
        >
          {error}
        </StyledAlert>
      )}

      {loading ? (
        <Box sx={{ 
          display: 'flex', 
          justifyContent: 'center', 
          alignItems: 'center', 
          minHeight: '400px' 
        }}>
          <CircularProgress 
            size={60} 
            sx={{ color: 'var(--primary-main)' }}
          />
        </Box>
      ) : (
        <Grid container spacing={3}>
          {/* System Status Card */}
          <Grid item xs={12} md={6}>
            <Fade in timeout={500}>
              <StyledCard>
                <CardContent>
                  <Box sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    mb: 2 
                  }}>
                    <SecurityIcon sx={{ 
                      fontSize: 30, 
                      mr: 1, 
                      color: 'var(--primary-main)' 
                    }} />
                    <Typography 
                      variant="h6" 
                      component="div"
                      sx={{ 
                        fontWeight: 600,
                        color: 'var(--text-primary)'
                      }}
                    >
                      System Status
                    </Typography>
                  </Box>
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <SecurityIcon sx={{ 
                          color: systemStatus.systemProtected 
                            ? 'var(--success-main)' 
                            : 'var(--error-main)' 
                        }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Typography component="div" sx={{ 
                            fontWeight: 500,
                            color: 'var(--text-primary)'
                          }}>
                            System Protection
                          </Typography>
                        }
                        secondary={
                          <Typography component="div" sx={{ 
                            color: 'var(--text-secondary)'
                          }}>
                            {systemStatus.systemProtected ? "Protected" : "At Risk"}
                          </Typography>
                        }
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircleIcon sx={{ 
                          color: systemStatus.realtimeProtection 
                            ? 'var(--success-main)' 
                            : 'var(--error-main)' 
                        }} />
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Typography component="div" sx={{ 
                            fontWeight: 500,
                            color: 'var(--text-primary)'
                          }}>
                            Realtime Protection
                          </Typography>
                        }
                        secondary={
                          <Typography component="div" sx={{ 
                            color: 'var(--text-secondary)'
                          }}>
                            {systemStatus.realtimeProtection ? "Active" : "Disabled"}
                          </Typography>
                        }
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </StyledCard>
            </Fade>
          </Grid>

          {/* Storage Status Card */}
          <Grid item xs={12} md={6}>
            <Fade in timeout={500} style={{ transitionDelay: '100ms' }}>
              <StyledCard>
                <CardContent>
                  <Box sx={{ 
                    display: 'flex', 
                    alignItems: 'center', 
                    mb: 2 
                  }}>
                    <StorageIcon sx={{ 
                      fontSize: 30, 
                      mr: 1, 
                      color: 'var(--primary-main)' 
                    }} />
                    <Typography 
                      variant="h6" 
                      component="div"
                      sx={{ 
                        fontWeight: 600,
                        color: 'var(--text-primary)'
                      }}
                    >
                      Storage Status
                    </Typography>
                  </Box>
                  <List>
                    {systemStatus.diskUsage && systemStatus.diskUsage.map((disk, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          <StorageIcon sx={{ color: 'var(--primary-main)' }} />
                        </ListItemIcon>
                        <ListItemText
                          primary={
                            <Typography component="div" sx={{ 
                              fontWeight: 500,
                              color: 'var(--text-primary)'
                            }}>
                              {disk.drive}
                            </Typography>
                          }
                          secondary={
                            <Typography 
                              component="div" 
                              sx={{ 
                                color: 'var(--text-secondary)',
                                mt: 1 
                              }}
                            >
                              <Box 
                                component="span" 
                                sx={{ 
                                  display: 'flex', 
                                  justifyContent: 'space-between', 
                                  mb: 0.5,
                                  color: 'var(--text-secondary)'
                                }}
                              >
                                <span>{formatBytes(disk.used)} used of {formatBytes(disk.total)}</span>
                                <span>{Math.round((disk.used / disk.total) * 100)}%</span>
                              </Box>
                              <StyledProgress
                                variant="determinate"
                                value={(disk.used / disk.total) * 100}
                              />
                            </Typography>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </StyledCard>
            </Fade>
          </Grid>

          {/* Scan History Card */}
          <Grid item xs={12}>
            <Fade in timeout={500} style={{ transitionDelay: '200ms' }}>
              <StyledCard>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <SpeedIcon sx={{ fontSize: 30, mr: 1, color: 'primary.main' }} />
                    <Typography 
                      variant="h6" 
                      component="div"
                      sx={{ 
                        fontWeight: 600,
                        color: 'var(--text-primary)'
                      }}
                    >
                      Recent Scan History
                    </Typography>
                  </Box>
                  <TableContainer>
                    <Table>
                      <TableHead>
                        <TableRow>
                          <TableCell sx={{ fontWeight: 600 }}>Time</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>File Path</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Status</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Threat Type</TableCell>
                          <TableCell sx={{ fontWeight: 600 }}>Details</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {scanHistory.map((scan, index) => (
                          <TableRow 
                            key={index}
                            sx={{ 
                              '&:hover': { 
                                backgroundColor: 'rgba(255, 255, 255, 0.05)',
                                transition: 'background-color 0.2s'
                              }
                            }}
                          >
                            <TableCell>{formatDate(scan.scanDateTime)}</TableCell>
                            <TableCell sx={{ maxWidth: 200, wordBreak: 'break-all' }}>
                              {scan.filePath}
                            </TableCell>
                            <TableCell>
                              <Alert
                                severity={scan.infected ? 'error' : 'success'}
                                sx={{ 
                                  display: 'inline-flex',
                                  py: 0,
                                  px: 1,
                                  '& .MuiAlert-message': { py: 0.5 }
                                }}
                              >
                                {scan.infected ? 'Infected' : 'Clean'}
                              </Alert>
                            </TableCell>
                            <TableCell>{scan.threatType || 'N/A'}</TableCell>
                            <TableCell>
                              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                <Typography component="div" sx={{ display: 'flex', alignItems: 'center' }}>
                                  {scan.threatDetails || 'No threats found'}
                                  <InfoIcon sx={{ ml: 1, fontSize: 16, opacity: 0.7 }} />
                                </Typography>
                              </Box>
                            </TableCell>
                          </TableRow>
                        ))}
                        {scanHistory.length === 0 && (
                          <TableRow>
                            <TableCell colSpan={5}>
                              <Typography component="div" align="center">
                                No scan history available
                              </Typography>
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </CardContent>
              </StyledCard>
            </Fade>
          </Grid>
        </Grid>
      )}
    </Box>
  );
}

export default Dashboard; 