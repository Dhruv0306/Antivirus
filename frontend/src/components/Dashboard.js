import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
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
  Warning as WarningIcon,
  Memory as MemoryIcon,
  Storage as StorageIcon,
  Speed as SpeedIcon,
  Refresh as RefreshIcon,
  Info as InfoIcon,
} from '@mui/icons-material';
import axios from 'axios';

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
    <Box sx={{ width: '100%', maxWidth: 1200, margin: '0 auto', p: 1 }}>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
        <Typography variant="h4" sx={{ fontWeight: 600 }}>
          System Dashboard
        </Typography>
        <Tooltip title="Refresh Data">
          <IconButton 
            onClick={handleRefresh} 
            disabled={refreshing}
            sx={{ 
              transition: 'transform 0.2s',
              '&:hover': { transform: 'rotate(180deg)' }
            }}
          >
            <RefreshIcon className={refreshing ? 'loading-spinner' : ''} />
          </IconButton>
        </Tooltip>
      </Box>

      {error && (
        <Alert 
          severity="error" 
          sx={{ 
            mb: 3,
            '& .MuiAlert-icon': { fontSize: '2rem' }
          }}
        >
          {error}
        </Alert>
      )}

      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', minHeight: '400px' }}>
          <CircularProgress size={60} />
        </Box>
      ) : (
        <Grid container spacing={3}>
          {/* System Status Card */}
          <Grid item xs={12} md={6}>
            <Fade in timeout={500}>
              <Card className="card-hover glass-effect">
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <SecurityIcon sx={{ fontSize: 30, mr: 1, color: 'primary.main' }} />
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      System Status
                    </Typography>
                  </Box>
                  <List>
                    <ListItem>
                      <ListItemIcon>
                        <SecurityIcon color={systemStatus.systemProtected ? "success" : "error"} />
                      </ListItemIcon>
                      <ListItemText
                        primary="System Protection"
                        secondary={systemStatus.systemProtected ? "Protected" : "At Risk"}
                        primaryTypographyProps={{ fontWeight: 500 }}
                      />
                    </ListItem>
                    <ListItem>
                      <ListItemIcon>
                        <CheckCircleIcon color={systemStatus.realtimeProtection ? "success" : "error"} />
                      </ListItemIcon>
                      <ListItemText
                        primary="Realtime Protection"
                        secondary={systemStatus.realtimeProtection ? "Active" : "Disabled"}
                        primaryTypographyProps={{ fontWeight: 500 }}
                      />
                    </ListItem>
                  </List>
                </CardContent>
              </Card>
            </Fade>
          </Grid>

          {/* Storage Status Card */}
          <Grid item xs={12} md={6}>
            <Fade in timeout={500} style={{ transitionDelay: '100ms' }}>
              <Card className="card-hover glass-effect">
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <StorageIcon sx={{ fontSize: 30, mr: 1, color: 'primary.main' }} />
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
                      Storage Status
                    </Typography>
                  </Box>
                  <List>
                    {systemStatus.diskUsage && systemStatus.diskUsage.map((disk, index) => (
                      <ListItem key={index}>
                        <ListItemIcon>
                          <StorageIcon color="primary" />
                        </ListItemIcon>
                        <ListItemText
                          primary={disk.name}
                          secondary={`${formatBytes(disk.used)} / ${formatBytes(disk.total)}`}
                          primaryTypographyProps={{ fontWeight: 500 }}
                        />
                        <Box sx={{ width: '100px', ml: 2 }}>
                          <LinearProgress
                            variant="determinate"
                            value={(disk.used / disk.total) * 100}
                            color={(disk.used / disk.total) > 0.9 ? "error" : "primary"}
                            sx={{ height: 8, borderRadius: 4 }}
                          />
                        </Box>
                      </ListItem>
                    ))}
                  </List>
                </CardContent>
              </Card>
            </Fade>
          </Grid>

          {/* Scan History Card */}
          <Grid item xs={12}>
            <Fade in timeout={500} style={{ transitionDelay: '200ms' }}>
              <Card className="card-hover glass-effect">
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
                    <SpeedIcon sx={{ fontSize: 30, mr: 1, color: 'primary.main' }} />
                    <Typography variant="h6" sx={{ fontWeight: 600 }}>
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
                              <Tooltip title={scan.threatDetails || 'No threats found'}>
                                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                                  {scan.threatDetails || 'No threats found'}
                                  <InfoIcon sx={{ ml: 1, fontSize: 16, opacity: 0.7 }} />
                                </Box>
                              </Tooltip>
                            </TableCell>
                          </TableRow>
                        ))}
                        {scanHistory.length === 0 && (
                          <TableRow>
                            <TableCell colSpan={5} align="center">
                              No scan history available
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </CardContent>
              </Card>
            </Fade>
          </Grid>
        </Grid>
      )}
    </Box>
  );
}

export default Dashboard; 