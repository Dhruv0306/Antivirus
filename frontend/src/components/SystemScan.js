import React, { useState, useEffect } from 'react';
import {
  Box,
  Paper,
  Typography,
  Button,
  CircularProgress,
  Alert,
  LinearProgress,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Grid,
  AlertTitle,
} from '@mui/material';
import {
  Computer as ComputerIcon,
  Folder as FolderIcon,
  Description as FileIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Security as SecurityIcon,
  Stop as StopIcon,
  Error as ErrorIcon,
} from '@mui/icons-material';
import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api/antivirus';

function SystemScan() {
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [currentActivity, setCurrentActivity] = useState('');
  const [scanResults, setScanResults] = useState(null);
  const [error, setError] = useState(null);
  const [needsElevation, setNeedsElevation] = useState(false);

  // Add status polling when scan is running
  useEffect(() => {
    let interval;
    if (scanning) {
      interval = setInterval(checkScanStatus, 1000);
    }
    return () => {
      if (interval) {
        clearInterval(interval);
      }
    };
  }, [scanning]);

  const checkScanStatus = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scan/system/status`);
      if (!response.data.isRunning) {
        setScanning(false);
        // Refresh results when scan completes
        fetchLatestResults();
      }
    } catch (error) {
      console.error('Error checking scan status:', error);
    }
  };

  const fetchLatestResults = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/history`);
      setScanResults(response.data);
    } catch (error) {
      console.error('Error fetching scan results:', error);
      setError('Error fetching scan results: ' + error.message);
    }
  };

  const handleScan = async () => {
    try {
      setError(null);
      setScanning(true);
      setNeedsElevation(false);
      setScanResults(null);
      setProgress(0);
      
      const response = await axios.post(`${API_BASE_URL}/scan/system`);
      
      if (response.data && response.data.length === 1) {
        const result = response.data[0];
        if (result.threatType === 'WARNING' && 
            result.threatDetails.includes('Administrator privileges required')) {
          setNeedsElevation(true);
          setError('This application requires administrator privileges for a full system scan.');
          return;
        }
      }

      if (response.data) {
        setScanResults(response.data);
      }
    } catch (err) {
      console.error('Scan error:', err);
      let errorMessage = 'An error occurred during the system scan.';
      
      if (err.response) {
        if (err.response.status === 500) {
          errorMessage = 'Internal server error: The scan could not be completed. Please check server logs for details.';
        } else if (err.response.data && err.response.data.message) {
          errorMessage = err.response.data.message;
        }
      } else if (err.request) {
        errorMessage = 'Could not connect to the server. Please check if the server is running.';
      }
      
      setError(errorMessage);
    } finally {
      setScanning(false);
      setProgress(100);
    }
  };

  const handleStop = async () => {
    try {
      await axios.post(`${API_BASE_URL}/scan/system/stop`);
      setScanning(false);
      setError('Scan stopped by user');
      // Don't clear scan results if they exist
    } catch (err) {
      console.error('Error stopping scan:', err);
      setError('Failed to stop the scan. Please try again.');
    }
  };

  const calculateScanSummary = (results) => {
    if (!results || !Array.isArray(results)) return null;
    
    return {
      totalFiles: results.length,
      threats: results.filter(r => r.infected).length,
      errors: results.filter(r => r.threatType === 'ERROR').length,
      clean: results.filter(r => !r.infected && r.threatType !== 'ERROR').length
    };
  };

  return (
    <Box>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        System Scan
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Box display="flex" alignItems="center" gap={2}>
              <Button
                variant="contained"
                color="primary"
                onClick={handleScan}
                disabled={scanning}
                startIcon={<SecurityIcon />}
              >
                {scanning ? (
                  <>
                    <CircularProgress size={24} sx={{ mr: 1 }} />
                    Scanning...
                  </>
                ) : (
                  'Start System Scan'
                )}
              </Button>
              {scanning && (
                <Button
                  variant="contained"
                  color="secondary"
                  onClick={handleStop}
                  startIcon={<StopIcon />}
                >
                  Stop Scan
                </Button>
              )}
            </Box>

            {needsElevation && (
              <Alert 
                severity="warning" 
                sx={{ mt: 2 }}
                action={
                  <Button 
                    color="inherit" 
                    size="small"
                    onClick={() => {
                      // Open instructions in a new window
                      window.open('https://support.microsoft.com/en-us/windows/how-to-run-a-program-as-an-administrator-in-windows-10-11-a98c42f8-e5a3-4e1f-96b5-e32bed99a424', '_blank');
                    }}
                  >
                    Learn More
                  </Button>
                }
              >
                <AlertTitle>Administrator Privileges Required</AlertTitle>
                To perform a full system scan, please:
                <ol style={{ marginTop: '8px', marginBottom: '0' }}>
                  <li>Close this application</li>
                  <li>Right-click the application shortcut</li>
                  <li>Select "Run as administrator"</li>
                  <li>Restart the scan</li>
                </ol>
              </Alert>
            )}

            {error && !needsElevation && (
              <Alert severity="error" sx={{ mt: 2 }}>
                {error}
              </Alert>
            )}

            {scanning && (
              <Box sx={{ width: '100%', mt: 2 }}>
                <LinearProgress variant="determinate" value={progress} />
                <Typography variant="body2" color="text.secondary" align="center" sx={{ mt: 1 }}>
                  {progress}% Complete
                </Typography>
              </Box>
            )}
          </Paper>
        </Grid>

        {scanResults && Array.isArray(scanResults) && scanResults.length > 0 && (
          <>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Scan Summary
                </Typography>
                <List>
                  {(() => {
                    const summary = calculateScanSummary(scanResults);
                    return (
                      <>
                        <ListItem>
                          <ListItemIcon>
                            <FileIcon />
                          </ListItemIcon>
                          <ListItemText
                            primary="Total Files Processed"
                            secondary={summary.totalFiles}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemIcon>
                            <ErrorIcon color={summary.threats > 0 ? "error" : "success"} />
                          </ListItemIcon>
                          <ListItemText
                            primary="Threats Found"
                            secondary={summary.threats}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemIcon>
                            <WarningIcon color={summary.errors > 0 ? "warning" : "success"} />
                          </ListItemIcon>
                          <ListItemText
                            primary="Errors/Skipped"
                            secondary={summary.errors}
                          />
                        </ListItem>
                        <ListItem>
                          <ListItemIcon>
                            <CheckCircleIcon color="success" />
                          </ListItemIcon>
                          <ListItemText
                            primary="Clean Files"
                            secondary={summary.clean}
                          />
                        </ListItem>
                      </>
                    );
                  })()}
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Scan Details
                </Typography>
                <List sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {scanResults.map((result, index) => (
                    <ListItem key={index}>
                      <ListItemIcon>
                        {result.infected ? (
                          <ErrorIcon color="error" />
                        ) : result.threatType === 'ERROR' ? (
                          <WarningIcon color="warning" />
                        ) : (
                          <CheckCircleIcon color="success" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={result.filePath}
                        secondary={
                          result.infected 
                            ? `Threat: ${result.threatType} - ${result.threatDetails}`
                            : result.threatType === 'ERROR'
                              ? result.threatDetails
                              : 'Clean'
                        }
                      />
                    </ListItem>
                  ))}
                </List>
              </Paper>
            </Grid>
          </>
        )}
      </Grid>
    </Box>
  );
}

export default SystemScan; 