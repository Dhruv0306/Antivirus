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
import { styled } from '@mui/material/styles';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:8080/api/antivirus';

// Styled components with light theme
const StyledPaper = styled(Paper)(({ theme }) => ({
  backgroundColor: 'var(--background-paper)',
  color: 'var(--text-primary)',
  border: '1px solid var(--border-main)',
  borderRadius: 'var(--border-radius-medium)',
  padding: 'var(--spacing-lg)',
  transition: 'all 0.2s ease-in-out',
  '&:hover': {
    borderColor: 'var(--primary-main)',
    boxShadow: 'var(--shadow-medium)'
  }
}));

const StyledButton = styled(Button)(({ theme, variant }) => ({
  borderRadius: 'var(--border-radius-medium)',
  padding: '8px 24px',
  fontWeight: 600,
  textTransform: 'none',
  ...(variant === 'contained' ? {
    backgroundColor: 'var(--button-primary)',
    color: 'var(--button-text)',
    '&:hover': {
      backgroundColor: 'var(--primary-dark)',
      boxShadow: 'var(--shadow-small)'
    }
  } : {
    backgroundColor: 'var(--primary-transparent)',
    color: 'var(--primary-main)',
    '&:hover': {
      backgroundColor: 'var(--primary-transparent-hover)'
    }
  })
}));

const StyledListItem = styled(ListItem)(({ theme }) => ({
  borderRadius: 'var(--border-radius-medium)',
  padding: 'var(--spacing-md)',
  marginBottom: 'var(--spacing-sm)',
  backgroundColor: 'var(--background-paper)',
  border: '1px solid var(--border-main)',
  '&:hover': {
    backgroundColor: 'var(--primary-transparent)',
    borderColor: 'var(--primary-main)'
  }
}));

const StyledProgress = styled(LinearProgress)(({ theme }) => ({
  height: 8,
  borderRadius: 'var(--border-radius-full)',
  backgroundColor: 'var(--background-dark)',
  '& .MuiLinearProgress-bar': {
    backgroundColor: 'var(--primary-main)',
    borderRadius: 'var(--border-radius-full)'
  }
}));

const StatusIcon = styled(Box)(({ status }) => ({
  display: 'inline-flex',
  alignItems: 'center',
  justifyContent: 'center',
  width: 40,
  height: 40,
  borderRadius: 'var(--border-radius-full)',
  marginRight: 'var(--spacing-md)',
  ...(status === 'success' && {
    backgroundColor: 'var(--success-transparent)',
    color: 'var(--success-main)'
  }),
  ...(status === 'warning' && {
    backgroundColor: 'var(--warning-transparent)',
    color: 'var(--warning-main)'
  }),
  ...(status === 'error' && {
    backgroundColor: 'var(--error-transparent)',
    color: 'var(--error-main)'
  })
}));

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
      <Typography 
        variant="h4" 
        gutterBottom 
        sx={{ 
          mb: 4,
          color: 'var(--text-primary)',
          fontWeight: 600 
        }}
      >
        System Scan
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <StyledPaper>
            <Box display="flex" alignItems="center" gap={2} mb={3}>
              <StyledButton
                variant="contained"
                startIcon={scanning ? <CircularProgress size={20} color="inherit" /> : <SecurityIcon />}
                onClick={handleScan}
                disabled={scanning}
              >
                {scanning ? 'Scanning...' : 'Start System Scan'}
              </StyledButton>
              
              {scanning && (
                <StyledButton
                  variant="outlined"
                  startIcon={<StopIcon />}
                  onClick={handleStop}
                  color="error"
                >
                  Stop Scan
                </StyledButton>
              )}
            </Box>

            {scanning && (
              <Box mb={3}>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  {currentActivity || 'Scanning system...'}
                </Typography>
                <StyledProgress variant="determinate" value={progress} />
              </Box>
            )}

            {error && (
              <Alert 
                severity={needsElevation ? "warning" : "error"}
                sx={{ 
                  mb: 3,
                  borderRadius: 'var(--border-radius-medium)',
                  backgroundColor: needsElevation ? 'var(--warning-transparent)' : 'var(--error-transparent)',
                  color: needsElevation ? 'var(--warning-main)' : 'var(--error-main)',
                  border: '1px solid',
                  borderColor: needsElevation ? 'var(--warning-main)' : 'var(--error-main)'
                }}
              >
                <AlertTitle>{needsElevation ? "Administrator Privileges Required" : "Error"}</AlertTitle>
                {error}
              </Alert>
            )}

            {scanResults && (
              <Box>
                <Typography variant="h6" gutterBottom sx={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                  Scan Results
                </Typography>
                
                {calculateScanSummary(scanResults) && (
                  <Grid container spacing={2} sx={{ mb: 3 }}>
                    <Grid item xs={3}>
                      <StyledPaper>
                        <StatusIcon status="success">
                          <CheckCircleIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).clean}</Typography>
                        <Typography variant="body2" color="textSecondary">Clean Files</Typography>
                      </StyledPaper>
                    </Grid>
                    <Grid item xs={3}>
                      <StyledPaper>
                        <StatusIcon status="error">
                          <ErrorIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).threats}</Typography>
                        <Typography variant="body2" color="textSecondary">Threats Found</Typography>
                      </StyledPaper>
                    </Grid>
                    <Grid item xs={3}>
                      <StyledPaper>
                        <StatusIcon status="warning">
                          <WarningIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).errors}</Typography>
                        <Typography variant="body2" color="textSecondary">Scan Errors</Typography>
                      </StyledPaper>
                    </Grid>
                    <Grid item xs={3}>
                      <StyledPaper>
                        <StatusIcon>
                          <FileIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).totalFiles}</Typography>
                        <Typography variant="body2" color="textSecondary">Total Files</Typography>
                      </StyledPaper>
                    </Grid>
                  </Grid>
                )}

                <List>
                  {scanResults.map((result, index) => (
                    <React.Fragment key={index}>
                      <StyledListItem>
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
                          secondary={result.threatDetails || 'No threats detected'}
                          sx={{
                            '& .MuiListItemText-primary': {
                              color: 'var(--text-primary)',
                              fontWeight: 500
                            },
                            '& .MuiListItemText-secondary': {
                              color: result.infected ? 'var(--error-main)' : 
                                     result.threatType === 'ERROR' ? 'var(--warning-main)' : 
                                     'var(--text-secondary)'
                            }
                          }}
                        />
                      </StyledListItem>
                    </React.Fragment>
                  ))}
                </List>
              </Box>
            )}
          </StyledPaper>
        </Grid>
      </Grid>
    </Box>
  );
}

export default SystemScan; 