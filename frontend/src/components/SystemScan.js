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
import { antivirusApi } from '../api/client';
import { styled } from '@mui/material/styles';
import { log, logError } from '../utils/logger';
import { toUserMessage } from '../utils/errors';
import { getVerdictStatus, getVerdictColorVar, isSuspicious, isMalicious } from '../utils/verdict';

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

function getDisplayName(result) {
  return result?.fileName || result?.filePath || 'Unknown file';
}

function SystemScan() {
  const [scanning, setScanning] = useState(false);
  // Keeps the UI in a "stopping..." state while we wait for the backend to
  // actually flip isRunning to false. That prevents us from dropping polling
  // too early and missing the final scan results.
  const [stopping, setStopping] = useState(false);
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
      const response = await antivirusApi.get('/scan/system/status');
      const isRunning = Boolean(response.data?.isRunning);
      const filesScanned = response.data?.filesScanned || 0;

      if (isRunning) {
        // While the scan is still active, keep the progress text updated.
        // If the user pressed Stop, show a stopping message instead of the
        // normal scanning message.
        setCurrentActivity(
          stopping ? 'Stopping scan...' : (filesScanned ? `Scanned ${filesScanned} files...` : 'Scanning system...')
        );
        return;
      }

      const wasStopping = stopping;
      setCurrentActivity(wasStopping ? 'Scan stopped. Loading results...' : 'Scan completed. Loading results...');
      setScanning(false);
      setStopping(false);
      // This endpoint returns only the current scan session, so old scans do
      // not bleed into the results view after a stop or completion.
      await fetchLatestResults();
      if (wasStopping) {
        setError('Scan stopped by user');
      }
    } catch (error) {
      logError('Error checking scan status:', error);
    }
  };

  const fetchLatestResults = async () => {
    try {
      // Pull only the live system-scan session results instead of global
      // history, which could include older scans and confuse the UI.
      const response = await antivirusApi.get('/scan/system/results');
      setScanResults(response.data || []);
    } catch (error) {
      logError('Error fetching scan results:', error);
      setError(toUserMessage(error));
    }
  };

  const handleScan = async () => {
    try {
      setError(null);
      setScanning(true);
      setStopping(false);
      setNeedsElevation(false);
      setScanResults(null);
      setCurrentActivity('Starting scan...');

      // POST /scan/system now starts the scan on a background thread and
      // returns immediately (202 Accepted) rather than blocking for the
      // full scan duration. checkScanStatus() polling (below) picks up
      // progress and, once isRunning flips false, the completed results
      // via fetchLatestResults().
      await antivirusApi.post('/scan/system');
      // Deliberately no setScanning(false) here: the POST now returns as
      // soon as the scan starts, not when it finishes. scanning stays true
      // until checkScanStatus() (polling below) sees isRunning: false.
    } catch (err) {
      logError('Scan error:', err);
      // N-07 Fix: ALWAYS use toUserMessage — never touch err.response.data.message
      setError(toUserMessage(err));
      setScanning(false);
    }
  };

  const handleStop = async () => {
    try {
      setStopping(true);
      setCurrentActivity('Stopping scan...');
      // The stop response only confirms that the request was accepted; the
      // scan itself shuts down asynchronously, so we still poll /status until
      // it reports isRunning=false before reading the results.
      const response = await antivirusApi.post('/scan/system/stop');
      if (response.status !== 200 || response.data?.stopRequested !== true) {
        throw new Error('Stop request was not accepted');
      }
      // Keep polling active until the backend actually reports that the scan
      // is no longer running, then we can safely load the final results.
      await checkScanStatus(); // Immediately check status to update UI
      // Don't clear scan results if they exist
    } catch (err) {
      logError('Error stopping scan:', err);
      setStopping(false);
      setError('Failed to stop the scan. Please try again.');
    }
  };

  const calculateScanSummary = (results) => {
    if (!results || !Array.isArray(results)) return null;

    return {
      totalFiles: results.length,
      threats: results.filter(isMalicious).length,
      suspicious: results.filter(isSuspicious).length,
      errors: results.filter(r => r.threatType === 'ERROR').length,
      clean: results.filter(r => getVerdictStatus(r) === 'clean').length
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
                  startIcon={stopping ? <CircularProgress size={20} color="inherit" /> : <StopIcon />}
                  onClick={handleStop}
                  color="error"
                  disabled={stopping}
                >
                  {stopping ? 'Stopping...' : 'Stop Scan'}
                </StyledButton>
              )}
            </Box>

            {scanning && (
              <Box mb={3}>
                <Typography variant="body2" color="textSecondary" gutterBottom>
                  {currentActivity || 'Scanning system...'}
                </Typography>
                <StyledProgress variant="indeterminate" />
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
                    <Grid item xs={6} sm={2.4}>
                      <StyledPaper>
                        <StatusIcon status="success">
                          <CheckCircleIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).clean}</Typography>
                        <Typography variant="body2" color="textSecondary">Clean Files</Typography>
                      </StyledPaper>
                    </Grid>
                    <Grid item xs={6} sm={2.4}>
                      <StyledPaper>
                        <StatusIcon status="error">
                          <ErrorIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).threats}</Typography>
                        <Typography variant="body2" color="textSecondary">Malicious Files</Typography>
                      </StyledPaper>
                    </Grid>
                    <Grid item xs={6} sm={2.4}>
                      <StyledPaper>
                        <StatusIcon status="warning">
                          <WarningIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).suspicious}</Typography>
                        <Typography variant="body2" color="textSecondary">Suspicious Files</Typography>
                      </StyledPaper>
                    </Grid>
                    <Grid item xs={6} sm={2.4}>
                      <StyledPaper>
                        <StatusIcon status="warning">
                          <WarningIcon />
                        </StatusIcon>
                        <Typography variant="h6">{calculateScanSummary(scanResults).errors}</Typography>
                        <Typography variant="body2" color="textSecondary">Scan Errors</Typography>
                      </StyledPaper>
                    </Grid>
                    <Grid item xs={6} sm={2.4}>
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
                          {isMalicious(result) ? (
                            <ErrorIcon color="error" />
                          ) : isSuspicious(result) ? (
                            <WarningIcon color="warning" />
                          ) : result.threatType === 'ERROR' ? (
                            <WarningIcon color="warning" />
                          ) : (
                            <CheckCircleIcon color="success" />
                          )}
                        </ListItemIcon>
                        <ListItemText
                          primary={getDisplayName(result)}
                          secondary={result.threatDetails || 'No threats detected'}
                          sx={{
                            '& .MuiListItemText-primary': {
                              color: 'var(--text-primary)',
                              fontWeight: 500
                            },
                            '& .MuiListItemText-secondary': {
                              color: getVerdictColorVar(result)
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
