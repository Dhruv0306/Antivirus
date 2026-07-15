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
  FormControlLabel,
  Switch,
  Grid
} from '@mui/material';
import {
  Folder as FolderIcon,
  Security as SecurityIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Warning as WarningIcon
} from '@mui/icons-material';
import { antivirusApi } from '../api/client';
import { styled } from '@mui/material/styles';
import { log, logError } from '../utils/logger';
import { toUserMessage } from '../utils/errors'; // Import the error normalizer
import { getVerdictStatus, getVerdictLabel, getVerdictColorVar, isSuspicious } from '../utils/verdict';

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

const StyledButton = styled(Button)(({ theme }) => ({
  backgroundColor: 'var(--button-primary)',
  color: 'var(--button-text)',
  '&:hover': {
    backgroundColor: 'var(--primary-dark)',
    boxShadow: 'var(--shadow-medium)'
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

const StyledProgress = styled(LinearProgress)(({ theme }) => ({
  height: 8,
  borderRadius: 'var(--border-radius-small)',
  backgroundColor: 'var(--background-dark)',
  '& .MuiLinearProgress-bar': {
    backgroundColor: 'var(--primary-main)'
  }
}));

function getDisplayName(result) {
  return result?.fileName || result?.filePath || 'Unknown file';
}

function DirectoryScan() {
  const [selectedDirectory, setSelectedDirectory] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [recursive, setRecursive] = useState(true);
  // Two distinct phases, each with a real (not fake) percentage:
  // uploadProgress comes from axios during the file upload itself;
  // scanProgress is computed from processedFiles/totalFiles once the
  // upload finishes and the background scan job starts.
  const [uploadProgress, setUploadProgress] = useState(0);
  const [scanProgress, setScanProgress] = useState(0);
  const [phase, setPhase] = useState('idle'); // 'idle' | 'uploading' | 'scanning'
  const [jobId, setJobId] = useState(null);
  const [selectedFiles, setSelectedFiles] = useState(null);

  const handleDirectorySelect = () => {
    try {
      const input = document.createElement('input');
      input.type = 'file';
      input.setAttribute('webkitdirectory', '');
      input.setAttribute('directory', '');

      input.onchange = (e) => {
        if (e.target.files && e.target.files.length > 0) {
          const files = Array.from(e.target.files);
          const firstFile = files[0];
          const directoryName = firstFile.webkitRelativePath.split('/')[0];

          // Store both the directory name and the FileList for scanning
          setSelectedDirectory(directoryName);
          setSelectedFiles(files);
          setError(null);
          setScanResult(null);
          setUploadProgress(0);
          setScanProgress(0);
          setPhase('idle');
        }
      };

      input.click();
    } catch (err) {
      logError('Directory selection error:', err);
      setError(toUserMessage(err));
    }
  };

  // Polls /scan/directory/status/{jobId} once a scan job has started.
  // Mirrors the same pattern used for system scan: the POST that starts
  // the job returns as soon as upload+job-creation finish, not when
  // scanning finishes, so this effect is what actually detects completion
  // and picks up the final results.
  useEffect(() => {
    if (!jobId) {
      return undefined;
    }

    let cancelled = false;

    const poll = async () => {
      try {
        const response = await antivirusApi.get(`/scan/directory/status/${jobId}`);
        if (cancelled) return;

        const data = response.data;
        const total = data.totalFiles || 0;
        const processed = data.processedFiles || 0;
        setScanProgress(total > 0 ? Math.round((processed / total) * 100) : 0);

        if (!data.isRunning) {
          setScanning(false);
          setPhase('idle');
          setJobId(null);

          if (data.failed) {
            setError('Directory scan failed. Please try again.');
            return;
          }

          const results = data.results || [];
          setScanResult({
            totalFiles: total,
            infectedFiles: data.infectedFiles || 0,
            suspiciousFiles: typeof data.suspiciousFiles === 'number'
              ? data.suspiciousFiles
              : results.filter(isSuspicious).length,
            skippedFiles: data.skippedFiles || 0,
            results
          });
        }
      } catch (err) {
        if (!cancelled) {
          logError('Error checking directory scan status:', err);
        }
      }
    };

    poll();
    const interval = setInterval(poll, 1000);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [jobId]);

  const handleScan = async () => {
    if (!selectedDirectory || !selectedFiles) {
      setError('Please select a directory first');
      return;
    }

    setScanning(true);
    setError(null);
    setScanResult(null);
    setUploadProgress(0);
    setScanProgress(0);
    setPhase('uploading');

    try {
      // Create FormData to send files
      const formData = new FormData();
      formData.append('directoryName', selectedDirectory);
      formData.append('recursive', recursive);

      // Append all files while maintaining their relative paths
      for (const file of selectedFiles) {
        formData.append('files', file, file.webkitRelativePath);
      }

      // The upload itself is still synchronous (the browser has to send
      // the bytes), but this now returns as soon as the upload finishes
      // and the background scan job starts, not once scanning completes.
      // The polling effect above picks up progress and final results.
      const response = await antivirusApi.post('/scan/directory', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setUploadProgress(percentCompleted);
        }
      });

      if (response.data && response.data.jobId) {
        setPhase('scanning');
        setJobId(response.data.jobId);
        // Deliberately no setScanning(false) here: scanning stays true
        // until the polling effect sees the job report isRunning: false.
      } else {
        throw new Error('No scan job was started');
      }
    } catch (err) {
      logError('Scan error:', err);
      // F-01: Use safe, normalized user-facing message instead of raw server error
      setError(toUserMessage(err));
      setScanning(false);
      setPhase('idle');
    }
  };

  return (
    <Box sx={{ width: '100%', maxWidth: 1200, margin: '0 auto', p: { xs: 2, sm: 3 } }}>
      <Typography
        variant="h4"
        gutterBottom
        sx={{
          mb: 4,
          color: 'var(--text-primary)',
          fontWeight: 600
        }}
      >
        Directory Scan
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <StyledPaper sx={{ p: { xs: 2, sm: 3 } }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
                <StyledButton
                  variant="contained"
                  startIcon={<FolderIcon />}
                  onClick={handleDirectorySelect}
                  disabled={scanning}
                >
                  Select Directory
                </StyledButton>
                <StyledButton
                  variant="contained"
                  startIcon={<SecurityIcon />}
                  onClick={handleScan}
                  disabled={!selectedDirectory || scanning}
                >
                  {scanning ? (
                    <>
                      <CircularProgress
                        size={24}
                        sx={{
                          mr: 1,
                          color: 'var(--primary-light)'
                        }}
                      />
                      Scanning...
                    </>
                  ) : (
                    'Start Scan'
                  )}
                </StyledButton>
                <FormControlLabel
                  control={
                    <StyledSwitch
                      checked={recursive}
                      onChange={(e) => setRecursive(e.target.checked)}
                      disabled={scanning}
                    />
                  }
                  label={
                    <Typography component="div" sx={{ color: 'var(--text-primary)' }}>
                      Include Subdirectories
                    </Typography>
                  }
                />
              </Box>

              {selectedDirectory && (
                <Typography
                  variant="body2"
                  sx={{ color: 'var(--text-secondary)' }}
                >
                  Selected Directory: {selectedDirectory}
                </Typography>
              )}

              {scanning && (
                <Box sx={{ width: '100%', mt: 2 }}>
                  <StyledProgress
                    variant="determinate"
                    value={phase === 'uploading' ? uploadProgress : scanProgress}
                  />
                  <Typography
                    variant="body2"
                    sx={{
                      mt: 1,
                      color: 'var(--text-secondary)',
                      textAlign: 'center'
                    }}
                  >
                    {phase === 'uploading'
                      ? `Uploading: ${Math.round(uploadProgress)}% Complete`
                      : `Scanning: ${Math.round(scanProgress)}% Complete`}
                  </Typography>
                </Box>
              )}

              {error && (
                <Alert
                  severity="error"
                  sx={{
                    mt: 2,
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
            </Box>
          </StyledPaper>
        </Grid>

        {scanResult && (
          <>
            <Grid item xs={12} md={6}>
              <StyledPaper sx={{ p: { xs: 2, sm: 3 } }}>
                <Typography
                  variant="h6"
                  gutterBottom
                  sx={{
                    color: 'var(--text-primary)',
                    fontWeight: 600
                  }}
                >
                  Scan Summary
                </Typography>
                <List>
                  <StyledListItem>
                    <ListItemIcon>
                      <FolderIcon sx={{ color: 'var(--primary-main)' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography component="div" sx={{ color: 'var(--text-primary)' }}>
                          Total Files Scanned
                        </Typography>
                      }
                      secondary={
                        <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                          {scanResult.totalFiles || 0}
                        </Typography>
                      }
                    />
                  </StyledListItem>
                  <StyledListItem>
                    <ListItemIcon>
                      <CheckCircleIcon sx={{ color: 'var(--success-main)' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography component="div" sx={{ color: 'var(--text-primary)' }}>
                          Clean Files
                        </Typography>
                      }
                      secondary={
                        <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                          {Math.max(
                            0,
                            (scanResult.totalFiles || 0) -
                            (scanResult.infectedFiles || 0) -
                            (scanResult.suspiciousFiles || 0) -
                            (scanResult.skippedFiles || 0)
                          )}
                        </Typography>
                      }
                    />
                  </StyledListItem>
                  <StyledListItem>
                    <ListItemIcon>
                      <ErrorIcon sx={{ color: 'var(--error-main)' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography component="div" sx={{ color: 'var(--text-primary)' }}>
                          Malicious Files
                        </Typography>
                      }
                      secondary={
                        <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                          {scanResult.infectedFiles || 0}
                        </Typography>
                      }
                    />
                  </StyledListItem>
                  <StyledListItem>
                    <ListItemIcon>
                      <WarningIcon sx={{ color: 'var(--warning-main)' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography component="div" sx={{ color: 'var(--text-primary)' }}>
                          Suspicious Files
                        </Typography>
                      }
                      secondary={
                        <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                          {scanResult.suspiciousFiles || 0}
                        </Typography>
                      }
                    />
                  </StyledListItem>
                  <StyledListItem>
                    <ListItemIcon>
                      <WarningIcon sx={{ color: 'var(--warning-main)' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography component="div" sx={{ color: 'var(--text-primary)' }}>
                          Skipped/Error Files
                        </Typography>
                      }
                      secondary={
                        <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                          {scanResult.skippedFiles || 0}
                        </Typography>
                      }
                    />
                  </StyledListItem>
                  <Divider sx={{ borderColor: 'var(--border-main)' }} />
                  <StyledListItem>
                    <ListItemIcon>
                      <CheckCircleIcon
                        sx={{
                          color: scanResult.infectedFiles > 0
                            ? 'var(--error-main)'
                            : scanResult.suspiciousFiles > 0
                              ? 'var(--warning-main)'
                              : 'var(--success-main)'
                        }}
                      />
                    </ListItemIcon>
                    <ListItemText
                      primary={
                        <Typography component="div" sx={{ color: 'var(--text-primary)' }}>
                          Directory Status
                        </Typography>
                      }
                      secondary={
                        <Typography component="div" sx={{ color: 'var(--text-secondary)' }}>
                          {scanResult.infectedFiles > 0
                            ? `Threats Found (${scanResult.infectedFiles} malicious files)`
                            : scanResult.suspiciousFiles > 0
                              ? `Review Recommended (${scanResult.suspiciousFiles} suspicious files)`
                              : "Clean"}
                        </Typography>
                      }
                    />
                  </StyledListItem>
                </List>
              </StyledPaper>
            </Grid>

            <Grid item xs={12} md={6}>
              <StyledPaper sx={{ p: { xs: 2, sm: 3 } }}>
                <Typography
                  variant="h6"
                  gutterBottom
                  sx={{
                    color: 'var(--text-primary)',
                    fontWeight: 600
                  }}
                >
                  Scan Details
                </Typography>
                <Typography
                  variant="body2"
                  component="div"
                  sx={{
                    mb: 2,
                    color: 'var(--text-secondary)'
                  }}
                >
                  {scanResult.infectedFiles > 0 || scanResult.suspiciousFiles > 0
                    ? "Showing only malicious, suspicious, and error files"
                    : "No threats found in this directory"}
                </Typography>
                <List sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {scanResult.results && scanResult.results
                    .filter(result => result.infected || isSuspicious(result) || result.threatType === "ERROR")
                    .map((result, index, filteredResults) => (
                      <React.Fragment key={index}>
                        <StyledListItem>
                          <ListItemIcon>
                            {result.infected ? (
                              <ErrorIcon sx={{ color: 'var(--error-main)' }} />
                            ) : (
                              <WarningIcon sx={{ color: getVerdictColorVar(result) }} />
                            )}
                          </ListItemIcon>
                          <ListItemText
                            primary={
                              <Typography
                                component="div"
                                sx={{
                                  color: 'var(--text-primary)',
                                  wordBreak: 'break-all'
                                }}
                              >
                                {getDisplayName(result)}
                              </Typography>
                            }
                            secondary={
                              <Box>
                                <Typography
                                  component="div"
                                  variant="body2"
                                  sx={{ color: 'var(--text-primary)' }}
                                >
                                  Status: {getVerdictLabel(result)}
                                  {typeof result.riskScore === 'number' ? ` (score ${result.riskScore}/100)` : ''}
                                </Typography>
                                {result.threatType && (
                                  <Typography
                                    component="div"
                                    variant="body2"
                                    sx={{ color: 'var(--text-secondary)' }}
                                  >
                                    {' | Type: ' + result.threatType}
                                  </Typography>
                                )}
                                {result.threatDetails && (
                                  <Typography
                                    component="div"
                                    variant="body2"
                                    sx={{ color: 'var(--text-secondary)' }}
                                  >
                                    {' | ' + result.threatDetails}
                                  </Typography>
                                )}
                              </Box>
                            }
                          />
                        </StyledListItem>
                        {index < filteredResults.length - 1 && (
                          <Divider sx={{ borderColor: 'var(--border-main)' }} />
                        )}
                      </React.Fragment>
                    ))}
                </List>
              </StyledPaper>
            </Grid>
          </>
        )}
      </Grid>
    </Box>
  );
}

export default DirectoryScan;
