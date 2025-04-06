import React, { useState } from 'react';
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

function DirectoryScan() {
  const [selectedDirectory, setSelectedDirectory] = useState('');
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);
  const [recursive, setRecursive] = useState(true);
  const [progress, setProgress] = useState(0);
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
          setProgress(0);
        }
      };

      input.click();
    } catch (err) {
      console.error('Directory selection error:', err);
      setError('Error selecting directory: ' + err.message);
    }
  };

  const handleScan = async () => {
    if (!selectedDirectory || !selectedFiles) {
      setError('Please select a directory first');
      return;
    }

    setScanning(true);
    setError(null);
    setScanResult(null);
    setProgress(0);

    try {
      // Create FormData to send files
      const formData = new FormData();
      formData.append('directoryName', selectedDirectory);
      formData.append('recursive', recursive);
      
      // Append all files while maintaining their relative paths
      for (const file of selectedFiles) {
        formData.append('files', file, file.webkitRelativePath);
      }

      // Send the files to the backend
      const response = await axios.post('http://localhost:8080/api/antivirus/scan/directory', formData, {
        headers: {
          'Content-Type': 'multipart/form-data'
        },
        onUploadProgress: (progressEvent) => {
          const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setProgress(percentCompleted);
        }
      });

      // Update the scan result with the response data
      if (response.data) {
        setScanResult({
          totalFiles: response.data.totalFiles || 0,
          infectedFiles: response.data.infectedFiles || 0,
          skippedFiles: response.data.skippedFiles || 0,
          results: response.data.results || []
        });
      } else {
        throw new Error('No scan result received');
      }
    } catch (err) {
      console.error('Scan error:', err);
      const errorMessage = err.response?.data?.error || err.message || 'Unknown error';
      setError('Error scanning directory: ' + errorMessage);
    } finally {
      setScanning(false);
    }
  };

  return (
    <Box sx={{ width: '100%', maxWidth: 1200, margin: '0 auto', p: 3 }}>
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
          <StyledPaper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
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
                  <StyledProgress variant="determinate" value={progress} />
                  <Typography 
                    variant="body2" 
                    sx={{ 
                      mt: 1,
                      color: 'var(--text-secondary)',
                      textAlign: 'center' 
                    }}
                  >
                    {Math.round(progress)}% Complete
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
              <StyledPaper sx={{ p: 3 }}>
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
                          {scanResult.totalFiles - (scanResult.infectedFiles + scanResult.skippedFiles) || 0}
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
                          Infected Files
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
                            ? `Threats Found (${scanResult.infectedFiles} infected files)` 
                            : "Clean"}
                        </Typography>
                      }
                    />
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
                  {scanResult.infectedFiles > 0 
                    ? "Showing only infected and error files" 
                    : "No threats found in this directory"}
                </Typography>
                <List sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {scanResult.results && scanResult.results
                    .filter(result => result.infected || result.threatType === "ERROR")
                    .map((result, index) => (
                    <React.Fragment key={index}>
                      <StyledListItem>
                        <ListItemIcon>
                          {result.infected ? (
                            <ErrorIcon sx={{ color: 'var(--error-main)' }} />
                          ) : (
                            <WarningIcon sx={{ color: 'var(--warning-main)' }} />
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
                              {result.filePath}
                            </Typography>
                          }
                          secondary={
                            <Box>
                              <Typography 
                                component="div" 
                                variant="body2" 
                                sx={{ color: 'var(--text-primary)' }}
                              >
                                Status: {result.infected ? 'Infected' : 'Error'}
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
                      {index < scanResult.results.filter(r => r.infected || r.threatType === "ERROR").length - 1 && (
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