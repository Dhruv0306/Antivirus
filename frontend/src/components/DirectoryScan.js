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
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        Directory Scan
      </Typography>

      <Grid container spacing={3}>
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                <Button
                  variant="contained"
                  startIcon={<FolderIcon />}
                  onClick={handleDirectorySelect}
                  disabled={scanning}
                >
                  Select Directory
                </Button>
                <Button
                  variant="contained"
                  color="primary"
                  startIcon={<SecurityIcon />}
                  onClick={handleScan}
                  disabled={!selectedDirectory || scanning}
                >
                  {scanning ? (
                    <>
                      <CircularProgress size={24} sx={{ mr: 1 }} color="inherit" />
                      Scanning...
                    </>
                  ) : (
                    'Start Scan'
                  )}
                </Button>
                <FormControlLabel
                  control={
                    <Switch
                      checked={recursive}
                      onChange={(e) => setRecursive(e.target.checked)}
                      disabled={scanning}
                    />
                  }
                  label="Include Subdirectories"
                />
              </Box>

              {selectedDirectory && (
                <Typography variant="body2" color="text.secondary">
                  Selected Directory: {selectedDirectory}
                </Typography>
              )}

              {scanning && (
                <Box sx={{ width: '100%', mt: 2 }}>
                  <LinearProgress variant="determinate" value={progress} />
                  <Typography variant="body2" color="text.secondary" align="center" sx={{ mt: 1 }}>
                    {Math.round(progress)}% Complete
                  </Typography>
                </Box>
              )}

              {error && (
                <Alert severity="error" sx={{ mt: 2 }}>
                  {error}
                </Alert>
              )}
            </Box>
          </Paper>
        </Grid>

        {scanResult && (
          <>
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Scan Summary
                </Typography>
                <List>
                  <ListItem>
                    <ListItemIcon>
                      <FolderIcon />
                    </ListItemIcon>
                    <ListItemText
                      primary="Total Files Scanned"
                      secondary={scanResult.totalFiles || 0}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color="success" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Clean Files"
                      secondary={scanResult.totalFiles - (scanResult.infectedFiles + scanResult.skippedFiles) || 0}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <ErrorIcon color="error" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Infected Files"
                      secondary={scanResult.infectedFiles || 0}
                    />
                  </ListItem>
                  <ListItem>
                    <ListItemIcon>
                      <WarningIcon color="warning" />
                    </ListItemIcon>
                    <ListItemText
                      primary="Skipped/Error Files"
                      secondary={scanResult.skippedFiles || 0}
                    />
                  </ListItem>
                  <Divider />
                  <ListItem>
                    <ListItemIcon>
                      <CheckCircleIcon color={scanResult.infectedFiles > 0 ? "error" : "success"} />
                    </ListItemIcon>
                    <ListItemText
                      primary="Directory Status"
                      secondary={
                        scanResult.infectedFiles > 0 
                          ? `Threats Found (${scanResult.infectedFiles} infected files)` 
                          : "Clean"
                      }
                    />
                  </ListItem>
                </List>
              </Paper>
            </Grid>

            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>
                  Scan Details
                </Typography>
                <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                  {scanResult.infectedFiles > 0 
                    ? "Showing only infected and error files" 
                    : "No threats found in this directory"}
                </Typography>
                <List sx={{ maxHeight: 400, overflow: 'auto' }}>
                  {scanResult.results && scanResult.results
                    .filter(result => result.infected || result.threatType === "ERROR")
                    .map((result, index) => (
                    <React.Fragment key={index}>
                      <ListItem>
                        <ListItemIcon>
                          {result.infected ? (
                            <ErrorIcon color="error" />
                          ) : (
                            <WarningIcon color="warning" />
                          )}
                        </ListItemIcon>
                        <ListItemText
                          primary={result.filePath}
                          secondary={
                            <>
                              <Typography component="span" variant="body2" color="text.primary">
                                Status: {result.infected ? 'Infected' : 'Error'}
                              </Typography>
                              {result.threatType && (
                                <Typography component="span" variant="body2" color="text.secondary">
                                  {' | Type: ' + result.threatType}
                                </Typography>
                              )}
                              {result.threatDetails && (
                                <Typography component="span" variant="body2" color="text.secondary">
                                  {' | ' + result.threatDetails}
                                </Typography>
                              )}
                            </>
                          }
                        />
                      </ListItem>
                      {index < scanResult.results.filter(r => r.infected || r.threatType === "ERROR").length - 1 && <Divider />}
                    </React.Fragment>
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

export default DirectoryScan; 