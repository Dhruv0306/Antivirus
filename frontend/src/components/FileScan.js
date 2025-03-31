import React, { useState } from 'react';
import {
  Box,
  Button,
  Typography,
  Alert,
  CircularProgress,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow
} from '@mui/material';
import { CloudUpload as CloudUploadIcon } from '@mui/icons-material';
import axios from 'axios';

function FileScan() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState(null);

  const handleFileSelect = (event) => {
    const file = event.target.files[0];
    if (file) {
      setSelectedFile(file);
      setError(null);
      setScanResult(null);
    }
  };

  const handleScan = async () => {
    if (!selectedFile) {
      setError('Please select a file to scan');
      return;
    }

    setScanning(true);
    setError(null);
    setScanResult(null);

    const formData = new FormData();
    formData.append('file', selectedFile, selectedFile.name);

    try {
      const response = await axios.post(
        'http://localhost:8080/api/antivirus/scan/file',
        formData,
        {
          headers: {
            'Content-Type': 'multipart/form-data',
          },
          onUploadProgress: (progressEvent) => {
            const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
            console.log('Upload Progress:', percentCompleted, '%');
          },
        }
      );
      
      if (response.data) {
        setScanResult(response.data);
      } else {
        throw new Error('No scan result received');
      }
    } catch (error) {
      console.error('Scan error:', error);
      setError('Error scanning file: ' + (error.response?.data?.threatDetails || error.message));
      setScanResult(null);
    } finally {
      setScanning(false);
    }
  };

  return (
    <Box sx={{ width: '100%', maxWidth: 1200, margin: '0 auto', p: 3 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        File Scan
      </Typography>

      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Button
              variant="contained"
              component="label"
              startIcon={<CloudUploadIcon />}
              disabled={scanning}
            >
              Select File
              <input
                type="file"
                hidden
                onChange={handleFileSelect}
                accept="*/*"
              />
            </Button>
            {selectedFile && (
              <Typography variant="body1" sx={{ flexGrow: 1, wordBreak: 'break-all' }}>
                Selected: {selectedFile.name}
              </Typography>
            )}
          </Box>

          <Button
            variant="contained"
            color="primary"
            onClick={handleScan}
            disabled={!selectedFile || scanning}
            sx={{ alignSelf: 'flex-start' }}
          >
            {scanning ? (
              <>
                <CircularProgress size={24} sx={{ mr: 1 }} color="inherit" />
                Scanning...
              </>
            ) : (
              'Scan File'
            )}
          </Button>

          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}
        </Box>
      </Paper>

      {scanResult && (
        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Scan Results
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>File Name</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Threat Type</TableCell>
                  <TableCell>Details</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                <TableRow>
                  <TableCell sx={{ maxWidth: 300, wordBreak: 'break-all' }}>
                    {selectedFile.name}
                  </TableCell>
                  <TableCell>
                    <Alert
                      severity={scanResult.infected ? 'error' : 'success'}
                      sx={{ display: 'inline-flex' }}
                    >
                      {scanResult.infected ? 'Infected' : 'Clean'}
                    </Alert>
                  </TableCell>
                  <TableCell>{scanResult.threatType || 'N/A'}</TableCell>
                  <TableCell>{scanResult.threatDetails || 'No threats found'}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </Paper>
      )}
    </Box>
  );
}

export default FileScan; 