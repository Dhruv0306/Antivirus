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

const StyledTableCell = styled(TableCell)(({ theme }) => ({
  color: 'var(--text-primary)',
  borderBottom: '1px solid var(--border-main)'
}));

const StyledTableRow = styled(TableRow)(({ theme }) => ({
  '&:hover': {
    backgroundColor: 'var(--background-dark)'
  }
}));

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
      <Typography 
        variant="h4" 
        gutterBottom 
        sx={{ 
          mb: 4,
          color: 'var(--text-primary)',
          fontWeight: 600 
        }}
      >
        File Scan
      </Typography>

      <StyledPaper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <StyledButton
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
            </StyledButton>
            {selectedFile && (
              <Typography 
                variant="body1" 
                sx={{ 
                  flexGrow: 1, 
                  wordBreak: 'break-all',
                  color: 'var(--text-secondary)' 
                }}
              >
                Selected: {selectedFile.name}
              </Typography>
            )}
          </Box>

          <StyledButton
            variant="contained"
            onClick={handleScan}
            disabled={!selectedFile || scanning}
            sx={{ alignSelf: 'flex-start' }}
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
              'Scan File'
            )}
          </StyledButton>

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

      {scanResult && (
        <StyledPaper sx={{ p: 3 }}>
          <Typography 
            variant="h6" 
            gutterBottom
            sx={{ 
              color: 'var(--text-primary)',
              fontWeight: 600 
            }}
          >
            Scan Results
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <StyledTableRow>
                  <StyledTableCell>File Name</StyledTableCell>
                  <StyledTableCell>Status</StyledTableCell>
                  <StyledTableCell>Threat Type</StyledTableCell>
                  <StyledTableCell>Details</StyledTableCell>
                </StyledTableRow>
              </TableHead>
              <TableBody>
                <StyledTableRow>
                  <StyledTableCell sx={{ maxWidth: 300, wordBreak: 'break-all' }}>
                    {selectedFile.name}
                  </StyledTableCell>
                  <StyledTableCell>
                    <Alert
                      severity={scanResult.infected ? 'error' : 'success'}
                      sx={{ 
                        display: 'inline-flex',
                        backgroundColor: scanResult.infected 
                          ? 'var(--error-main)' 
                          : 'var(--success-main)',
                        color: '#FFFFFF',
                        '& .MuiAlert-icon': {
                          color: '#FFFFFF'
                        }
                      }}
                    >
                      {scanResult.infected ? 'Infected' : 'Clean'}
                    </Alert>
                  </StyledTableCell>
                  <StyledTableCell>{scanResult.threatType || 'N/A'}</StyledTableCell>
                  <StyledTableCell>{scanResult.threatDetails || 'No threats found'}</StyledTableCell>
                </StyledTableRow>
              </TableBody>
            </Table>
          </TableContainer>
        </StyledPaper>
      )}
    </Box>
  );
}

export default FileScan; 