import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  Box,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Typography,
  Paper,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  Description as FileIcon,
  Folder as FolderIcon,
  Computer as ComputerIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';

function Sidebar() {
  const location = useLocation();

  const menuItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
    { text: 'File Scan', icon: <FileIcon />, path: '/file-scan' },
    { text: 'Directory Scan', icon: <FolderIcon />, path: '/directory-scan' },
    { text: 'System Scan', icon: <ComputerIcon />, path: '/system-scan' },
    { text: 'Network Security', icon: <SecurityIcon />, path: '/network-security' },
  ];

  return (
    <Paper
      elevation={3}
      sx={{
        width: 240,
        bgcolor: 'background.paper',
        borderRadius: '12px',
        m: 2,
        overflow: 'hidden',
        border: '1px solid rgba(0, 255, 255, 0.1)',
        boxShadow: '0 4px 15px rgba(0, 255, 255, 0.15)',
        height: 'fit-content',
        position: 'sticky',
        top: 16,
      }}
    >
      <Box 
        sx={{ 
          p: 1.5, 
          display: 'flex', 
          alignItems: 'center', 
          gap: 1,
          borderBottom: '1px solid rgba(0, 255, 255, 0.1)',
          background: 'linear-gradient(145deg, rgba(0, 33, 64, 0.9), rgba(0, 21, 41, 0.9))',
        }}
      >
        <SecurityIcon sx={{ color: '#00ffff', fontSize: '1.5rem' }} />
        <Typography variant="h6" component="div" sx={{ color: '#ffffff', fontSize: '1.2rem' }}>
          SecureGuard
        </Typography>
      </Box>
      <List sx={{ py: 0.5 }}>
        {menuItems.map((item) => (
          <ListItem
            key={item.text}
            component={Link}
            to={item.path}
            sx={{
              color: 'white',
              bgcolor: location.pathname === item.path 
                ? 'rgba(0, 255, 255, 0.1)' 
                : 'transparent',
              '&:hover': {
                bgcolor: 'rgba(0, 255, 255, 0.05)',
                '& .MuiListItemIcon-root': {
                  color: '#00ffff',
                },
              },
              transition: 'all 0.2s ease',
              borderRadius: '8px',
              mx: 1,
              mb: 0.5,
              py: 0.75,
              minHeight: '40px',
            }}
          >
            <ListItemIcon 
              sx={{ 
                color: location.pathname === item.path ? '#00ffff' : 'rgba(255, 255, 255, 0.7)',
                transition: 'color 0.2s ease',
                minWidth: '35px',
                '& .MuiSvgIcon-root': {
                  fontSize: '1.3rem',
                },
              }}
            >
              {item.icon}
            </ListItemIcon>
            <ListItemText 
              primary={item.text} 
              sx={{
                margin: 0,
                '& .MuiTypography-root': {
                  fontWeight: location.pathname === item.path ? 600 : 400,
                  fontSize: '0.9rem',
                }
              }}
            />
          </ListItem>
        ))}
      </List>
    </Paper>
  );
}

export default Sidebar; 