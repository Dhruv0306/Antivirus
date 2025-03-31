import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  Drawer,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  ListItemButton,
  Box,
  Typography,
  useTheme,
  useMediaQuery,
} from '@mui/material';
import {
  Dashboard as DashboardIcon,
  FileCopy as FileIcon,
  Folder as FolderIcon,
  Computer as ComputerIcon,
  Security as SecurityIcon,
} from '@mui/icons-material';

const drawerWidth = 240;

const menuItems = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { text: 'File Scan', icon: <FileIcon />, path: '/file-scan' },
  { text: 'Directory Scan', icon: <FolderIcon />, path: '/directory-scan' },
  { text: 'System Scan', icon: <ComputerIcon />, path: '/system-scan' },
  { text: 'Network Security', icon: <SecurityIcon />, path: '/network-security' },
];

function Navigation() {
  const navigate = useNavigate();
  const location = useLocation();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down('sm'));

  return (
    <Drawer
      variant={isMobile ? "temporary" : "permanent"}
      sx={{
        width: drawerWidth,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: drawerWidth,
          boxSizing: 'border-box',
          backgroundColor: 'background.paper',
          borderRight: '1px solid rgba(255, 255, 255, 0.12)',
        },
      }}
    >
      <Box sx={{ 
        overflow: 'auto',
        display: 'flex',
        flexDirection: 'column',
        height: '100%'
      }}>
        <Box sx={{ 
          display: 'flex', 
          alignItems: 'center', 
          p: 2,
          borderBottom: '1px solid rgba(255, 255, 255, 0.12)'
        }}>
          <SecurityIcon sx={{ 
            fontSize: 32,
            mr: 1,
            color: 'primary.main',
            animation: 'pulse 2s infinite',
            '@keyframes pulse': {
              '0%': { opacity: 0.6 },
              '50%': { opacity: 1 },
              '100%': { opacity: 0.6 }
            }
          }} />
          <Typography variant="h6" color="primary" sx={{ 
            fontWeight: 'bold',
            letterSpacing: '0.5px',
            background: 'linear-gradient(45deg, #2196f3 30%, #21CBF3 90%)',
            WebkitBackgroundClip: 'text',
            WebkitTextFillColor: 'transparent'
          }}>
            SecureGuard
          </Typography>
        </Box>
        <List sx={{ flexGrow: 1 }}>
          {menuItems.map((item) => (
            <ListItem key={item.text} disablePadding>
              <ListItemButton
                selected={location.pathname === item.path}
                onClick={() => navigate(item.path)}
                sx={{
                  '&.Mui-selected': {
                    backgroundColor: 'rgba(33, 150, 243, 0.1)',
                    '&:hover': {
                      backgroundColor: 'rgba(33, 150, 243, 0.2)',
                    }
                  },
                  '&:hover': {
                    backgroundColor: 'rgba(255, 255, 255, 0.05)',
                  }
                }}
              >
                <ListItemIcon sx={{ 
                  color: location.pathname === item.path ? 'primary.main' : 'inherit',
                  minWidth: 40,
                  ml: 1
                }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText 
                  primary={item.text} 
                  sx={{
                    '& .MuiTypography-root': {
                      fontWeight: location.pathname === item.path ? 600 : 400
                    }
                  }}
                />
              </ListItemButton>
            </ListItem>
          ))}
        </List>
      </Box>
    </Drawer>
  );
}

export default Navigation; 