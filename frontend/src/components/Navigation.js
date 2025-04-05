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
import { styled } from '@mui/material/styles';

const drawerWidth = 240;

// Styled components
const StyledDrawer = styled(Drawer)(({ theme }) => ({
  width: drawerWidth,
  flexShrink: 0,
  '& .MuiDrawer-paper': {
    width: drawerWidth,
    boxSizing: 'border-box',
    backgroundColor: 'var(--background-paper)',
    borderRight: '1px solid var(--border-main)',
    color: 'var(--text-primary)'
  }
}));

const StyledListItemButton = styled(ListItemButton)(({ theme }) => ({
  '&.Mui-selected': {
    backgroundColor: 'rgba(33, 150, 243, 0.1)',
    '&:hover': {
      backgroundColor: 'rgba(33, 150, 243, 0.2)',
    }
  },
  '&:hover': {
    backgroundColor: 'rgba(33, 150, 243, 0.05)',
  }
}));

const LogoIcon = styled(SecurityIcon)(({ theme }) => ({
  fontSize: 32,
  marginRight: 8,
  color: 'var(--primary-main)',
  animation: 'pulse 2s infinite',
  '@keyframes pulse': {
    '0%': { opacity: 0.6 },
    '50%': { opacity: 1 },
    '100%': { opacity: 0.6 }
  }
}));

const LogoText = styled(Typography)(({ theme }) => ({
  fontWeight: 'bold',
  letterSpacing: '0.5px',
  background: 'linear-gradient(45deg, var(--primary-main) 30%, var(--primary-light) 90%)',
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent'
}));

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
    <StyledDrawer variant={isMobile ? "temporary" : "permanent"}>
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
          borderBottom: `1px solid var(--border-main)`
        }}>
          <LogoIcon />
          <LogoText variant="h6">
            SecureGuard
          </LogoText>
        </Box>
        <List sx={{ flexGrow: 1 }}>
          {menuItems.map((item) => (
            <ListItem key={item.text} disablePadding>
              <StyledListItemButton
                selected={location.pathname === item.path}
                onClick={() => navigate(item.path)}
              >
                <ListItemIcon sx={{ 
                  color: location.pathname === item.path 
                    ? 'var(--primary-main)' 
                    : 'var(--text-secondary)',
                  minWidth: 40,
                  ml: 1
                }}>
                  {item.icon}
                </ListItemIcon>
                <ListItemText 
                  primary={item.text} 
                  sx={{
                    '& .MuiTypography-root': {
                      fontWeight: location.pathname === item.path ? 600 : 400,
                      color: location.pathname === item.path 
                        ? 'var(--text-primary)' 
                        : 'var(--text-secondary)'
                    }
                  }}
                />
              </StyledListItemButton>
            </ListItem>
          ))}
        </List>
      </Box>
    </StyledDrawer>
  );
}

export default Navigation; 