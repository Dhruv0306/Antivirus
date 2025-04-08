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
  Schedule as ScheduleIcon,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';

// Styled components
const StyledPaper = styled(Paper)(({ theme }) => ({
  width: 240,
  backgroundColor: 'var(--background-paper)',
  color: 'var(--text-primary)',
  borderRadius: 'var(--border-radius-large)',
  margin: 16,
  overflow: 'hidden',
  border: '1px solid var(--border-main)',
  boxShadow: 'var(--shadow-large)',
  height: 'fit-content',
  position: 'sticky',
  top: 16,
  transition: 'all 0.2s ease-in-out',
  '&:hover': {
    boxShadow: 'var(--shadow-xlarge)'
  }
}));

const LogoContainer = styled(Box)(({ theme }) => ({
  padding: '12px',
  display: 'flex',
  alignItems: 'center',
  gap: 8,
  borderBottom: '1px solid var(--border-main)',
  background: 'linear-gradient(145deg, var(--background-dark), var(--background-paper))'
}));

const LogoIcon = styled(SecurityIcon)(({ theme }) => ({
  color: 'var(--primary-main)',
  fontSize: '1.5rem',
  animation: 'pulse 2s infinite',
  '@keyframes pulse': {
    '0%': { opacity: 0.6 },
    '50%': { opacity: 1 },
    '100%': { opacity: 0.6 }
  }
}));

const LogoText = styled(Typography)(({ theme }) => ({
  color: 'var(--text-primary)',
  fontSize: '1.2rem',
  fontWeight: 600,
  background: 'linear-gradient(45deg, var(--primary-main), var(--primary-light))',
  WebkitBackgroundClip: 'text',
  WebkitTextFillColor: 'transparent'
}));

const StyledListItem = styled(ListItem)(({ theme }) => ({
  color: 'var(--text-primary)',
  '&:hover': {
    backgroundColor: 'var(--primary-transparent-hover)',
    '& .MuiListItemIcon-root': {
      color: 'var(--primary-main)'
    }
  },
  transition: 'all 0.2s ease',
  borderRadius: 'var(--border-radius-medium)',
  margin: '4px 8px',
  marginBottom: 4,
  padding: '6px',
  minHeight: '40px',
  '&.active': {
    backgroundColor: 'var(--primary-transparent)',
    '& .MuiListItemIcon-root': {
      color: 'var(--primary-main)'
    },
    '& .MuiListItemText-root .MuiTypography-root': {
      fontWeight: 600,
      color: 'var(--text-primary)'
    }
  }
}));

const StyledListItemIcon = styled(ListItemIcon)(({ theme }) => ({
  color: 'var(--text-secondary)',
  transition: 'color 0.2s ease',
  minWidth: '35px',
  '& .MuiSvgIcon-root': {
    fontSize: '1.3rem'
  }
}));

const StyledListItemText = styled(ListItemText)(({ theme }) => ({
  margin: 0,
  '& .MuiTypography-root': {
    fontWeight: 400,
    fontSize: '0.9rem',
    color: 'var(--text-secondary)'
  }
}));

function Sidebar() {
  const location = useLocation();

  const menuItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
    { text: 'File Scan', icon: <FileIcon />, path: '/file-scan' },
    { text: 'Directory Scan', icon: <FolderIcon />, path: '/directory-scan' },
    { text: 'System Scan', icon: <ComputerIcon />, path: '/system-scan' },
    { text: 'Network Security', icon: <SecurityIcon />, path: '/network-security' },
    { text: 'Auto Scan Guide', icon: <ScheduleIcon />, path: '/auto-scan-guide' },
  ];

  return (
    <StyledPaper elevation={3}>
      <LogoContainer>
        <LogoIcon />
        <LogoText variant="h6" component="div">
          SecureGuard
        </LogoText>
      </LogoContainer>
      <List sx={{ py: 0.5 }}>
        {menuItems.map((item) => {
          const isActive = location.pathname === item.path;
          return (
            <StyledListItem
              key={item.text}
              component={Link}
              to={item.path}
              className={isActive ? 'active' : ''}
            >
              <StyledListItemIcon>
                {item.icon}
              </StyledListItemIcon>
              <StyledListItemText 
                primary={item.text}
              />
            </StyledListItem>
          );
        })}
      </List>
    </StyledPaper>
  );
}

export default Sidebar;