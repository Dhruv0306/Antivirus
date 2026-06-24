import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import {
  Box,
  Button,
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
  Logout as LogoutIcon,
} from '@mui/icons-material';
import { useAuth } from '../context/AuthContext';
import { styled } from '@mui/material/styles';

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
    '& .MuiListItemIcon-root': { color: 'var(--primary-main)' }
  },
  transition: 'all 0.2s ease',
  borderRadius: 'var(--border-radius-medium)',
  margin: '4px 8px',
  marginBottom: 4,
  padding: '6px',
  minHeight: '40px',
  '&.active': {
    backgroundColor: 'var(--primary-transparent)',
    '& .MuiListItemIcon-root': { color: 'var(--primary-main)' },
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
  '& .MuiSvgIcon-root': { fontSize: '1.3rem' }
}));

const StyledListItemText = styled(ListItemText)(({ theme }) => ({
  margin: 0,
  '& .MuiTypography-root': {
    fontWeight: 400,
    fontSize: '0.9rem',
    color: 'var(--text-secondary)'
  }
}));

// All menu items declared with an optional adminOnly flag
const ALL_MENU_ITEMS = [
  { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
  { text: 'File Scan', icon: <FileIcon />, path: '/file-scan' },
  { text: 'Directory Scan', icon: <FolderIcon />, path: '/directory-scan' },
  { text: 'System Scan', icon: <ComputerIcon />, path: '/system-scan', adminOnly: true },
  { text: 'Network Security', icon: <SecurityIcon />, path: '/network-security', adminOnly: true },
  { text: 'Auto Scan Guide', icon: <ScheduleIcon />, path: '/auto-scan-guide', adminOnly: true },
];

function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, isAdmin, logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Regular users only see Dashboard, File Scan, Directory Scan
  const menuItems = isAdmin
    ? ALL_MENU_ITEMS
    : ALL_MENU_ITEMS.filter((item) => !item.adminOnly);

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
              <StyledListItemIcon>{item.icon}</StyledListItemIcon>
              <StyledListItemText primary={item.text} />
            </StyledListItem>
          );
        })}
      </List>

      <Box sx={{ p: 2, borderTop: '1px solid var(--border-main)' }}>
        {user && (
          <Typography
            variant="caption"
            sx={{ display: 'block', mb: 1, color: 'var(--text-secondary)' }}
          >
            {isAdmin ? 'Admin' : 'User'}: {user}
          </Typography>
        )}
        <Button
          fullWidth
          variant="outlined"
          color="inherit"
          startIcon={<LogoutIcon />}
          onClick={handleLogout}
        >
          Sign Out
        </Button>
      </Box>
    </StyledPaper>
  );
}

export default Sidebar;