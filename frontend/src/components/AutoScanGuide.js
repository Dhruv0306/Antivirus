import React from 'react';
import {
  Box,
  Typography,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Divider,
  Paper,
  Alert,
} from '@mui/material';
import {
  Schedule as ScheduleIcon,
  Settings as SettingsIcon,
  Computer as ComputerIcon,
  Search as SearchIcon,
  Timer as TimerIcon,
  Info as InfoIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material';
import { styled } from '@mui/material/styles';

// Styled components
const StyledCard = styled(Card)(({ theme }) => ({
  backgroundColor: '#ffffff',
  color: '#2c3e50',
  border: '1px solid rgba(0, 0, 0, 0.12)',
  borderRadius: '8px',
  transition: 'all 0.2s ease-in-out',
  marginBottom: '16px',
  '&:hover': {
    borderColor: '#0068ff',
    boxShadow: '0 8px 16px rgba(0, 0, 0, 0.15)'
  }
}));

const StyledPaper = styled(Paper)(({ theme }) => ({
  padding: '24px',
  backgroundColor: '#ffffff',
  border: '1px solid rgba(0, 0, 0, 0.12)',
  borderRadius: '8px',
  marginBottom: '16px'
}));

const AutoScanGuide = () => {
  return (
    <Box sx={{ 
      p: 3, 
      color: '#2c3e50',
      backgroundColor: '#f5f5f5',
      minHeight: '100vh'
    }}>
      {/* Main Title */}
      <Typography 
        variant="h3" 
        gutterBottom 
        align="center" 
        sx={{ 
          color: '#2c3e50',
          mb: 4,
          fontWeight: 600
        }}
      >
        Setting Up Automated System Scans with Windows Task Scheduler
      </Typography>

      {/* Introduction */}
      <StyledPaper elevation={3} sx={{ mb: 4 }}>
        <Typography variant="body1" paragraph>
          You can automate virus scanning using Windows Task Scheduler to run scans at regular intervals. 
          This guide will walk you through the process of setting up automated scans using Windows built-in tools.
        </Typography>
        <Alert severity="info" sx={{ mt: 2 }}>
          Make sure you have administrative privileges on your Windows system to set up scheduled tasks.
        </Alert>
      </StyledPaper>

      {/* Step-by-Step Guide */}
      <StyledCard>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <SettingsIcon sx={{ fontSize: 30, mr: 1, color: '#0068ff' }} />
            <Typography variant="h5" component="div">
              Step-by-Step Setup Guide
            </Typography>
          </Box>
          
          <List>
            {/* Step 1 */}
            <ListItem>
              <ListItemIcon>
                <SearchIcon sx={{ color: '#0068ff' }} />
              </ListItemIcon>
              <ListItemText
                primary="Step 1: Open Task Scheduler"
                secondary={
                  <Typography variant="body2" component="div" color="text.secondary">
                    • Press Windows + R to open Run dialog<br />
                    • Type "taskschd.msc" and press Enter<br />
                    • Or search for "Task Scheduler" in Windows Search
                  </Typography>
                }
              />
            </ListItem>
            
            <Divider sx={{ my: 2 }} />
            
            {/* Step 2 */}
            <ListItem>
              <ListItemIcon>
                <ComputerIcon sx={{ color: '#0068ff' }} />
              </ListItemIcon>
              <ListItemText
                primary="Step 2: Create a New Task"
                secondary={
                  <Typography variant="body2" component="div" color="text.secondary">
                    • In Task Scheduler, click "Create Basic Task" in the right panel<br />
                    • Give your task a name (e.g., "Weekly Virus Scan")<br />
                    • Add a description (optional)
                  </Typography>
                }
              />
            </ListItem>
            
            <Divider sx={{ my: 2 }} />
            
            {/* Step 3 */}
            <ListItem>
              <ListItemIcon>
                <TimerIcon sx={{ color: '#0068ff' }} />
              </ListItemIcon>
              <ListItemText
                primary="Step 3: Set the Schedule"
                secondary={
                  <Typography variant="body2" component="div" color="text.secondary">
                    • Choose how often to run the scan (Daily, Weekly, or Monthly)<br />
                    • Select the start time (preferably during off-hours)<br />
                    • For weekly tasks, choose which days of the week<br />
                    • For monthly tasks, choose which day of the month
                  </Typography>
                }
              />
            </ListItem>
            
            <Divider sx={{ my: 2 }} />
            
            {/* Step 4 */}
            <ListItem>
              <ListItemIcon>
                <SettingsIcon sx={{ color: '#0068ff' }} />
              </ListItemIcon>
              <ListItemText
                primary="Step 4: Configure the Action"
                secondary={
                  <Typography variant="body2" component="div" color="text.secondary">
                    • Choose "Start a Program" as the action<br />
                    • Browse to your antivirus program's executable file<br />
                    • Add command-line arguments for silent scanning (refer to your antivirus documentation)<br />
                    • Example: "C:\Program Files\YourAntivirus\scanner.exe" --silent --full
                  </Typography>
                }
              />
            </ListItem>
          </List>
        </CardContent>
      </StyledCard>

      {/* Additional Settings Card */}
      <StyledCard>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <InfoIcon sx={{ fontSize: 30, mr: 1, color: '#0068ff' }} />
            <Typography variant="h5" component="div">
              Additional Task Settings
            </Typography>
          </Box>

          <List>
            <ListItem>
              <ListItemIcon>
                <CheckCircleIcon sx={{ color: '#00a854' }} />
              </ListItemIcon>
              <ListItemText
                primary="Run with Highest Privileges"
                secondary="Enable 'Run with highest privileges' in task settings to ensure the scan has necessary permissions"
              />
            </ListItem>

            <ListItem>
              <ListItemIcon>
                <CheckCircleIcon sx={{ color: '#00a854' }} />
              </ListItemIcon>
              <ListItemText
                primary="Wake Computer"
                secondary="Enable 'Wake the computer to run this task' if you want scans to run even when the computer is in sleep mode"
              />
            </ListItem>

            <ListItem>
              <ListItemIcon>
                <CheckCircleIcon sx={{ color: '#00a854' }} />
              </ListItemIcon>
              <ListItemText
                primary="Start When Available"
                secondary="Enable 'Run task as soon as possible after a scheduled start is missed' to ensure scans run even if the original time is missed"
              />
            </ListItem>
          </List>
        </CardContent>
      </StyledCard>

      {/* Best Practices Card */}
      <StyledCard>
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', mb: 3 }}>
            <ScheduleIcon sx={{ fontSize: 30, mr: 1, color: '#0068ff' }} />
            <Typography variant="h5" component="div">
              Best Practices
            </Typography>
          </Box>

          <List>
            <ListItem>
              <ListItemText
                primary="Optimal Scheduling"
                secondary="Schedule scans during off-hours (e.g., 2 AM) when the computer is less likely to be in use"
              />
            </ListItem>

            <ListItem>
              <ListItemText
                primary="Frequency"
                secondary="Weekly scans are recommended for personal computers, while business computers might need more frequent scans"
              />
            </ListItem>

            <ListItem>
              <ListItemText
                primary="Resource Usage"
                secondary="Configure your antivirus to use fewer resources during scheduled scans to minimize system impact"
              />
            </ListItem>

            <ListItem>
              <ListItemText
                primary="Log Files"
                secondary="Enable logging in your antivirus software to keep track of scheduled scan results"
              />
            </ListItem>
          </List>
        </CardContent>
      </StyledCard>

      {/* Warning Note */}
      <Alert severity="warning" sx={{ mt: 3 }}>
        Remember to periodically check the Task Scheduler to ensure your scheduled scans are running properly 
        and review the scan logs to verify the effectiveness of your automated scanning setup.
      </Alert>
    </Box>
  );
};

export default AutoScanGuide; 