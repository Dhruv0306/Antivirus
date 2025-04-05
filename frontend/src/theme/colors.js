// Utility function to get CSS variable value
const getCssVar = (variable) => {
  return getComputedStyle(document.documentElement).getPropertyValue(variable).trim();
};

// Get theme colors from CSS variables
export const getThemeColors = () => ({
  primary: {
    main: getCssVar('--primary-main'),
    light: getCssVar('--primary-light'),
    dark: getCssVar('--primary-dark'),
    contrastText: getCssVar('--primary-contrast'),
  },
  secondary: {
    main: getCssVar('--secondary-main'),
    light: getCssVar('--secondary-light'),
    dark: getCssVar('--secondary-dark'),
    contrastText: getCssVar('--secondary-contrast'),
  },
  success: {
    main: getCssVar('--success-main'),
    light: getCssVar('--success-light'),
    dark: getCssVar('--success-dark'),
  },
  error: {
    main: getCssVar('--error-main'),
    light: getCssVar('--error-light'),
    dark: getCssVar('--error-dark'),
  },
  background: {
    default: getCssVar('--background-default'),
    paper: getCssVar('--background-paper'),
    dark: getCssVar('--background-dark'),
  },
  text: {
    primary: getCssVar('--text-primary'),
    secondary: getCssVar('--text-secondary'),
    disabled: getCssVar('--text-disabled'),
  },
}); 