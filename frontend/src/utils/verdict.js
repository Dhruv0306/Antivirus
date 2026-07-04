// Central place for interpreting a ScanResult's verdict tier (CLEAN,
// SUSPICIOUS, MALICIOUS). Falls back to the legacy `infected` boolean for
// any result that predates the verdict field, so old scan history rows
// don't render blank after the upgrade.

export function getVerdictStatus(result) {
    if (!result) {
        return 'clean';
    }
    if (result.threatType === 'ERROR') {
        return 'error';
    }
    if (result.verdict) {
        return result.verdict.toLowerCase(); // 'malicious' | 'suspicious' | 'clean'
    }
    return result.infected ? 'malicious' : 'clean';
}

export function getVerdictLabel(result) {
    switch (getVerdictStatus(result)) {
        case 'malicious':
            return 'Malicious';
        case 'suspicious':
            return 'Suspicious';
        case 'error':
            return 'Error';
        default:
            return 'Clean';
    }
}

// Maps to MUI's Alert/Chip `severity`/`color` prop.
export function getVerdictSeverity(result) {
    switch (getVerdictStatus(result)) {
        case 'malicious':
            return 'error';
        case 'suspicious':
            return 'warning';
        case 'error':
            return 'warning';
        default:
            return 'success';
    }
}

// Maps to the app's CSS custom properties (var(--error-main) etc.) used
// throughout the existing styled components.
export function getVerdictColorVar(result) {
    switch (getVerdictStatus(result)) {
        case 'malicious':
            return 'var(--error-main)';
        case 'suspicious':
            return 'var(--warning-main)';
        case 'error':
            return 'var(--warning-main)';
        default:
            return 'var(--success-main)';
    }
}

export function isSuspicious(result) {
    return getVerdictStatus(result) === 'suspicious';
}

export function isMalicious(result) {
    return getVerdictStatus(result) === 'malicious';
}