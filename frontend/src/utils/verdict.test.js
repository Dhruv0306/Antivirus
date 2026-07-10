import { describe, expect, test } from 'vitest';
import {
    getVerdictStatus,
    getVerdictLabel,
    getVerdictSeverity,
    getVerdictColorVar,
    isSuspicious,
    isMalicious,
} from './verdict';

describe('getVerdictStatus', () => {
    test('returns clean for a null or undefined result', () => {
        expect(getVerdictStatus(null)).toBe('clean');
        expect(getVerdictStatus(undefined)).toBe('clean');
    });

    test('returns error when threatType is ERROR, regardless of verdict', () => {
        expect(getVerdictStatus({ threatType: 'ERROR', verdict: 'CLEAN' })).toBe('error');
    });

    test('lowercases the verdict field when present', () => {
        expect(getVerdictStatus({ verdict: 'MALICIOUS' })).toBe('malicious');
        expect(getVerdictStatus({ verdict: 'SUSPICIOUS' })).toBe('suspicious');
        expect(getVerdictStatus({ verdict: 'CLEAN' })).toBe('clean');
    });

    test('falls back to the legacy infected boolean when verdict is absent', () => {
        expect(getVerdictStatus({ infected: true })).toBe('malicious');
        expect(getVerdictStatus({ infected: false })).toBe('clean');
    });

    test('prefers verdict over the legacy infected boolean when both are present', () => {
        expect(getVerdictStatus({ verdict: 'SUSPICIOUS', infected: true })).toBe('suspicious');
    });
});

describe('getVerdictLabel', () => {
    test('maps each status to its display label', () => {
        expect(getVerdictLabel({ verdict: 'MALICIOUS' })).toBe('Malicious');
        expect(getVerdictLabel({ verdict: 'SUSPICIOUS' })).toBe('Suspicious');
        expect(getVerdictLabel({ threatType: 'ERROR' })).toBe('Error');
        expect(getVerdictLabel({ verdict: 'CLEAN' })).toBe('Clean');
        expect(getVerdictLabel(null)).toBe('Clean');
    });
});

describe('getVerdictSeverity', () => {
    test('maps each status to an MUI severity', () => {
        expect(getVerdictSeverity({ verdict: 'MALICIOUS' })).toBe('error');
        expect(getVerdictSeverity({ verdict: 'SUSPICIOUS' })).toBe('warning');
        expect(getVerdictSeverity({ threatType: 'ERROR' })).toBe('warning');
        expect(getVerdictSeverity({ verdict: 'CLEAN' })).toBe('success');
    });
});

describe('getVerdictColorVar', () => {
    test('maps each status to a CSS custom property', () => {
        expect(getVerdictColorVar({ verdict: 'MALICIOUS' })).toBe('var(--error-main)');
        expect(getVerdictColorVar({ verdict: 'SUSPICIOUS' })).toBe('var(--warning-main)');
        expect(getVerdictColorVar({ threatType: 'ERROR' })).toBe('var(--warning-main)');
        expect(getVerdictColorVar({ verdict: 'CLEAN' })).toBe('var(--success-main)');
    });
});

describe('isSuspicious / isMalicious', () => {
    test('isSuspicious is true only for the suspicious tier', () => {
        expect(isSuspicious({ verdict: 'SUSPICIOUS' })).toBe(true);
        expect(isSuspicious({ verdict: 'MALICIOUS' })).toBe(false);
        expect(isSuspicious({ verdict: 'CLEAN' })).toBe(false);
    });

    test('isMalicious is true only for the malicious tier', () => {
        expect(isMalicious({ verdict: 'MALICIOUS' })).toBe(true);
        expect(isMalicious({ infected: true })).toBe(true);
        expect(isMalicious({ verdict: 'SUSPICIOUS' })).toBe(false);
    });
});