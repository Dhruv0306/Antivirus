// src/utils/logger.js
// M-09: Toggled logger utility — noops in production builds
// Vite's esbuild.drop config strips console.* entirely in prod,
// but this utility provides explicit dev-only logging as a second
// layer of defense and makes intent clear at the call site.

const isDev = import.meta.env.DEV;

export const log = isDev ? console.log.bind(console) : () => {};
export const logError = isDev ? console.error.bind(console) : () => {};
export const logWarn = isDev ? console.warn.bind(console) : () => {};
export const logDebug = isDev ? console.debug.bind(console) : () => {};
