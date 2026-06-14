import axios from 'axios';

const API_ROOT = import.meta.env.VITE_API_URL || 'http://localhost:8080';
const CSRF_STORAGE_KEY = 'auth_csrf_credentials';

let runtimeCsrf = null;

function canUseSessionStorage() {
  return typeof window !== 'undefined' && typeof window.sessionStorage !== 'undefined';
}

function readStoredCsrfCredentials() {
  if (!canUseSessionStorage()) {
    return null;
  }

  try {
    const raw = sessionStorage.getItem(CSRF_STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function writeStoredCsrfCredentials(csrf) {
  if (!canUseSessionStorage()) {
    return;
  }

  sessionStorage.setItem(CSRF_STORAGE_KEY, JSON.stringify(csrf));
}

function clearStoredCsrfCredentials() {
  if (!canUseSessionStorage()) {
    return;
  }

  sessionStorage.removeItem(CSRF_STORAGE_KEY);
}

export function setCsrfCredentials(csrf) {
  runtimeCsrf = csrf;
  writeStoredCsrfCredentials(csrf);
}

export function clearCsrfCredentials() {
  runtimeCsrf = null;
  clearStoredCsrfCredentials();
}

function getCsrfCredentials() {
  if (runtimeCsrf) {
    return runtimeCsrf;
  }

  runtimeCsrf = readStoredCsrfCredentials();
  return runtimeCsrf;
}

function getCookieValue(name) {
  const cookie = document.cookie
    .split('; ')
    .find((entry) => entry.startsWith(`${name}=`));

  return cookie ? decodeURIComponent(cookie.split('=').slice(1).join('=')) : null;
}

function setRequestHeader(headers, name, value) {
  if (!headers) {
    return { [name]: value };
  }

  if (typeof headers.set === 'function') {
    headers.set(name, value);
    return headers;
  }

  return {
    ...headers,
    [name]: value,
  };
}

function createApiClient(basePath) {
  const client = axios.create({
    baseURL: `${API_ROOT}${basePath}`,
    withCredentials: true,
    headers: {
      Accept: 'application/json',
    },
  });

  client.interceptors.request.use((config) => {
    const method = config.method?.toLowerCase();
    if (method && ['post', 'put', 'delete', 'patch'].includes(method)) {
      const csrfCredentials = getCsrfCredentials();
      const csrfToken = csrfCredentials?.token || getCookieValue('XSRF-TOKEN');
      if (csrfToken) {
        const headerName = csrfCredentials?.headerName || 'X-XSRF-TOKEN';
        config.headers = setRequestHeader(config.headers, headerName, csrfToken);
      }
    }

    return config;
  });

  client.interceptors.response.use(
    (response) => response,
    (error) => {
      if (error.response?.status === 401 && !window.location.pathname.startsWith('/login')) {
        sessionStorage.removeItem('auth_user');
        clearCsrfCredentials();
        window.location.assign('/login');
      }
      return Promise.reject(error);
    }
  );

  return client;
}

export const antivirusApi = createApiClient('/api/antivirus');
export const authApi = createApiClient('/api/auth');
export const networkSecurityApi = createApiClient('/api/network-security');
