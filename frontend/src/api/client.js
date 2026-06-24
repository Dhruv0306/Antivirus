import axios from 'axios';

const API_ROOT = import.meta.env.VITE_API_URL || 'http://localhost:8080';

let runtimeCsrf = null;

export function setCsrfCredentials(csrf) {
  runtimeCsrf = csrf;
}

export function clearCsrfCredentials() {
  runtimeCsrf = null;
}

function getCsrfCredentials() {
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
