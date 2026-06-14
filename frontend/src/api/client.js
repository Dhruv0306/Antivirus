import axios from 'axios';

const API_ROOT = import.meta.env.VITE_API_URL || 'http://localhost:8080';

let runtimeCredentials = null;

export function setAuthCredentials(username, password) {
  runtimeCredentials = { username, password };
}

export function clearAuthCredentials() {
  runtimeCredentials = null;
}

function getCredentials() {
  if (runtimeCredentials) {
    return runtimeCredentials;
  }

  return null;
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
    const credentials = getCredentials();
    if (credentials) {
      config.auth = credentials;
    }
    return config;
  });

  client.interceptors.response.use(
    (response) => response,
    (error) => {
      if (error.response?.status === 401 && !window.location.pathname.startsWith('/login')) {
        sessionStorage.removeItem('auth_user');
        clearAuthCredentials();
        window.location.assign('/login');
      }
      return Promise.reject(error);
    }
  );

  return client;
}

export const antivirusApi = createApiClient('/api/antivirus');
export const networkSecurityApi = createApiClient('/api/network-security');
