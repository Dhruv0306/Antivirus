import axios from 'axios';

const API_ROOT = process.env.REACT_APP_API_URL || 'http://localhost:8080';
const API_USERNAME = process.env.REACT_APP_API_USERNAME;
const API_PASSWORD = process.env.REACT_APP_API_PASSWORD;

function createApiClient(basePath) {
  const client = axios.create({
    baseURL: `${API_ROOT}${basePath}`,
    withCredentials: true,
    headers: {
      Accept: 'application/json',
    },
  });

  if (API_USERNAME && API_PASSWORD) {
    client.interceptors.request.use((config) => {
      config.auth = {
        username: API_USERNAME,
        password: API_PASSWORD,
      };
      return config;
    });
  }

  return client;
}

export const antivirusApi = createApiClient('/api/antivirus');
export const networkSecurityApi = createApiClient('/api/network-security');
