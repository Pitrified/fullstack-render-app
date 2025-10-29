const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

/**
 * Make an authenticated API request with credentials included
 * @param {string} endpoint - API endpoint (without base URL)
 * @param {object} options - Fetch options
 * @returns {Promise<Response>} - Fetch response
 */
export async function apiRequest(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  
  const defaultOptions = {
    credentials: 'include', // Always include cookies for session-based auth
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
  };

  const mergedOptions = {
    ...defaultOptions,
    ...options,
    headers: {
      ...defaultOptions.headers,
      ...options.headers,
    },
  };

  return fetch(url, mergedOptions);
}

/**
 * Make an authenticated API request and parse JSON response
 * @param {string} endpoint - API endpoint (without base URL)
 * @param {object} options - Fetch options
 * @returns {Promise<object>} - Parsed JSON response
 * @throws {Error} - If request fails or response is not ok
 */
export async function apiRequestJson(endpoint, options = {}) {
  const response = await apiRequest(endpoint, options);
  
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({ 
      detail: `Request failed with status ${response.status}` 
    }));
    throw new Error(errorData.detail || `Request failed with status ${response.status}`);
  }
  
  return response.json();
}