/**
 * Secure authentication hook using httpOnly cookies and CSRF protection.
 * 
 * This hook replaces the vulnerable localStorage token storage with secure
 * session management via httpOnly cookies. It provides:
 * 
 * - Automatic session restoration on page load
 * - Secure login/logout with session cookies
 * - CSRF token management for state-changing operations
 * - Session refresh functionality
 * - Automatic token cleanup on errors
 */

import { useState, useEffect, useCallback } from 'react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL;

export function useSecureAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [csrfToken, setCsrfToken] = useState(null);
  const [error, setError] = useState(null);

  /**
   * Get CSRF token from cookie for API requests
   */
  const getCsrfTokenFromCookie = useCallback(() => {
    const cookies = document.cookie.split(';');
    const csrfCookie = cookies.find(cookie => 
      cookie.trim().startsWith('csrf_token=')
    );
    return csrfCookie ? csrfCookie.split('=')[1] : null;
  }, []);

  /**
   * Make authenticated API request with CSRF protection
   */
  const makeAuthenticatedRequest = useCallback(async (url, options = {}) => {
    const csrfToken = getCsrfTokenFromCookie();
    
    const requestOptions = {
      ...options,
      credentials: 'include', // Include httpOnly cookies
      headers: {
        'Content-Type': 'application/json',
        ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
        ...options.headers,
      },
    };

    try {
      const response = await fetch(`${API_BASE_URL}${url}`, requestOptions);
      
      // Handle authentication errors
      if (response.status === 401) {
        setUser(null);
        setCsrfToken(null);
        setError('Session expired. Please log in again.');
        return null;
      }
      
      // Handle CSRF errors
      if (response.status === 403) {
        setError('Security validation failed. Please refresh the page.');
        return null;
      }
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }
      
      return response;
    } catch (err) {
      console.error('API request failed:', err);
      setError('Network error. Please check your connection.');
      return null;
    }
  }, [getCsrfTokenFromCookie]);

  /**
   * Check if user has an active session on page load
   */
  const checkSession = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await makeAuthenticatedRequest('/auth/me');
      
      if (response && response.ok) {
        const data = await response.json();
        setUser(data.user);
        setCsrfToken(getCsrfTokenFromCookie());
      } else {
        setUser(null);
        setCsrfToken(null);
      }
    } catch (err) {
      console.error('Session check failed:', err);
      setUser(null);
      setCsrfToken(null);
    } finally {
      setLoading(false);
    }
  }, [makeAuthenticatedRequest, getCsrfTokenFromCookie]);

  /**
   * Secure login using Google OAuth token
   */
  const login = useCallback(async (googleToken) => {
    setLoading(true);
    setError(null);
    
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        credentials: 'include', // Include cookies
        headers: {
          'Authorization': `Bearer ${googleToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (response.ok) {
        const data = await response.json();
        setUser(data.user);
        setCsrfToken(data.csrf_token);
        setError(null);
        
        console.log('Secure login successful');
        return { success: true, user: data.user };
      } else {
        const errorData = await response.json().catch(() => ({}));
        const errorMessage = errorData.detail || 'Login failed';
        setError(errorMessage);
        return { success: false, error: errorMessage };
      }
    } catch (err) {
      console.error('Login error:', err);
      const errorMessage = 'Network error during login';
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  }, []);

  /**
   * Secure logout that clears server session
   */
  const logout = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Call logout endpoint to clear server session
      await makeAuthenticatedRequest('/auth/logout', {
        method: 'POST',
      });
      
      // Clear client state regardless of server response
      setUser(null);
      setCsrfToken(null);
      
      console.log('Secure logout successful');
      return { success: true };
    } catch (err) {
      console.error('Logout error:', err);
      // Still clear client state even if server call fails
      setUser(null);
      setCsrfToken(null);
      return { success: true }; // Return success since client is cleared
    } finally {
      setLoading(false);
    }
  }, [makeAuthenticatedRequest]);

  /**
   * Refresh user session to extend expiry
   */
  const refreshSession = useCallback(async () => {
    try {
      const response = await makeAuthenticatedRequest('/auth/refresh', {
        method: 'POST',
      });
      
      if (response && response.ok) {
        const data = await response.json();
        setUser(data.user);
        setCsrfToken(data.csrf_token);
        console.log('Session refreshed successfully');
        return { success: true };
      } else {
        return { success: false, error: 'Session refresh failed' };
      }
    } catch (err) {
      console.error('Session refresh error:', err);
      return { success: false, error: 'Network error during refresh' };
    }
  }, [makeAuthenticatedRequest]);

  /**
   * Clear any error messages
   */
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Check for existing session on component mount
  useEffect(() => {
    checkSession();
  }, [checkSession]);

  // Auto-refresh session periodically (every 30 minutes)
  useEffect(() => {
    if (!user) return;
    
    const refreshInterval = setInterval(() => {
      if (user) {
        refreshSession();
      }
    }, 30 * 60 * 1000); // 30 minutes
    
    return () => clearInterval(refreshInterval);
  }, [user, refreshSession]);

  return {
    user,
    loading,
    error,
    csrfToken,
    login,
    logout,
    refreshSession,
    checkSession,
    clearError,
    makeAuthenticatedRequest,
    isAuthenticated: !!user,
  };
}
