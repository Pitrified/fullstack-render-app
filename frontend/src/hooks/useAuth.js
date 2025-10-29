import { useState, useEffect, useCallback, useRef } from 'react';
import { apiRequest, apiRequestJson } from '../utils/api';

export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const initialCheckDone = useRef(false);

  // Login function that creates a session from Google token
  const login = useCallback(async (googleToken) => {
    try {
      setLoading(true);
      setError(null);

      const response = await apiRequestJson('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ google_token: googleToken }),
      });

      // Extract user data from response
      const userData = response.user || response;
      setUser(userData);
      return { success: true, user: userData };
    } catch (err) {
      const errorMessage = err.message || 'Network error during login';
      setError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  }, []);

  // Logout function that invalidates the session
  const logout = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      await apiRequest('/auth/logout', {
        method: 'POST',
      });

      // Clear user state regardless of response status
      setUser(null);
      return { success: true };
    } catch (err) {
      // Clear user state even if logout request fails
      setUser(null);
      return { success: true }; // Don't show error for logout failures
    } finally {
      setLoading(false);
    }
  }, []);

  // Check authentication status using session
  const checkAuth = useCallback(async (silent = false) => {
    try {
      setLoading(true);
      if (!silent) {
        setError(null);
      }

      const userData = await apiRequestJson('/auth/me', {
        method: 'GET',
      });

      setUser(userData);
      return { success: true, user: userData };
    } catch (err) {
      // Session expired, invalid, or network error
      setUser(null);
      
      // Only set error state if not silent and it's not a 401 (unauthorized)
      if (!silent && !err.message.includes('401')) {
        const errorMessage = 'Authentication check failed';
        setError(errorMessage);
        return { success: false, error: errorMessage };
      }
      
      // For 401s or silent checks, don't show error
      const errorMessage = err.message.includes('401') ? 'No active session' : 'Authentication check failed';
      return { success: false, error: errorMessage };
    } finally {
      setLoading(false);
    }
  }, []);

  // Refresh session if needed
  const refreshSession = useCallback(async () => {
    try {
      await apiRequest('/auth/refresh', {
        method: 'POST',
      });

      // Session refreshed successfully, check auth status
      try {
        const userData = await apiRequestJson('/auth/me', {
          method: 'GET',
        });
        setUser(userData);
        return { success: true, user: userData };
      } catch (err) {
        setUser(null);
        return { success: false, error: 'Authentication check failed after refresh' };
      }
    } catch (err) {
      // Refresh failed, user needs to login again
      setUser(null);
      return { success: false, error: 'Session refresh failed' };
    }
  }, []);

  // Check authentication status on hook initialization (silently)
  useEffect(() => {
    if (initialCheckDone.current) return;
    
    const initialAuthCheck = async () => {
      try {
        initialCheckDone.current = true;
        setLoading(true);
        
        const userData = await apiRequestJson('/auth/me', {
          method: 'GET',
        });

        setUser(userData);
      } catch (err) {
        // Session expired, invalid, or network error - this is expected on first load
        setUser(null);
      } finally {
        setLoading(false);
      }
    };

    initialAuthCheck();
  }, []); // Empty dependency array - only run once on mount

  // Auto-refresh session when user becomes active (optional enhancement)
  // Temporarily disabled to debug infinite loop issues
  // useEffect(() => {
  //   const handleVisibilityChange = async () => {
  //     if (!document.hidden && user) {
  //       try {
  //         const userData = await apiRequestJson('/auth/me', {
  //           method: 'GET',
  //         });
  //         setUser(userData);
  //       } catch (err) {
  //         setUser(null);
  //       }
  //     }
  //   };

  //   document.addEventListener('visibilitychange', handleVisibilityChange);
  //   return () => {
  //     document.removeEventListener('visibilitychange', handleVisibilityChange);
  //   };
  // }, [user]);

  return {
    user,
    loading,
    error,
    login,
    logout,
    checkAuth,
    refreshSession,
    isAuthenticated: !!user,
  };
}