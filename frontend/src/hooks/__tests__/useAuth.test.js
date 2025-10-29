/**
 * Basic tests for useAuth hook functionality
 * Note: These are minimal tests focusing on core functionality
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, act } from '@testing-library/react';
import { useAuth } from '../useAuth';

// Mock the API utility
vi.mock('../../utils/api', () => ({
  apiRequest: vi.fn(),
  apiRequestJson: vi.fn(),
}));

import { apiRequest, apiRequestJson } from '../../utils/api';

describe('useAuth Hook', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should initialize with loading state', async () => {
    // Mock successful auth check
    apiRequestJson.mockResolvedValueOnce({ id: 1, name: 'Test User', email: 'test@example.com' });

    const { result } = renderHook(() => useAuth());

    expect(result.current.loading).toBe(true);
    expect(result.current.user).toBe(null);
    expect(result.current.isAuthenticated).toBe(false);

    // Wait for the initial auth check to complete
    await act(async () => {
      await new Promise(resolve => setTimeout(resolve, 0));
    });
  });

  it('should handle successful login', async () => {
    const mockUser = { id: 1, name: 'Test User', email: 'test@example.com' };
    
    // Mock checkAuth call (initial load)
    apiRequestJson.mockResolvedValueOnce(mockUser);
    
    const { result } = renderHook(() => useAuth());

    // Mock login call
    apiRequestJson.mockResolvedValueOnce(mockUser);

    await act(async () => {
      const loginResult = await result.current.login('mock-google-token');
      expect(loginResult.success).toBe(true);
      expect(loginResult.user).toEqual(mockUser);
    });

    expect(apiRequestJson).toHaveBeenCalledWith('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ google_token: 'mock-google-token' }),
    });
  });

  it('should handle login failure', async () => {
    // Mock checkAuth call (initial load)
    apiRequestJson.mockRejectedValueOnce(new Error('Session expired'));
    
    const { result } = renderHook(() => useAuth());

    // Mock login failure
    apiRequestJson.mockRejectedValueOnce(new Error('Login failed'));

    await act(async () => {
      const loginResult = await result.current.login('invalid-token');
      expect(loginResult.success).toBe(false);
      expect(loginResult.error).toBe('Login failed');
    });
  });

  it('should handle logout', async () => {
    const mockUser = { id: 1, name: 'Test User', email: 'test@example.com' };
    
    // Mock checkAuth call (initial load)
    apiRequestJson.mockResolvedValueOnce(mockUser);
    
    const { result } = renderHook(() => useAuth());

    // Mock logout call
    apiRequest.mockResolvedValueOnce({});

    await act(async () => {
      const logoutResult = await result.current.logout();
      expect(logoutResult.success).toBe(true);
    });

    expect(apiRequest).toHaveBeenCalledWith('/auth/logout', {
      method: 'POST',
    });
  });

  it('should handle session refresh', async () => {
    const mockUser = { id: 1, name: 'Test User', email: 'test@example.com' };
    
    // Mock checkAuth call (initial load)
    apiRequestJson.mockResolvedValueOnce(mockUser);
    
    const { result } = renderHook(() => useAuth());

    // Mock refresh and subsequent checkAuth calls
    apiRequest.mockResolvedValueOnce({});
    apiRequestJson.mockResolvedValueOnce(mockUser);

    await act(async () => {
      const refreshResult = await result.current.refreshSession();
      expect(refreshResult.success).toBe(true);
    });

    expect(apiRequest).toHaveBeenCalledWith('/auth/refresh', {
      method: 'POST',
    });
  });
});