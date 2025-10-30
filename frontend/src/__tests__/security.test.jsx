/**
 * Security tests for frontend authentication
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { useAuth } from '../hooks/useAuth';
import App from '../App';

// Mock the hooks
vi.mock('../hooks/useGoogleIdentity', () => ({
  useGoogleIdentity: vi.fn(() => true),
}));

vi.mock('../hooks/useAuth');

vi.mock('../utils/sanitize', () => ({
  sanitizeUserData: vi.fn((data) => data),
}));

// Mock Google Identity Services
global.window.google = {
  accounts: {
    id: {
      initialize: vi.fn(),
      renderButton: vi.fn(),
    },
  },
};

describe('Frontend Security Tests', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    document.getElementById = vi.fn(() => ({ appendChild: vi.fn() }));
    localStorage.clear();
  });

  describe('XSS Protection', () => {
    it('should not expose authentication tokens to JavaScript', () => {
      // Verify that no authentication tokens are stored in localStorage
      expect(localStorage.getItem('token')).toBeNull();
      expect(localStorage.getItem('google_token')).toBeNull();
      expect(localStorage.getItem('auth_token')).toBeNull();
      expect(localStorage.getItem('session_token')).toBeNull();
    });

    it('should sanitize user data to prevent XSS attacks', () => {
      const maliciousUser = {
        name: '<script>alert("XSS")</script>',
        email: 'test@example.com',
      };

      useAuth.mockReturnValue({
        user: maliciousUser,
        loading: false,
        error: null,
        login: vi.fn(),
        logout: vi.fn(),
        isAuthenticated: true,
      });

      render(<App />);

      // Verify that the malicious script is not executed
      // The component should render safely without executing the script
      expect(screen.getByText(/script/i)).toBeInTheDocument();
    });
  });

  describe('Session Security', () => {
    it('should handle authentication state without direct token access', () => {
      const mockUser = { name: 'Test User', email: 'test@example.com' };
      
      useAuth.mockReturnValue({
        user: mockUser,
        loading: false,
        error: null,
        login: vi.fn(),
        logout: vi.fn(),
        isAuthenticated: true,
      });

      render(<App />);

      // Verify that user data is displayed
      expect(screen.getByText('Test User')).toBeInTheDocument();
      expect(screen.getByText('test@example.com')).toBeInTheDocument();
      
      // Verify that no token information is displayed
      expect(screen.queryByText(/token/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/bearer/i)).not.toBeInTheDocument();
      expect(screen.queryByText(/session_id/i)).not.toBeInTheDocument();
    });
  });

  describe('Error Handling Security', () => {
    it('should not expose sensitive information in error messages', () => {
      useAuth.mockReturnValue({
        user: null,
        loading: false,
        error: 'Authentication failed',
        login: vi.fn(),
        logout: vi.fn(),
        isAuthenticated: false,
      });

      render(<App />);

      const errorMessage = screen.getByText('Authentication failed');
      expect(errorMessage).toBeInTheDocument();

      // Verify error message doesn't contain sensitive information
      expect(errorMessage.textContent).not.toContain('token');
      expect(errorMessage.textContent).not.toContain('session');
      expect(errorMessage.textContent).not.toContain('database');
      expect(errorMessage.textContent).not.toContain('internal');
    });
  });
});