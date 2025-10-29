/**
 * Basic tests for App component authentication flow
 * Note: These are minimal tests focusing on core functionality
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from '../App';

// Mock the hooks
vi.mock('../hooks/useGoogleIdentity', () => ({
  useGoogleIdentity: vi.fn(() => true),
}));

vi.mock('../hooks/useAuth', () => ({
  useAuth: vi.fn(),
}));

vi.mock('../utils/sanitize', () => ({
  sanitizeUserData: vi.fn((data) => data),
}));

import { useAuth } from '../hooks/useAuth';

// Mock Google Identity Services
global.window.google = {
  accounts: {
    id: {
      initialize: vi.fn(),
      renderButton: vi.fn(),
    },
  },
};

describe('App Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock getElementById
    document.getElementById = vi.fn(() => ({ appendChild: vi.fn() }));
  });

  it('should show loading state when authentication is loading', () => {
    useAuth.mockReturnValue({
      user: null,
      loading: true,
      error: null,
      login: vi.fn(),
      logout: vi.fn(),
      isAuthenticated: false,
    });

    render(<App />);
    
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  it('should show login button when user is not authenticated', () => {
    useAuth.mockReturnValue({
      user: null,
      loading: false,
      error: null,
      login: vi.fn(),
      logout: vi.fn(),
      isAuthenticated: false,
    });

    render(<App />);
    
    expect(screen.getByText('Login with Google')).toBeInTheDocument();
    expect(screen.queryByText('Welcome!')).not.toBeInTheDocument();
  });

  it('should show user info when authenticated', () => {
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
    
    expect(screen.getByText('Welcome!')).toBeInTheDocument();
    expect(screen.getByText('Test User')).toBeInTheDocument();
    expect(screen.getByText('test@example.com')).toBeInTheDocument();
    expect(screen.getByText('Logout')).toBeInTheDocument();
  });

  it('should show error message when there is an authentication error', () => {
    useAuth.mockReturnValue({
      user: null,
      loading: false,
      error: 'Authentication failed',
      login: vi.fn(),
      logout: vi.fn(),
      isAuthenticated: false,
    });

    render(<App />);
    
    expect(screen.getByText('Authentication failed')).toBeInTheDocument();
  });
});