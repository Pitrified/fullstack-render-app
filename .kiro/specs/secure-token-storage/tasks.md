# Implementation Plan

- [x] 1. Create core session management infrastructure

  - Implement SessionManager class with in-memory session storage
  - Create SessionData dataclass for session information
  - Add session creation, validation, and cleanup methods
  - _Requirements: 1.1, 3.3, 3.4_

- [x] 1.1 Implement SessionManager class

  - Create `backend/app/session.py` with SessionManager and SessionData classes
  - Implement create_session, validate_session, refresh_session, and invalidate_session methods
  - Add session expiration and cleanup functionality
  - _Requirements: 1.1, 3.3, 3.4_

- [x] 1.2 Add secure cookie utilities

  - Create cookie helper functions for setting httpOnly, Secure, and SameSite attributes
  - Implement cookie creation and deletion utilities
  - Add session ID generation using secure random methods
  - _Requirements: 1.1, 1.2, 1.3, 4.1_

- [x] 1.3 Write unit tests for session management

  - Create tests for SessionManager session lifecycle operations
  - Test session expiration and cleanup functionality
  - Verify secure session ID generation
  - _Requirements: 1.1, 3.3, 3.4_

- [x] 2. Update authentication system for cookie-based sessions

  - Create new session-based authentication endpoints
  - Update authentication middleware to support cookie-based sessions
  - Replace Bearer token authentication with session validation
  - _Requirements: 1.4, 2.3, 2.4, 4.4_

- [x] 2.1 Create session authentication endpoints

  - Add POST /auth/login endpoint that creates sessions from Google tokens and sets httpOnly cookies
  - Add POST /auth/logout endpoint that invalidates sessions and clears cookies
  - Add GET /auth/me endpoint that returns current user from session
  - Add POST /auth/refresh endpoint for session refresh
  - _Requirements: 1.1, 3.2, 3.5_

- [x] 2.2 Update authentication middleware

  - Create get_current_user_from_session function to validate sessions from cookies
  - Add session-based user retrieval and validation
  - Implement proper error handling for invalid or expired sessions
  - Keep existing get_current_user for backward compatibility during transition
  - _Requirements: 2.3, 2.4, 4.2, 4.3_

- [x] 2.3 Initialize session manager in main.py

  - Import and initialize the global session_manager
  - Start the session cleanup background task on application startup
  - Update CORS middleware to allow credentials for cookie-based authentication
  - _Requirements: 3.4, 4.5_

- [x] 2.4 Write integration tests for authentication endpoints

  - Test complete authentication flow from Google OAuth to session creation
  - Test session validation and user retrieval
  - Test logout flow and session cleanup
  - _Requirements: 1.1, 2.3, 3.2_

- [x] 3. Update frontend to use cookie-based authentication

  - Create new authentication hook that manages sessions without direct token access
  - Update App.jsx to use cookie-based authentication flow
  - Remove direct token handling and implement cookie-based session management
  - _Requirements: 1.4, 1.5, 2.5_

- [x] 3.1 Create useAuth hook for session management

  - Create `frontend/src/hooks/useAuth.js` with session-based authentication
  - Implement login, logout, and authentication state management using session endpoints
  - Add automatic session validation and refresh handling
  - Handle authentication state without direct token access
  - _Requirements: 1.5, 2.1, 2.2, 2.5_

- [x] 3.2 Update App.jsx for cookie-based authentication

  - Replace current authentication flow to use new useAuth hook
  - Update login handler to call session creation endpoint with credentials: 'include'
  - Remove direct token handling from handleCredentialResponse
  - Update logout functionality to call session invalidation endpoint
  - _Requirements: 1.4, 1.5, 3.2_

- [x] 3.3 Add session state management

  - Implement automatic session validation on app startup using /auth/me endpoint
  - Add session refresh handling for expired sessions
  - Update all API calls to include credentials: 'include' for cookie support
  - _Requirements: 2.1, 2.2, 3.2_

- [x] 3.4 Write frontend authentication tests

  - Test useAuth hook functionality and state management
  - Test authentication flow integration with backend sessions
  - Test session expiration and refresh handling
  - _Requirements: 2.1, 2.2, 2.5_

- [x] 4. Add security hardening and cleanup

  - Add comprehensive error handling with generic messages
  - Remove deprecated Bearer token authentication code after migration
  - Implement additional security measures and testing
  - _Requirements: 3.4, 4.2, 4.3, 4.5_

- [x] 4.1 Remove deprecated authentication code

  - Remove Bearer token authentication function (get_current_user) from auth.py
  - Remove the old /login endpoint that uses Bearer token authentication
  - Update documentation files to remove localStorage and Bearer token references
  - _Requirements: 1.4, 4.2_

- [x] 4.2 Update documentation to reflect secure token storage

  - Update plan.md to remove localStorage references and update authentication strategy
  - Update .github/copilot-instructions.md to reflect session-based authentication
  - Update vulnerabilities.md to mark token storage vulnerability as resolved
  - _Requirements: 1.4, 4.2_

- [x] 4.3 Add comprehensive security tests

  - Test XSS protection by verifying tokens are not accessible from JavaScript
  - Test CSRF protection with SameSite cookie attributes
  - Test session hijacking prevention and security headers
  - _Requirements: 1.2, 1.3, 4.1_

- [x] 4.4 Add security error handling improvements

  - Update all authentication error responses to use generic messages
  - Add proper logging for security events without exposing sensitive data
  - Implement consistent error handling across all session endpoints
  - _Requirements: 4.2, 4.3, 4.5_

- [x] 4.5 Add rate limiting protection

  - Implement rate limiting for authentication endpoints
  - Add protection against brute force attacks on session endpoints
  - Configure appropriate rate limits for login attempts
  - _Requirements: 4.2, 4.5_

- [x] 5. Final cleanup and documentation polish

  - Clean up remaining localStorage references in plan.md
  - Verify all security requirements are fully implemented
  - Ensure all documentation reflects the secure session-based implementation
  - _Requirements: 1.4, 4.2_

- [x] 5.1 Clean up plan.md localStorage references

  - Remove outdated localStorage references from implementation plan
  - Update authentication strategy section to reflect session-based approach
  - Ensure all documentation is consistent with secure implementation
  - _Requirements: 1.4, 4.2_
