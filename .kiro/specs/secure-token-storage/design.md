# Secure Token Storage Design Document

## Overview

This design addresses the critical token storage vulnerability by replacing the current Bearer token approach with secure httpOnly cookie-based session management. The solution implements server-side session storage with proper cookie security attributes to prevent XSS-based token theft while maintaining the existing Google OAuth authentication flow.

## Architecture

### Current Architecture Issues
- Frontend receives Google OAuth token directly
- Token sent as Bearer header on each request
- No server-side session management
- Vulnerable to XSS attacks if token exposed to client-side JavaScript

### New Secure Architecture
```
[Google OAuth] → [Frontend] → [Backend Session Endpoint] → [httpOnly Cookie]
                                     ↓
[Protected Routes] ← [Session Validation] ← [Cookie-based Auth]
```

The new architecture introduces:
1. **Session Creation Endpoint**: Converts Google OAuth tokens to secure sessions
2. **Cookie-based Authentication**: Uses httpOnly cookies instead of Bearer tokens
3. **Server-side Session Store**: Maintains session state and token validation
4. **Automatic Session Management**: Handles token refresh and expiration

## Components and Interfaces

### 1. Session Manager (`backend/app/session.py`)

**Purpose**: Central session management with secure token storage

**Key Classes**:
```python
class SessionManager:
    async def create_session(self, google_token: str) -> str
    async def validate_session(self, session_id: str) -> dict
    async def refresh_session(self, session_id: str) -> bool
    async def invalidate_session(self, session_id: str) -> bool
    async def cleanup_expired_sessions(self) -> int

class SessionStore:
    # In-memory store with Redis option for production
    sessions: Dict[str, SessionData]
```

**Session Data Structure**:
```python
@dataclass
class SessionData:
    user_id: int
    google_token: str
    expires_at: datetime
    created_at: datetime
    last_accessed: datetime
```

### 2. Authentication Middleware (`backend/app/auth.py` - Updated)

**Purpose**: Cookie-based authentication replacement for Bearer token auth

**Key Functions**:
```python
async def get_current_user_from_session(request: Request, db=Depends(get_db)) -> dict
async def create_user_session(google_token: str, db=Depends(get_db)) -> str
async def logout_user_session(request: Request) -> bool
```

### 3. Session Endpoints (`backend/app/main.py` - Updated)

**New Endpoints**:
- `POST /auth/login` - Creates session from Google token
- `POST /auth/logout` - Invalidates session and clears cookies
- `GET /auth/me` - Returns current user from session
- `POST /auth/refresh` - Refreshes session if needed

### 4. Frontend Authentication Hook (`frontend/src/hooks/useAuth.js` - New)

**Purpose**: Manages authentication state without direct token access

**Key Functions**:
```javascript
export function useAuth() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  
  const login = async (googleToken) => { /* Session creation */ };
  const logout = async () => { /* Session invalidation */ };
  const checkAuth = async () => { /* Session validation */ };
  
  return { user, loading, login, logout, checkAuth };
}
```

## Data Models

### 1. Session Storage Schema

**In-Memory Session Store**:
```python
# Key: session_id (UUID)
# Value: SessionData object
{
  "session_123": {
    "user_id": 1,
    "google_token": "encrypted_token",
    "expires_at": "2024-01-01T12:00:00Z",
    "created_at": "2024-01-01T10:00:00Z",
    "last_accessed": "2024-01-01T11:30:00Z"
  }
}
```

### 2. Cookie Structure

**Authentication Cookie**:
```
Name: auth_session
Value: session_uuid
Attributes:
  - HttpOnly: true
  - Secure: true (HTTPS only)
  - SameSite: Strict
  - Path: /
  - Max-Age: 86400 (24 hours)
```

### 3. Database Schema Updates

**New Session Table** (Optional - for persistent sessions):
```sql
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id),
    google_token_hash VARCHAR(255),
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_accessed TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

## Error Handling

### 1. Session Validation Errors
- **Invalid Session**: Return 401 with generic message
- **Expired Session**: Attempt refresh, fallback to 401
- **Missing Cookie**: Return 401 for protected routes

### 2. Token Refresh Errors
- **Google Token Expired**: Clear session, require re-authentication
- **Network Errors**: Retry with exponential backoff
- **Invalid Refresh**: Clear session, require re-authentication

### 3. Security Error Handling
```python
# Generic error responses to prevent information leakage
try:
    session_data = await session_manager.validate_session(session_id)
except Exception as e:
    logger.warning(f"Session validation failed: {e}")
    raise HTTPException(status_code=401, detail="Authentication required")
```

## Testing Strategy

### 1. Unit Tests

**Session Manager Tests**:
- Session creation with valid Google tokens
- Session validation with various states
- Session expiration and cleanup
- Token refresh functionality

**Authentication Tests**:
- Cookie-based authentication flow
- Invalid session handling
- Session timeout scenarios

### 2. Integration Tests

**End-to-End Authentication Flow**:
- Google OAuth → Session Creation → Protected Route Access
- Logout flow with session cleanup
- Session expiration and refresh

**Security Tests**:
- XSS protection verification (no token access from JavaScript)
- CSRF protection with SameSite cookies
- Session hijacking prevention

### 3. Security Testing

**Cookie Security Validation**:
```javascript
// Verify tokens are not accessible from client-side
console.log(document.cookie); // Should not contain token data
console.log(localStorage.getItem('token')); // Should be null
```

**Session Management Testing**:
- Concurrent session handling
- Session cleanup on logout
- Expired session handling

## Implementation Phases

### Phase 1: Core Session Infrastructure
1. Create SessionManager class with in-memory storage
2. Implement session creation and validation
3. Add cookie utilities for secure cookie handling

### Phase 2: Authentication Integration
1. Update authentication middleware for cookie-based auth
2. Create new session endpoints
3. Modify existing login endpoint to use sessions

### Phase 3: Frontend Integration
1. Create useAuth hook for session management
2. Update App.jsx to use cookie-based authentication
3. Remove any localStorage token references

### Phase 4: Security Hardening
1. Add session cleanup background task
2. Implement session refresh logic
3. Add comprehensive error handling

## Security Considerations

### 1. Cookie Security
- **HttpOnly**: Prevents JavaScript access to authentication cookies
- **Secure**: Ensures cookies only sent over HTTPS
- **SameSite=Strict**: Prevents CSRF attacks

### 2. Session Management
- **Server-side Validation**: All session validation happens on the server
- **Token Encryption**: Google tokens encrypted before storage
- **Session Expiration**: Automatic cleanup of expired sessions

### 3. Error Handling
- **Generic Error Messages**: No sensitive information in error responses
- **Audit Logging**: Log authentication events without exposing tokens
- **Rate Limiting**: Prevent brute force attacks on session endpoints

## Migration Strategy

### 1. Backward Compatibility
- Keep existing Bearer token authentication during transition
- Gradual migration of endpoints to cookie-based auth
- Feature flag for authentication method selection

### 2. Deployment Steps
1. Deploy session infrastructure (no breaking changes)
2. Update frontend to use new authentication flow
3. Remove Bearer token support after verification
4. Clean up deprecated code

This design provides a comprehensive solution to the token storage vulnerability while maintaining the existing user experience and adding robust session management capabilities.