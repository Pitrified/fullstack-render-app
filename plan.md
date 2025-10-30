# Authentication Implementation Plan

## Current State Analysis

### ✅ What's Working
- Google OAuth JWT token verification in backend (`auth.py`)
- User auto-creation on first login
- Session-based authentication with httpOnly cookies
- Secure token storage using server-side sessions
- Session management endpoints (`/auth/login`, `/auth/logout`, `/auth/me`)

### ✅ Recently Implemented
- Frontend auth state management with useAuth hook
- Protected routes/pages
- Secure session persistence across browser sessions
- Session refresh handling
- Logout functionality with session cleanup
- Comprehensive auth error handling and user feedback

## Implementation Plan

### Phase 1: Frontend Auth Context & State Management ✅ COMPLETED

#### 1.1 Create Auth Context Provider ✅
```javascript
// frontend/src/hooks/useAuth.js
- useAuth hook with session-based authentication
- Secure session management without direct token access
- Login/logout methods using session endpoints
- Auto session validation on app load
```

#### 1.2 Update App Structure ✅
```javascript
// frontend/src/App.jsx
- Updated to use session-based authentication
- Handles authentication state with cookies
- Secure login/logout flow
- Session state management
```

#### 1.3 Auth Hook Implementation ✅
```javascript
// frontend/src/hooks/useAuth.js
- useAuth() hook with session management
- Methods: login(), logout(), checkAuth()
- Session validation and refresh
- API call wrapper with credentials: 'include'
```

### Phase 2: Protected Routes & Components

#### 2.1 Route Protection
```javascript
// frontend/src/components/ProtectedRoute.jsx
- Component that checks auth state
- Redirects to login if not authenticated
- Shows loading state during auth check
```

#### 2.2 Create Page Components
```javascript
// frontend/src/pages/LoginPage.jsx
- Move login logic from App.jsx
- Handle login success/error states
- Redirect after successful login

// frontend/src/pages/DashboardPage.jsx
- Protected page showing user info
- Example of authenticated content
- Logout button

// frontend/src/pages/ProfilePage.jsx
- Another protected page example
- Display user data from backend
```

#### 2.3 Navigation Component
```javascript
// frontend/src/components/Navbar.jsx
- Show different nav items based on auth state
- User avatar/name when logged in
- Logout button
```

### Phase 3: Enhanced Backend Endpoints

#### 3.1 User Management Endpoints
```python
# backend/app/main.py additions
@app.get("/user/profile")  # Get current user profile
@app.put("/user/profile")  # Update user profile
@app.get("/user/dashboard")  # Dashboard data
@app.post("/auth/logout")  # Optional logout endpoint
```

#### 3.2 Error Handling Improvements
```python
# backend/app/auth.py enhancements
- Better error messages for token validation
- Structured error responses
- Token expiry specific handling
```

### Phase 4: Session Management & Security ✅ COMPLETED

#### 4.1 Frontend Session Handling ✅
```javascript
// Session-based authentication (no direct token access)
// Auto-logout on session expiry
// Secure httpOnly cookie storage
// Session cleanup on logout
```

#### 4.2 API Client Layer ✅
```javascript
// frontend/src/utils/api.js
- Centralized API client with credentials: 'include'
- Automatic session validation
- Error interceptors for 401/403
- Session refresh handling
```

### Phase 5: User Experience Enhancements

#### 5.1 Loading & Error States
```javascript
// Loading spinners during auth operations
// Error messages for auth failures
// Success feedback for login/logout
// Skeleton screens for protected content
```

#### 5.2 Session Persistence
```javascript
// Remember user across browser sessions
// Optional "Remember me" functionality
// Graceful handling of expired sessions
```

## File Structure After Implementation

```
frontend/src/
├── components/
│   ├── Navbar.jsx
│   ├── ProtectedRoute.jsx
│   └── LoadingSpinner.jsx
├── contexts/
│   └── AuthContext.jsx
├── hooks/
│   ├── useAuth.js
│   └── useGoogleIdentity.js (existing)
├── pages/
│   ├── LoginPage.jsx
│   ├── DashboardPage.jsx
│   └── ProfilePage.jsx
├── services/
│   └── api.js
└── App.jsx (updated)
```

## Implementation Steps

### Step 1: Install Dependencies
```bash
cd frontend
npm install react-router-dom
```

### Step 2: Create Auth Context
- Implement AuthContext with session management
- Add secure httpOnly cookie persistence
- Create useAuth hook

### Step 3: Add Routing
- Install and configure React Router
- Create route structure with protection
- Implement ProtectedRoute component

### Step 4: Create Page Components
- Build LoginPage, DashboardPage, ProfilePage
- Move login logic from App.jsx to LoginPage
- Add navigation between pages

### Step 5: Enhance Backend
- Add user profile endpoints
- Improve error handling in auth.py
- Add dashboard data endpoint

### Step 6: API Integration
- Create centralized API client
- Implement automatic session credentials
- Add error handling for expired sessions

### Step 7: Polish UX
- Add loading states
- Implement proper error messaging
- Style components for better UX

## Key Design Decisions

### Authentication Strategy
- **Session-based**: Using server-side session management with httpOnly cookies
- **Storage**: Secure httpOnly cookies (not accessible to JavaScript)
- **Validation**: Server-side session validation with automatic cleanup

### Route Protection
- **High-level**: Protect entire page components
- **Granular**: Individual API calls require valid tokens
- **Fallback**: Redirect to login page on auth failure

### Error Handling
- **401 Unauthorized**: Clear sessions, redirect to login
- **Network errors**: Show retry options
- **Session expiry**: Automatic logout with notification

## Security Considerations

### Session Security
- Store session IDs in httpOnly cookies (not accessible to JavaScript)
- Clear sessions on logout with server-side cleanup
- Validate sessions on each authenticated request

### API Security
- All protected endpoints use `Depends(get_current_user_from_session)`
- CORS properly configured with credentials support
- No sensitive data in frontend state or localStorage

### Future Enhancements
- Consider refresh token implementation
- Add session timeout warnings
- Implement remember me functionality
- Add two-factor authentication option

## Testing Strategy

### Frontend Tests
- Auth context state management
- Protected route behavior
- Session expiry handling
- Login/logout flows

### Backend Tests
- Session validation edge cases
- Protected endpoint access
- User creation/retrieval
- Error response formats

## Success Criteria

### Must Have
- ✅ Users can log in with Google OAuth
- ✅ Protected pages require authentication
- ✅ Users stay logged in across browser sessions
- ✅ Clear logout functionality
- ✅ Proper error handling for auth failures

### Nice to Have
- ✅ Smooth loading states during auth operations
- ✅ User profile management
- ✅ Multiple protected pages demonstrating auth patterns
- ✅ Responsive design for all auth components
