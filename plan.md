# Authentication Implementation Plan

## Current State Analysis

### ✅ What's Working
- Google OAuth JWT token verification in backend (`auth.py`)
- User auto-creation on first login
- Basic login endpoint (`/login`)
- Stateless backend authentication with `get_current_user()` dependency

### ❌ What's Missing
- Frontend auth state management
- Protected routes/pages
- Token persistence across browser sessions
- Token refresh handling
- Logout functionality
- Auth error handling and user feedback

## Implementation Plan

### Phase 1: Frontend Auth Context & State Management

#### 1.1 Create Auth Context Provider
```javascript
// frontend/src/contexts/AuthContext.jsx
- AuthProvider component with token/user state
- useAuth hook for components
- Token storage in localStorage
- Login/logout methods
- Auto token validation on app load
```

#### 1.2 Update App Structure
```javascript
// frontend/src/App.jsx
- Wrap app with AuthProvider
- Add routing (React Router)
- Create protected route wrapper
- Handle initial auth state loading
```

#### 1.3 Auth Hook Implementation
```javascript
// frontend/src/hooks/useAuth.js
- useAuth() hook consuming AuthContext
- Methods: login(), logout(), isAuthenticated()
- Token expiry checking
- API call wrapper with auth headers
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

### Phase 4: Token Management & Security

#### 4.1 Frontend Token Handling
```javascript
// Token refresh strategy (if implementing refresh tokens)
// Auto-logout on token expiry
// Secure token storage considerations
// Clear tokens on logout
```

#### 4.2 API Client Layer
```javascript
// frontend/src/services/api.js
- Centralized API client
- Automatic auth header injection
- Error interceptors for 401/403
- Retry logic for expired tokens
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
- Implement AuthContext with token management
- Add localStorage persistence
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
- Implement automatic auth headers
- Add error handling for expired tokens

### Step 7: Polish UX
- Add loading states
- Implement proper error messaging
- Style components for better UX

## Key Design Decisions

### Authentication Strategy
- **Stateless**: Continue using Google JWT tokens (no refresh tokens initially)
- **Storage**: localStorage for token persistence
- **Validation**: Client-side expiry checking + server-side verification

### Route Protection
- **High-level**: Protect entire page components
- **Granular**: Individual API calls require valid tokens
- **Fallback**: Redirect to login page on auth failure

### Error Handling
- **401 Unauthorized**: Clear tokens, redirect to login
- **Network errors**: Show retry options
- **Token expiry**: Automatic logout with notification

## Security Considerations

### Token Security
- Store tokens in localStorage (acceptable for this use case)
- Clear tokens on logout
- Validate token expiry on each route change

### API Security
- All protected endpoints use `Depends(get_current_user)`
- CORS properly configured
- No sensitive data in frontend state

### Future Enhancements
- Consider refresh token implementation
- Add session timeout warnings
- Implement remember me functionality
- Add two-factor authentication option

## Testing Strategy

### Frontend Tests
- Auth context state management
- Protected route behavior
- Token expiry handling
- Login/logout flows

### Backend Tests
- Token validation edge cases
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
