# Copilot Instructions - Fullstack Google OAuth App

## Architecture Overview

This is a **fullstack Google OAuth application** with clear service boundaries:
- **Frontend**: React + Vite static site (`frontend/`) serving Google OAuth login UI
- **Backend**: FastAPI async API (`backend/app/`) handling OAuth verification and user persistence  
- **Database**: PostgreSQL with async SQLAlchemy models
- **Deployment**: Render.com with internal service networking via `render.yaml`

## Key Patterns & Conventions

### Authentication Flow
- Frontend uses Google Identity Services to get JWT tokens (`useGoogleIdentity` hook in `src/hooks/`)
- Backend verifies Google JWT tokens using `google.oauth2.id_token.verify_oauth2_token()` in `auth.py`
- User auto-creation on first login via `get_current_user()` dependency
- Bearer token passed via `Authorization` header for API calls

### OAuth Verification Details
- **Stateless Design**: No server-side sessions - each request carries Google JWT token
- **Token Verification**: `get_current_user()` validates token signature, expiry, and audience on every request
- **Auto-User Creation**: New users are inserted into DB on first successful OAuth verification
- **Token Lifecycle**: Google JWTs are short-lived (1 hour) - frontend should handle re-authentication
- **Protected Routes**: Any endpoint using `Depends(get_current_user)` automatically requires valid Google token

### Session & Protected Page Patterns
- **Current State**: No persistent sessions - token must be stored/managed by frontend (localStorage, state, etc.)
- **Protected API Calls**: All require `Authorization: Bearer {google_jwt_token}` header
- **Frontend Protection**: Currently no route protection - App.jsx only shows login UI
- **Missing Pieces**: No token refresh logic, no frontend auth state management, no protected route components

### Database Architecture
- **Async-first**: All DB operations use `AsyncSession` and `await`
- **URL transformation**: `postgresql://` URLs automatically converted to `postgresql+asyncpg://` in `database.py`
- **User model**: Single `User` table with `google_sub` as unique identifier
- Tables auto-created on startup via `Base.metadata.create_all`

### Environment Configuration
- **Local dev**: Use `.env.local` files (frontend) and `.env` files (backend)
- **Render deployment**: Environment variables configured in `render.yaml` and Render dashboard
- **API communication**: 
  - Local: `VITE_API_BASE_URL=http://localhost:8000`
  - Production: Uses Render internal hostname `http://fastapi-backend:8000`

### Development Workflow
```bash
# Backend (port 8000)
cd backend && python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload

# Frontend (port 5173)  
cd frontend && npm install && npm run dev
```

## Critical Files

- `render.yaml`: Defines entire deployment architecture including internal networking
- `backend/app/auth.py`: Core Google OAuth verification logic
- `backend/app/database.py`: Async SQLAlchemy setup with URL transformation
- `frontend/src/hooks/useGoogleIdentity.js`: Google Identity Services integration
- `backend/app/main.py`: CORS configuration with specific allowed origins

## Integration Points

- **CORS**: Explicitly configured for localhost:5173 and Render frontend domain
- **Google OAuth**: Requires `GOOGLE_CLIENT_ID` in backend and `VITE_GOOGLE_CLIENT_ID` in frontend
- **Service communication**: Frontend -> Backend via internal Render networking (no external URLs)
- **Database**: PostgreSQL connection managed via `DATABASE_URL` from Render's managed database

## When Making Changes

- **Adding endpoints**: Use async functions with `Depends(get_current_user)` for auth
- **Database changes**: Modify `models.py` and rely on startup auto-creation (no migrations)
- **Environment vars**: Update both `render.yaml` and local `.env.example` files
- **Frontend API calls**: Always use `API_BASE_URL` env var, never hardcode URLs

### Implementing Protected Pages
```javascript
// Frontend token storage pattern
const [user, setUser] = useState(null);
const [token, setToken] = useState(localStorage.getItem('google_token'));

// Protected API call pattern
const apiCall = async (endpoint) => {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (response.status === 401) {
    // Token expired - redirect to login
    setUser(null);
    setToken(null);
    localStorage.removeItem('google_token');
  }
  return response;
};
```

```python
# Backend protected endpoint pattern
@app.get("/protected-data")
async def get_protected_data(current_user=Depends(get_current_user)):
    # current_user is automatically populated from valid Google JWT
    return {"data": "secret", "user_id": current_user["id"]}
```
