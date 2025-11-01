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
- Backend creates secure sessions from Google JWT tokens via `/auth/login` endpoint
- User auto-creation on first login via session creation process
- Session-based authentication using httpOnly cookies (no Bearer tokens)

### Session Management Details
- **Session-based Design**: Server-side sessions with httpOnly cookies for security
- **Session Verification**: `get_current_user_from_session()` validates sessions on every request
- **Auto-User Creation**: New users are inserted into DB on first successful session creation
- **Session Lifecycle**: Sessions managed server-side with automatic cleanup and refresh
- **Protected Routes**: Any endpoint using `Depends(get_current_user_from_session)` requires valid session

### Session & Protected Page Patterns
- **Current State**: Secure server-side sessions with httpOnly cookies
- **Protected API Calls**: All use `credentials: 'include'` for cookie-based authentication
- **Frontend Protection**: Complete authentication state management with useAuth hook
- **Implemented Features**: Session refresh logic, frontend auth state management, protected route handling

### Database Architecture
- **Async-first**: All DB operations use `AsyncSession` and `await`
- **URL transformation**: `postgresql://` URLs automatically converted to `postgresql+asyncpg://` in `database.py`
- **User model**: Single `User` table with `google_sub` as unique identifier
- Tables auto-created on startup via `Base.metadata.create_all`

### Environment Configuration
- **Local dev**: Use `.env` files for both frontend and backend
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
// Frontend session-based authentication pattern
import { useAuth } from './hooks/useAuth';

const { user, login, logout, loading } = useAuth();

// Protected API call pattern
const apiCall = async (endpoint) => {
  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    credentials: 'include'  // Include httpOnly cookies
  });
  if (response.status === 401) {
    // Session expired - redirect to login
    logout();
  }
  return response;
};
```

```python
# Backend protected endpoint pattern
@app.get("/protected-data")
async def get_protected_data(current_user=Depends(get_current_user_from_session)):
    # current_user is automatically populated from valid session
    return {"data": "secret", "user_id": current_user["id"]}
```
