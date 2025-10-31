# Project Structure

## Root Level Organization
```
├── backend/           # FastAPI Python backend
├── frontend/          # React Vite frontend
├── .kiro/            # Kiro AI assistant configuration
├── render.yaml       # Render.com deployment configuration
├── vulnerabilities.md # Security assessment documentation
└── README.md         # Project documentation
```

## Backend Structure (`backend/`)
```
backend/
├── app/
│   ├── main.py           # FastAPI application entry point
│   ├── config.py         # Environment configuration management
│   ├── database.py       # Database connection and setup
│   ├── models.py         # SQLAlchemy database models
│   ├── auth.py           # Google OAuth authentication logic
│   ├── session.py        # Session management and cookies
│   ├── rate_limiter.py   # Custom rate limiting implementation
│   ├── secure_logger.py  # Secure logging infrastructure
│   └── security_logger.py # Security event logging
├── tests/
│   ├── conftest.py       # Pytest configuration and fixtures
│   ├── test_auth_endpoints.py
│   ├── test_rate_limiting.py
│   ├── test_security.py
│   └── test_session.py
├── requirements.txt      # Python dependencies
├── requirements_frozen.txt # Locked dependencies for production
├── .env.example         # Environment variables template
└── venv/               # Python virtual environment
```

## Frontend Structure (`frontend/`)
```
frontend/
├── src/
│   ├── App.jsx          # Main React application component
│   ├── main.jsx         # React application entry point
│   ├── hooks/
│   │   ├── useAuth.js   # Authentication state management
│   │   └── useGoogleIdentity.js # Google Identity integration
│   ├── utils/
│   │   ├── api.js       # API communication utilities
│   │   └── sanitize.js  # Input sanitization with DOMPurify
│   └── __tests__/       # Component and utility tests
├── dist/               # Production build output
├── package.json        # Node.js dependencies and scripts
├── vite.config.js      # Vite build configuration
├── vitest.config.js    # Vitest testing configuration
└── .env.example        # Environment variables template
```

## Key Architectural Patterns

### Backend Patterns
- **Dependency Injection**: FastAPI's `Depends()` for database and auth
- **Async/Await**: All database operations use async SQLAlchemy
- **Middleware Pattern**: CORS, security headers, rate limiting
- **Repository Pattern**: Database operations abstracted in models
- **Configuration Management**: Centralized in `config.py`

### Frontend Patterns
- **Custom Hooks**: `useAuth`, `useGoogleIdentity` for state management
- **Utility Functions**: Centralized API calls and sanitization
- **Component Composition**: Single-responsibility components
- **Security-First**: All user input sanitized through DOMPurify

### Security Architecture
- **Layered Security**: Frontend sanitization + backend validation
- **Session Management**: Server-side sessions with httpOnly cookies
- **Rate Limiting**: IP-based throttling on authentication endpoints
- **Secure Logging**: PII redaction and structured security events

## File Naming Conventions
- **Backend**: Snake_case for Python files (`rate_limiter.py`)
- **Frontend**: camelCase for JavaScript files (`useAuth.js`)
- **Components**: PascalCase for React components (`App.jsx`)
- **Tests**: Prefix with `test_` for backend, suffix with `.test.js` for frontend

## Environment Files
- **Development**: `.env` files in both `backend/` and `frontend/`
- **Production**: Environment variables managed by Render.com
- **Templates**: `.env.example` files show required variables
- **Security**: Never commit actual `.env` files (in `.gitignore`)

## Deployment Structure
- **Backend**: Deployed as web service on Render.com
- **Frontend**: Deployed as static site on Render.com
- **Database**: Managed PostgreSQL service on Render.com
- **Configuration**: `render.yaml` defines all services and connections