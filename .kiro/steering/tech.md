# Technology Stack

## Architecture

**Fullstack Application**: React frontend + FastAPI backend + PostgreSQL database

## Backend Stack

- **Framework**: FastAPI (Python async web framework)
- **Database**: PostgreSQL with SQLAlchemy ORM (async)
- **Authentication**: Google OAuth 2.0 with server-side sessions
- **Security**: Custom rate limiting, secure logging, input validation
- **Deployment**: Uvicorn ASGI server

## Frontend Stack

- **Framework**: React 18 with Vite build tool
- **Security**: DOMPurify for XSS protection
- **State Management**: React hooks (useState, useEffect)
- **Testing**: Vitest with Testing Library
- **Deployment**: Static site generation

## Key Dependencies

### Backend (`backend/requirements.txt`)

```
fastapi          # Web framework
uvicorn          # ASGI server
sqlalchemy       # ORM with async support
asyncpg          # PostgreSQL async driver
google-auth      # Google OAuth validation
python-dotenv    # Environment configuration
requests         # HTTP client
pytest           # Testing framework
pytest-asyncio   # Async testing support
```

### Frontend (`frontend/package.json`)

```
react            # UI framework
react-dom        # DOM rendering
dompurify        # XSS protection
vite             # Build tool and dev server
vitest           # Testing framework
@testing-library # Testing utilities
```

## Common Commands

### Backend Development

The backend is located in the `backend/` directory and uses a Python virtual environment.

```bash
# Navigate to backend directory
cd backend

# Create and activate virtual environment (first time setup)
python3 -m venv venv
source venv/bin/activate  # On Linux/Mac
# venv\Scripts\activate   # On Windows

# Install dependencies
pip install -r requirements.txt

# Run the FastAPI server (development mode with auto-reload)
uvicorn app.main:app --reload

# The server will be available at http://localhost:8000
```

### Backend Testing

```bash
# Navigate to backend and activate venv
cd backend
source venv/bin/activate

# Run all tests
python -m pytest

# Run tests with verbose output
python -m pytest -v

# Run specific test file
python -m pytest tests/test_auth_endpoints.py

# Run tests with coverage
python -m pytest --cov=app
```

### Frontend Development

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev

# The frontend will be available at http://localhost:5173
```

### Frontend Testing

```bash
# Frontend tests
cd frontend && npm test        # Single run
cd frontend && npm run test:watch  # Watch mode
```

### Database Setup

```bash
# Start PostgreSQL with Docker
docker run --name pg-local -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=mydb -d postgres

# Start existing container
docker start pg-local

# Stop and remove container
docker stop pg-local && docker rm pg-local
```

### Production Build

```bash
# Frontend build
cd frontend && npm run build

# Backend deployment
uvicorn app.main:app --host 0.0.0.0 --port 10000
```

## Environment Configuration

- **Development**: Uses `.env` files for local configuration
- **Production**: Environment variables managed by Render.com
- **Database**: Automatic async PostgreSQL connection handling
- **Security**: Environment-specific logging and validation

## Security Libraries

- **DOMPurify**: Client-side XSS protection
- **google-auth**: Server-side token validation
- **Custom rate limiter**: IP-based request limiting
- **Secure logging**: PII redaction and structured logging
