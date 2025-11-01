# Fullstack Google OAuth App (FastAPI + React + PostgreSQL)

This project demonstrates a **secure fullstack web app** with enterprise-grade authentication:
- 🔒 **Secure Google OAuth** with httpOnly cookies (XSS protection)
- 🛡️ **CSRF protection** with double-submit cookie pattern
- 🚀 **FastAPI backend** with async PostgreSQL persistence
- ⚡ **React frontend** with session-based authentication
- 🌐 **Production deployment** on Render.com with security hardening

## 🔐 Security Features

### ✅ OWASP Top 10 Protection
- **XSS Prevention**: httpOnly cookies prevent token theft
- **CSRF Protection**: Double-submit cookie pattern  
- **Secure Sessions**: JWT-based server-side session management
- **Input Sanitization**: DOMPurify-based XSS protection
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options

### 🛡️ Authentication Security
- **No localStorage**: Tokens never exposed to JavaScript
- **httpOnly Cookies**: Browser-only session storage
- **Session Expiry**: Automatic 24-hour timeout with refresh
- **Secure Flags**: Production HTTPS-only cookies
- **CSRF Validation**: Required for state-changing operations

## 🛠 Local Setup

### 1. Clone the Repo

```bash
git clone https://github.com/Pitrified/fullstack-render-app.git
cd fullstack-render-app
```

### 2. Setup PostgreSQL Locally

You can use Docker:

```bash
docker run --name pg-local -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=mydb -d postgres
```

And restart it later with:

```bash
docker start pg-local
```

Or if you need to stop and remove it:

```bash
docker stop pg-local
docker rm pg-local
```

Or install PostgreSQL and create the DB manually.

### 3. Environment Configuration

#### Backend Environment Variables (`backend/.env`)

Copy `backend/.env.example` to `backend/.env` and configure:

```bash
# Required for all environments
GOOGLE_CLIENT_ID=your_google_client_id_here
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/mydb
SESSION_SECRET=your_very_secure_random_string_here_at_least_32_characters_long

# Optional - defaults shown
ENVIRONMENT=development
LOG_LEVEL=INFO

# Production only (not needed for local development)
# COOKIE_DOMAIN=yourdomain.com
```

**Generate a secure SESSION_SECRET:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

#### Frontend Environment Variables (`frontend/.env`)

Copy `frontend/.env.example` to `frontend/.env` and configure:

```bash
# Required
VITE_GOOGLE_CLIENT_ID=your_google_client_id_here

# For local development
VITE_API_BASE_URL=http://localhost:8000
```

### 4. Google OAuth Setup

1. Go to https://console.cloud.google.com/apis/credentials
2. Create OAuth 2.0 Client ID:
   - Application type: **Web application**
   - Name: Your app name
   - Authorized JavaScript origins:
     - `http://localhost:5173` (for local development)
     - `https://your-frontend-domain.com` (for production)
3. Copy the Client ID to both:
   - `backend/.env`: `GOOGLE_CLIENT_ID=your_client_id`
   - `frontend/.env`: `VITE_GOOGLE_CLIENT_ID=your_client_id`

### 5. Backend Setup

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Ensure .env is configured (see step 3)
uvicorn app.main:app --reload
```

### 6. Frontend Setup

```bash
cd frontend
npm install
# Ensure .env is configured (see step 3)
npm run dev
```

### 7. Quick Start Commands

After completing the environment configuration above, use these commands:

**Terminal 1 - Database:**
```bash
# Start PostgreSQL in Docker
docker run --name pg-local -p 5432:5432 \
   -e POSTGRES_PASSWORD=postgres \
   -e POSTGRES_DB=mydb -d postgres

# If container exists but stopped
docker start pg-local
```

**Terminal 2 - Backend:**
```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --port 8000
```

**Terminal 3 - Frontend:**
```bash
cd frontend
npm run dev
```

**Access the application:**
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## 🔗 Service Communication

This app is configured for communication between frontend and backend:

- **Local Development**: Frontend uses `http://localhost:8000` (via `VITE_API_BASE_URL` in `.env`)
- **Render Deployment**: Frontend uses `https://fastapi-backend-yf8l.onrender.com` (configured in `render.yaml`)


## 🚀 Production Deployment on Render

### Automatic Deployment Setup

1. **Push to GitHub**: Ensure your code is in a GitHub repository
2. **Create Render Blueprint**: 
   - Go to https://dashboard.render.com/blueprint/new
   - Connect your GitHub repository
   - Render will detect the `render.yaml` configuration
3. **Deploy**: Render automatically creates:
   - PostgreSQL database (`userdb`)
   - FastAPI backend service (`fastapi-backend`)
   - React frontend static site (`react-frontend`)

### Required Production Environment Variables

After deployment, manually configure these environment variables in the Render dashboard:

#### Backend Service Environment Variables
Navigate to your backend service settings and add:

```bash
# Required - Set manually in Render dashboard
GOOGLE_CLIENT_ID=your_google_client_id_here
SESSION_SECRET=your_secure_session_secret_here

# Optional - Production optimizations
ENVIRONMENT=production
LOG_LEVEL=INFO
```

**Generate SESSION_SECRET for production:**
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

#### Frontend Service Environment Variables
Navigate to your frontend service settings and add:

```bash
# Required - Set manually in Render dashboard
VITE_GOOGLE_CLIENT_ID=your_google_client_id_here

# Automatically configured in render.yaml
VITE_API_BASE_URL=https://fastapi-backend-yf8l.onrender.com
```

#### Automatically Configured Variables
These are set automatically by `render.yaml`:
- `DATABASE_URL` - Connected to the PostgreSQL service
- `VITE_API_BASE_URL` - Points to your backend service URL

### Google OAuth Production Setup

Update your Google OAuth configuration for production:

1. Go to https://console.cloud.google.com/apis/credentials
2. Edit your OAuth 2.0 Client ID
3. Add your production domains to **Authorized JavaScript origins**:
   - `https://your-frontend-domain.onrender.com`
4. Save the configuration

### Post-Deployment Configuration

After your services are deployed, you'll need to update the CORS configuration:

1. **Get your frontend URL** from the Render dashboard
2. **Update CORS origins** in `backend/app/main.py`:
   ```python
   allow_origins=[
       "http://localhost:5173",  # Local development
       "https://your-actual-frontend-url.onrender.com",  # Your production URL
   ],
   ```
3. **Commit and push** the change to trigger a backend redeployment

### Production Security Notes

- All cookies are automatically secured with `httpOnly`, `secure`, and `samesite=strict`
- Database connections use SSL in production
- Sensitive data is automatically redacted from logs
- Rate limiting is enabled on authentication endpoints
- CORS is configured for your specific frontend domain

You're live! 🎉

## 🏗️ Architecture

- **Frontend**: React + Vite (static site) with secure session management
- **Backend**: FastAPI + PostgreSQL with httpOnly cookie authentication
- **Security**: Enterprise-grade with XSS/CSRF protection
- **Authentication**: Google OAuth 2.0 with secure session storage
- **Deployment**: Render.com with internal service communication
- **Database**: PostgreSQL (managed by Render)

## 📋 Environment Variables Reference

### Backend Variables (`backend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GOOGLE_CLIENT_ID` | ✅ | - | Google OAuth 2.0 Client ID from Google Cloud Console |
| `DATABASE_URL` | ✅ | - | PostgreSQL connection string (auto-configured on Render) |
| `SESSION_SECRET` | ✅ | - | Cryptographically secure secret for session signing |
| `ENVIRONMENT` | ❌ | `production` | Environment mode: `development`, `production`, `test` |
| `LOG_LEVEL` | ❌ | `INFO` | Logging level: `DEBUG`, `INFO`, `WARNING`, `ERROR` |

### Frontend Variables (`frontend/.env`)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `VITE_GOOGLE_CLIENT_ID` | ✅ | - | Same Google OAuth Client ID as backend |
| `VITE_API_BASE_URL` | ✅ | - | Backend API URL (auto-configured on Render) |

### Environment-Specific Behavior

#### Development (`ENVIRONMENT=development`)
- Detailed logging with database query echo
- CORS allows `http://localhost:5173`
- Cookies work over HTTP (not secure)
- Debug information in logs

#### Production (`ENVIRONMENT=production`)
- Structured JSON logging with PII redaction
- Secure cookies (HTTPS only, httpOnly, samesite=strict)
- Rate limiting enabled
- Security headers enforced
- Database SSL connections

## 🔧 Troubleshooting

### Common Environment Configuration Issues

#### Backend Issues

**"DATABASE_URL not configured"**
- Ensure `DATABASE_URL` is set in `backend/.env`
- For local development: `postgresql://postgres:postgres@localhost:5432/mydb`
- Check PostgreSQL is running: `docker ps` or `docker start pg-local`

**"SESSION_SECRET not configured"**
- Generate a secure secret: `python -c "import secrets; print(secrets.token_urlsafe(32))"`
- Add to `backend/.env`: `SESSION_SECRET=your_generated_secret`

**"GOOGLE_CLIENT_ID not configured"**
- Create OAuth credentials at https://console.cloud.google.com/apis/credentials
- Add the Client ID to `backend/.env`: `GOOGLE_CLIENT_ID=your_client_id`

#### Frontend Issues

**"Google Sign-In not working"**
- Verify `VITE_GOOGLE_CLIENT_ID` matches the backend `GOOGLE_CLIENT_ID`
- Check Google OAuth origins include your frontend URL
- For local development: add `http://localhost:5173` to authorized origins

**"API calls failing"**
- Verify `VITE_API_BASE_URL` points to your backend
- Local development: `http://localhost:8000`
- Production: your Render backend URL

**"CORS errors in production"**
- Update `backend/app/main.py` CORS configuration with your frontend URL
- Replace `https://react-frontend-t2b1.onrender.com` with your actual Render frontend URL
- Redeploy the backend after making this change

#### Production Deployment Issues

**"Environment variables not found on Render"**
- Set variables in Render dashboard, not in `.env` files
- Backend variables go in the backend service settings
- Frontend variables go in the frontend service settings

**"Google OAuth not working in production"**
- Add your production frontend URL to Google OAuth authorized origins
- Ensure `VITE_GOOGLE_CLIENT_ID` is set in Render frontend service
- Check that `GOOGLE_CLIENT_ID` matches between frontend and backend

## 📚 Documentation

- **[vulnerabilities.md](vulnerabilities.md)** - Security vulnerability assessment and fixes