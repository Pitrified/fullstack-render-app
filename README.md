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
git clone https://github.com/yourname/yourrepo.git
cd yourrepo
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

### 3. Backend Setup

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Create environment file
cp .env.example .env
# Edit .env and add your GOOGLE_CLIENT_ID and SESSION_SECRET

uvicorn app.main:app --reload
```

**Important**: Generate a secure SESSION_SECRET:
```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### 4. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

### 5. Google OAuth Setup

1. Go to https://console.cloud.google.com/apis/credentials
2. Create OAuth 2.0 Client ID:
   - Web App
   - Add http://localhost:5173 as Authorized JS Origin
3. Copy client ID to:
   - `frontend/.env.local`: `VITE_GOOGLE_CLIENT_ID`
   - `backend/.env`: `GOOGLE_CLIENT_ID`
4. Generate secure session secret:
   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
   Add to `backend/.env`: `SESSION_SECRET=your_generated_secret`

### 6. Quick Local Run (Docker + Backend + Frontend)

Use these commands to start PostgreSQL, the FastAPI backend (using the `venv` in `backend`), and the React frontend for local testing.

1) Start PostgreSQL in Docker (if not already running):

```bash
# Run Postgres container
docker run --name pg-local -p 5432:5432 \
   -e POSTGRES_PASSWORD=postgres \
   -e POSTGRES_DB=mydb -d postgres

# If container exists but stopped
docker start pg-local
```

2) Start the backend (from project root):

```bash
# Activate the virtualenv and run the backend
cd backend
source venv/bin/activate
pip install -r requirements.txt
# Ensure .env is configured (see step 3)
uvicorn app.main:app --reload --port 8000
```

3) Start the frontend (in a new terminal):

```bash
cd frontend
npm install
npm run dev
```

Notes:
- The backend expects the database at `postgresql://postgres:postgres@localhost:5432/mydb` by default (see `.env.example`).
- Frontend dev server runs at `http://localhost:5173` and should be configured to use `VITE_API_BASE_URL=http://localhost:8000` in `frontend/.env.local`.
- Use the Google OAuth client configured with `http://localhost:5173` as an authorized origin.

## 🔗 Internal Communication (Render)

This app is configured to use Render's internal networking for communication between services:

- **Local Development**: Frontend uses `http://localhost:8000` (via `VITE_API_BASE_URL` in `.env.local`)
- **Render Deployment**: Frontend uses `http://fastapi-backend:8000` (internal hostname) for secure, low-latency communication


## 🚀 Deploy to Render

1. Push the repo to GitHub
2. Create a new Blueprint on Render: https://dashboard.render.com/blueprint/new, it will detect the `render.yaml` at the root
3. Render will auto-deploy:
   - Static React site
   - FastAPI backend
   - PostgreSQL DB
4. Manually set the following **environment variables** in Render:
   - **backend service**: 
     - `GOOGLE_CLIENT_ID` (your Google OAuth client ID)
     - `SESSION_SECRET` (generate with: `python -c "import secrets; print(secrets.token_urlsafe(32))"`)
   - **frontend service**: 
     - `VITE_GOOGLE_CLIENT_ID` (same as backend)
   
   Note: `VITE_API_BASE_URL`, `ENVIRONMENT`, and `COOKIE_DOMAIN` are automatically set in `render.yaml`.

You're live! 🎉

## 🏗️ Architecture

- **Frontend**: React + Vite (static site) with secure session management
- **Backend**: FastAPI + PostgreSQL with httpOnly cookie authentication
- **Security**: Enterprise-grade with XSS/CSRF protection
- **Authentication**: Google OAuth 2.0 with secure session storage
- **Deployment**: Render.com with internal service communication
- **Database**: PostgreSQL (managed by Render)

## 📚 Documentation

- **[vulnerabilities.md](vulnerabilities.md)** - Security vulnerability assessment and fixes