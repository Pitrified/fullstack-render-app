# Fullstack Google OAuth App (FastAPI + React + PostgreSQL)

This project demonstrates a fullstack web app with:
- Google OAuth login
- FastAPI backend with user persistence
- PostgreSQL database
- React frontend
- Deployment to Render.com

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
uvicorn app.main:app --reload
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
   - `frontend/.env`: `VITE_GOOGLE_CLIENT_ID`
   - `backend/.env`: `GOOGLE_CLIENT_ID`

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
   - backend service: `GOOGLE_CLIENT_ID`
   - frontend service: `VITE_GOOGLE_CLIENT_ID`
   
   Note: `VITE_API_BASE_URL` is automatically set in the `render.yaml` for internal communication.

You're live! 🎉

## 🏗️ Architecture

- **Frontend**: React + Vite (static site)
- **Backend**: FastAPI + PostgreSQL
- **Authentication**: Google OAuth 2.0
- **Deployment**: Render.com with internal service communication
- **Database**: PostgreSQL (managed by Render)