# ─────────────────────────────────────────
# Netrix — README.md
# Purpose: Project overview and setup instructions
# Author: Netrix Development Team
# ─────────────────────────────────────────

# Netrix — Network Scanning & Vulnerability Assessment Platform

> A production-grade platform for network scanning, vulnerability detection, CVE matching, and professional report generation.

## Features

- **Advanced Network Scanning** — Powered by Nmap with NSE script support
- **Vulnerability Detection** — Automatic CVE matching against NVD database
- **Multi-Format Reports** — PDF, HTML, JSON, and CSV output
- **Three Interfaces** — CLI, REST API, and React Web Dashboard
- **Role-Based Access** — JWT authentication with granular permissions
- **Real-Time Updates** — WebSocket-powered scan progress tracking

## Tech Stack

| Component   | Technology                               |
|-------------|------------------------------------------|
| Backend     | Python 3.11 + FastAPI                    |
| Database    | MySQL 8.0 + SQLAlchemy 2.0 + Alembic    |
| Cache       | Redis 7                                  |
| Scanner     | python-nmap + Scapy                      |
| Auth        | JWT (access + refresh tokens) + bcrypt   |
| CLI         | Typer + Rich                             |
| Frontend    | React.js + Tailwind CSS + Redux Toolkit  |
| Reports     | ReportLab (PDF) + Jinja2 (HTML) + pandas |
| CVE Data    | NVD API + Offline JSON backup            |
| Container   | Docker + Docker Compose                  |

## Quick Start

### Prerequisites

- Docker & Docker Compose
- Python 3.11+ (for local development)
- Node.js 18+ (for frontend development)
- Nmap installed on the host system

### Running with Docker

```bash
# Clone the repository
git clone https://github.com/your-org/netrix.git
cd netrix

# Copy and configure environment variables
cp .env.example .env
# Edit .env with your settings

# Start all services
docker-compose up -d

# Access the platform
# Backend API:  http://localhost:8000
# Frontend UI:  http://localhost:3000
# API Docs:     http://localhost:8000/docs
```

### Local Development

```bash
# Backend
cd backend
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm start
```

## Project Structure

```
netrix/
├── backend/          # FastAPI backend application
│   ├── app/          # Application source code
│   │   ├── api/      # REST API endpoints (v1)
│   │   ├── core/     # Security, middleware, validators
│   │   ├── scanner/  # Nmap engine, vuln engine, reports
│   │   ├── models/   # SQLAlchemy ORM models
│   │   ├── schemas/  # Pydantic request/response schemas
│   │   ├── services/ # Business logic layer
│   │   └── database/ # DB session and initialization
│   ├── migrations/   # Alembic database migrations
│   └── tests/        # Backend test suite
├── cli/              # Typer CLI interface
├── frontend/         # React web dashboard
└── docker-compose.yml
```

## API Documentation

Once the backend is running, interactive API docs are available at:
- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

## License

This project is proprietary software. All rights reserved.
