# Netrix — Network Scanning & Vulnerability Assessment Platform

> A production-grade platform for network scanning, vulnerability detection, CVE matching, professional report generation, and full admin oversight — with a React web dashboard, REST API, and a fully interactive terminal CLI.

---

## Features

### Core Scanning
- **Network Scanning** — Nmap-powered scanning with NSE script support (quick, full, vuln, stealth, aggressive, custom)
- **Vulnerability Detection** — Automatic CVE matching against a 1,000-entry offline NVD database
- **Real-Time Progress** — WebSocket-powered live scan progress tracking
- **Multi-Format Reports** — PDF, HTML, JSON, and CSV output via ReportLab + Jinja2

### Interactive CLI
- **Full Terminal Interface** — Rich TUI built with Typer + InquirerPy + Rich
- **Interactive Wizards** — Guided scan setup, vulnerability browser, report generator
- **Auth-Aware Menu** — Main menu dynamically shows Login/Register or Logout/Account based on session state
- **JWT Expiry Detection** — Automatically detects expired tokens before any command runs and prompts re-login
- **Direct Mode** — All commands support flags for scripting and automation

### Admin Panel
- **User Management** — List users, ban/unban, change roles, reset passwords, delete accounts
- **Scan Oversight** — View all users' scans, force-stop running scans, force-delete with full cascade
- **Audit Logs** — Immutable event log tracking 10 action types (login, logout, login_failed, scan_start, scan_delete, report_download, password_reset, user_ban, role_change, cve_sync)
- **System Health** — MySQL/Redis/Nmap status, CPU & memory usage, active scan count, 24-hour metrics
- **CVE Browser** — Search and filter all 1,000 CVEs with severity filter, pagination, CVSS score bars, and detail modal

### Security
- **Role-Based Access Control** — `admin` and `analyst` roles with JWT authentication (HS256, 15-min expiry)
- **Input Validation** — Server-side and client-side validation; automatic `https://` stripping from scan targets
- **Rate Limiting** — SlowAPI middleware on sensitive endpoints
- **Audit Trail** — Every privileged action is logged to the immutable audit log table

---

## Tech Stack

| Component      | Technology                                          |
|----------------|-----------------------------------------------------|
| Backend        | Python 3.11 + FastAPI 0.104                         |
| Database       | MySQL 8.0 + SQLAlchemy 2.0 + Alembic                |
| Cache          | Redis 7 (Alpine)                                    |
| Scanner        | python-nmap 0.7.1 + Scapy 2.5                       |
| Auth           | JWT via python-jose + bcrypt (passlib)              |
| Frontend       | React 18 + Tailwind CSS + Redux Toolkit             |
| Reports        | ReportLab (PDF) + Jinja2 (HTML) + fpdf2 + pandas    |
| CVE Data       | NVD API v2 + Offline JSON cache (1,000 CVEs)        |
| System Monitor | psutil 5.9.6                                        |
| CLI            | Typer + Rich + InquirerPy                           |
| Container      | Docker + Docker Compose                             |

---

## Project Structure

```
netrix/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── v1/
│   │   │       ├── admin.py          # Admin endpoints (users, scans, logs, health, CVE)
│   │   │       ├── auth.py           # Login, register, logout, /me
│   │   │       ├── dashboard.py      # Stats, charts, recent scans
│   │   │       ├── hosts.py          # Host details and port listing
│   │   │       ├── reports.py        # Report generation and download
│   │   │       ├── scans.py          # Scan CRUD and results
│   │   │       └── vulnerabilities.py
│   │   ├── core/
│   │   │   ├── metrics_task.py       # Background system metrics collection
│   │   │   ├── security.py           # JWT creation and verification
│   │   │   └── validators.py         # Target/port/CIDR/domain validation
│   │   ├── models/
│   │   │   ├── audit_log.py          # Immutable audit event records
│   │   │   ├── host.py
│   │   │   ├── port.py
│   │   │   ├── report.py
│   │   │   ├── scan.py
│   │   │   ├── system_metric.py      # CPU/memory snapshots
│   │   │   ├── user.py               # User with role + ban fields
│   │   │   └── vulnerability.py
│   │   ├── schemas/
│   │   │   └── admin.py              # Admin API request/response schemas
│   │   ├── services/
│   │   │   ├── audit_service.py      # log_event() — fire-and-forget audit writer
│   │   │   ├── auth_service.py
│   │   │   ├── cve_service.py        # CVE loading and NVD sync
│   │   │   ├── health_service.py     # MySQL/Redis/Nmap health checks
│   │   │   ├── report_service.py
│   │   │   └── scan_service.py
│   │   ├── scanner/
│   │   │   ├── nmap_engine.py        # Nmap subprocess wrapper
│   │   │   ├── vuln_engine.py        # CVE matching engine
│   │   │   ├── scan_manager.py       # Async scan orchestration
│   │   │   ├── script_engine.py      # NSE script runner
│   │   │   └── report_engine.py      # PDF/HTML/JSON/CSV rendering
│   │   └── database/
│   │       └── init_db.py
│   ├── data/
│   │   └── cve_offline.json          # 1,000 pre-loaded NVD CVEs
│   ├── migrations/
│   ├── scripts/
│   │   └── populate_cve_db.py        # Fetches ~1,000 CVEs from NVD API v2
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AdminRoute.jsx        # RBAC guard — redirects non-admins
│   │   │   ├── AdminSummary.jsx      # Admin stats widget for dashboard
│   │   │   └── Sidebar.jsx
│   │   ├── context/
│   │   │   └── ToastContext.jsx      # Global toast notification system
│   │   ├── pages/
│   │   │   ├── AdminCVE.jsx          # CVE browser with search, filter, modal
│   │   │   ├── AdminHealth.jsx       # System health dashboard
│   │   │   ├── AdminLogs.jsx         # Audit log viewer with filters
│   │   │   ├── AdminScans.jsx        # All-users scan management
│   │   │   ├── AdminUsers.jsx        # User management panel
│   │   │   ├── Dashboard.jsx
│   │   │   ├── History.jsx
│   │   │   ├── Login.jsx
│   │   │   ├── NewScan.jsx
│   │   │   ├── Register.jsx
│   │   │   ├── Reports.jsx
│   │   │   ├── ScanResults.jsx
│   │   │   ├── Settings.jsx
│   │   │   └── Vulnerabilities.jsx
│   │   ├── services/
│   │   │   └── api.js                # Axios client with JWT interceptors
│   │   └── store/
│   │       └── index.js              # Redux Toolkit store (auth slice)
│   └── Dockerfile
├── cli/                              # Interactive terminal CLI
│   ├── netrix_cli.py                 # Main entry point + dynamic main menu
│   ├── api_client.py                 # Centralized HTTP client (all backend calls)
│   ├── config.py                     # Token storage, JWT expiry check, settings
│   ├── commands/
│   │   ├── auth.py                   # login, register, logout, whoami
│   │   ├── scan.py                   # Scan wizard + direct mode
│   │   ├── vulns.py                  # Vulnerability browser + CVE detail
│   │   ├── report.py                 # Report generator
│   │   ├── history.py                # Scan history viewer
│   │   ├── dashboard.py              # Stats overview
│   │   └── config_cmd.py             # CLI settings management
│   ├── ui/
│   │   ├── banners.py                # ASCII art banner
│   │   ├── panels.py                 # Rich panels (error, success, scan summary, CVE)
│   │   ├── progress.py               # Live scan progress bar (polling)
│   │   ├── prompts.py                # All InquirerPy menus and wizards
│   │   └── tables.py                 # Rich tables (hosts, ports, vulns, scans, reports)
│   ├── utils/
│   │   ├── formatters.py             # Date, duration, file size formatters
│   │   └── validators.py             # Target, scan type, severity validators
│   └── requirements.txt
├── tests/
├── docker-compose.yml
└── README.md
```

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Nmap installed on the host (required for scan containers):
  ```bash
  sudo apt install nmap      # Debian/Ubuntu/Kali
  sudo yum install nmap      # RHEL/CentOS
  ```

### Running with Docker

```bash
# Clone the repository
git clone https://github.com/DevAjudiya/Netrix.git
cd Netrix

# Copy and configure environment variables
cp .env.example .env
# Edit .env — set MYSQL_ROOT_PASSWORD, MYSQL_PASSWORD, SECRET_KEY

# Build and start all services
docker compose up -d --build

# Access the platform
# Frontend UI:   http://localhost:3000
# Backend API:   http://localhost:8000
# API Docs:      http://localhost:8000/docs
```

### Default Admin Credentials

```
Username: admin
Password: admin
```

> Change this immediately after first login via Admin → Users → Reset Password.

### Populate the CVE Database (optional — already included)

The repo ships with `backend/data/cve_offline.json` pre-loaded with 1,000 CVEs.
To refresh from NVD:

```bash
docker exec netrix-backend python scripts/populate_cve_db.py
```

Or from the Admin panel: **Admin → CVE Control → Sync Now**.

---

## CLI

The Netrix CLI provides full access to the platform from the terminal with both an interactive TUI and direct command-line flags.

### Installation

```bash
cd cli
pip install -r requirements.txt
```

### Usage

```bash
# Interactive main menu (recommended)
python netrix_cli.py

# Direct commands
python netrix_cli.py login
python netrix_cli.py scan
python netrix_cli.py scan -t 192.168.1.0/24 --type full
python netrix_cli.py vulns --scan 1 --severity critical
python netrix_cli.py report --scan 1 --format pdf
python netrix_cli.py history
python netrix_cli.py dashboard
python netrix_cli.py whoami
python netrix_cli.py logout
python netrix_cli.py status          # Check backend connectivity
python netrix_cli.py version
```

### Commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate with the backend (interactive or `--username`/`--password`) |
| `register` | Create a new account (interactive) |
| `logout` | Clear the saved session token |
| `whoami` | Display the current user's profile |
| `scan` | Launch a scan — interactive wizard or direct `--target`/`--type` |
| `vulns` | Browse vulnerabilities with severity filter and CVE detail view |
| `report` | Generate a report — interactive or direct `--scan`/`--format` |
| `history` | View past scans — view results, generate reports, or delete |
| `dashboard` | Quick stats overview (scans, hosts, vulns, severity breakdown) |
| `config` | View and manage CLI settings (`--list`, `--set KEY=VALUE`, `--reset`) |
| `status` | Check backend connectivity |
| `version` | Display CLI version |

### Scan Types

| Type | Description | Est. Time |
|------|-------------|-----------|
| `quick` | Top 100 ports | ~2 min |
| `stealth` | All ports, SYN scan (IDS evasion) | ~20 min |
| `full` | All 65,535 ports + OS + scripts | ~30 min |
| `aggressive` | Everything + traceroute | ~45 min |
| `vulnerability` | NSE vuln scripts + CVE detection | ~60 min |

### Supported Target Formats

```
192.168.1.1          # Single IP
192.168.1.0/24       # CIDR range
192.168.1.1-50       # IP range
example.com          # Domain
```

### CLI Settings

```bash
# View all settings
python netrix_cli.py config --list

# Change the API URL (e.g. remote backend)
python netrix_cli.py config --set api_url=http://192.168.1.100:8000/api/v1

# Change default scan type
python netrix_cli.py config --set default_scan_type=quick

# Reset to defaults
python netrix_cli.py config --reset
```

Settings are stored in `~/.netrix/config.json`.

### Auth Flow

The CLI checks authentication before every command that requires it:

1. If no token is saved → prompts **Login / Register / Cancel**
2. If a token is saved but expired (JWT `exp` check) → clears it, prompts re-login
3. If token is valid → proceeds immediately

The main interactive menu is auth-aware:
- **Not logged in** — shows Login and Register as the first options
- **Logged in** — shows Account and Logout at the bottom

---

## API Reference

Interactive docs are available once the backend is running:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/auth/login` | Authenticate and receive JWT |
| `POST` | `/api/v1/auth/register` | Register new user |
| `GET`  | `/api/v1/auth/me` | Current user info |
| `POST` | `/api/v1/scans/` | Launch a new scan |
| `GET`  | `/api/v1/scans/` | List scans (paginated) |
| `GET`  | `/api/v1/scans/{scan_id}/status` | Lightweight scan status |
| `GET`  | `/api/v1/scans/{scan_id}/results` | Full scan results |
| `DELETE` | `/api/v1/scans/{scan_id}` | Delete a scan |
| `POST` | `/api/v1/reports/generate` | Generate a report |
| `GET`  | `/api/v1/reports/{id}/download` | Download a report |
| `GET`  | `/api/v1/vulnerabilities/` | List vulnerabilities (filter by severity, scan, CVSS) |
| `GET`  | `/api/v1/vulnerabilities/cve/{cve_id}` | CVE detail lookup |
| `GET`  | `/api/v1/vulnerabilities/stats/{scan_id}` | Vulnerability statistics |
| `GET`  | `/api/v1/dashboard/stats` | Dashboard statistics |
| `GET`  | `/api/v1/dashboard/recent-scans` | Recent scans |
| `GET`  | `/api/v1/admin/users` | List all users (admin) |
| `GET`  | `/api/v1/admin/scans` | List all scans (admin) |
| `GET`  | `/api/v1/admin/logs` | Audit log viewer (admin) |
| `GET`  | `/api/v1/admin/health` | System health (admin) |
| `GET`  | `/api/v1/admin/cve/list` | Browse CVE database (admin) |
| `POST` | `/api/v1/admin/cve/sync` | Sync CVEs from NVD (admin) |

---

## Admin Panel

The admin panel is accessible at `/admin/*` and requires the `admin` role.

| Page | Path | Description |
|------|------|-------------|
| Users | `/admin/users` | Ban/unban, role change, password reset, delete |
| Scans | `/admin/scans` | View, stop, and delete any user's scan |
| Audit Logs | `/admin/logs` | Immutable log of all privileged actions |
| System Health | `/admin/health` | Real-time service status and system metrics |
| CVE Control | `/admin/cve` | Sync status, CVE browser, re-match engine |

### Audit Log Action Types

`login` · `logout` · `login_failed` · `scan_start` · `scan_delete` · `report_download` · `password_reset` · `user_ban` · `role_change` · `cve_sync`

---

## Development

### Backend (local)

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run database migrations
alembic upgrade head

# Start the server
uvicorn app.main:app --reload --port 8000
```

### Frontend (local)

```bash
cd frontend
npm install
npm run dev
```

> **Note:** The frontend is built as a static nginx image in production. After editing `.jsx` files, rebuild the image:
> ```bash
> docker compose build netrix-frontend && docker compose up -d netrix-frontend
> ```

### CLI (local)

```bash
cd cli
pip install -r requirements.txt
python netrix_cli.py
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing secret | required |
| `MYSQL_HOST` | MySQL hostname | `mysql` |
| `MYSQL_DATABASE` | Database name | `netrix_db` |
| `MYSQL_USER` | DB username | `netrix_user` |
| `MYSQL_PASSWORD` | DB password | required |
| `MYSQL_ROOT_PASSWORD` | MySQL root password | required |
| `REDIS_URL` | Redis connection URL | `redis://redis:6379` |
| `NVD_API_KEY` | NVD API key for CVE sync | optional |
| `TZ` | Timezone | `Asia/Kolkata` |

---

## License

This project is proprietary software. All rights reserved.
