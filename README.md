# syl-pentools

A vulnerability management platform built with reverse engineering insights.

## Features Implemented

### Core Modules
- **Dashboard** - Asset overview, running scans, vulnerability summary, latest scans
- **Assets** - Add/manage targets (hostnames/IPs), import from file, risk levels
- **Scans** - 6 scan types (Website, Network, Port, Subdomain, Recon, Password Auditor)
- **Findings** - Vulnerability tracking with risk levels, status workflow
- **Reports** - DOCX/PDF report generation templates, branding
- **Integrations** - 11 integrations (Slack, Teams, Jira, GitHub, Discord, Webhook, Vanta, Burp, AWS, Nucleus, MCP)
- **Settings** - Profile, 2FA, notifications, appearance, billing, team, API keys

### Tech Stack
- **Frontend**: React 18 + TypeScript + Vite + Tailwind CSS + Zustand + TanStack Query
- **Backend**: FastAPI (Python 3.11) + Uvicorn
- **Real-time**: Socket.io (planned)
- **Queue**: Redis + Celery (planned)
- **Database**: SQLite (dev) / PostgreSQL (prod)

## Quick Start

```bash
# Using Docker (recommended)
chmod +x start.sh
./start.sh

# Or manual
cd frontend && npm install && npm run dev
cd backend && pip install -r requirements.txt && uvicorn main:app --reload
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/assets` | List all assets |
| POST | `/api/assets` | Create new asset |
| DELETE | `/api/assets/{id}` | Delete asset |
| GET | `/api/scans` | List all scans |
| POST | `/api/scans` | Start new scan |
| GET | `/api/scans/{id}` | Get scan details |
| POST | `/api/scans/{id}/retry` | Retry failed scan |
| GET | `/api/findings` | List all findings |
| GET | `/api/integrations` | List integrations |
| POST | `/api/integrations/{id}` | Configure integration |

## Scan Types

| Type | Description |
|------|-------------|
| Website Scanner | XSS, SQLi, RCE + 70+ web vulns |
| Network Scanner | 10,000+ CVEs & misconfigs |
| Port Scanner | Open ports & service fingerprinting |
| Subdomain Finder | Discover subdomains |
| Website Recon | Fingerprint web technologies |
| Password Auditor | Weak credentials detection |

## Screenshots

*Add screenshots after running*

## Roadmap

- [ ] Real vulnerability scanners (nmap, nuclei, etc.)
- [ ] Authenticated scanning with login recording
- [ ] Real-time scan progress via WebSocket
- [ ] PDF/DOCX report generation
- [ ] Scheduled scans with cron
- [ ] Attack surface mapping
- [ ] AI-powered findings triage
- [ ] Compliance report templates (PCI DSS, ISO 27001)

## Architecture

```
Frontend (React/Inertia) ←→ Backend (Laravel/FastAPI)
       ↑                         ↑
  Socket.io                  Redis Queue
       ↑                         ↑
  Real-time              Scanner Workers
  updates                (nmap, nuclei, etc.)
```

## License

MIT - For educational/research purposes only.
