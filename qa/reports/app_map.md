# Application Map — Syl-Pentools

Generated during F0 Discovery phase.

---

## Frontend Routes (React 18 + TS + Vite)

| Route | Page Component | Auth Required |
|-------|----------------|---------------|
| `/login` | Login | No |
| `/register` | Register | No |
| `/dashboard` | Dashboard | Yes |
| `/assets` | Assets | Yes |
| `/attack-surface` | AttackSurface | Yes |
| `/scans` | Scans | Yes |
| `/scans/new` | NewScan | Yes |
| `/findings` | Findings | Yes |
| `/reports` | Reports | Yes |
| `/ai-pentests` | AiPentests | Yes |
| `/robots` | Robots | Yes |
| `/integrations` | Integrations | Yes |
| `/settings` | Settings | Yes |
| `/team` | Team | Yes |
| `/join` | Join | Yes |

**Note**: Frontend built files exist in `frontend/dist/` but dev server not running (ports 3000/3001 return 404). Production build would need to be served.

---

## API Endpoints (Starlette, prefix `/api`)

### Auth
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/auth/register` | No | Register new user + create workspace |
| POST | `/api/auth/login` | No | Login, returns access + refresh JWT |
| POST | `/api/auth/refresh` | No | Refresh access token using refresh token |
| POST | `/api/auth/logout` | Yes | Revoke current session |
| GET | `/api/auth/me` | Yes | Current user profile |

### Workspace & Team
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/bootstrap` | Yes | Full workspace data (assets, scans, findings, integrations) |
| GET | `/api/workspace` | Yes | Current workspace |
| GET | `/api/workspaces` | Yes | List workspaces |
| GET | `/api/team/members` | Yes | List team members |
| POST | `/api/team/invites` | Yes | Invite team member |
| DELETE | `/api/team/invites/{invite_id}` | Yes | Cancel invite |
| POST | `/api/team/invite/accept` | No | Accept invite |
| PATCH | `/api/team/members/{user_id}` | Yes | Update member role |
| DELETE | `/api/team/members/{user_id}` | Yes | Remove member |

### API Keys
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/api-keys` | Yes | List API keys |
| POST | `/api/api-keys` | Yes | Create API key |
| DELETE | `/api/api-keys/{key_id}` | Yes | Revoke API key |

### Assets (Targets)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/assets` | Yes | List assets |
| GET | `/api/assets/{asset_id}` | Yes | Get asset detail |
| POST | `/api/assets` | Yes | Create asset (target: domain, IP, CIDR, URL) |
| POST | `/api/assets/import` | Yes | Bulk import assets |
| DELETE | `/api/assets/{asset_id}` | Yes | Soft delete asset |

### Scans
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/scans` | Yes | List scans (paginated, 200) |
| POST | `/api/scans` | Yes | Create & queue scan |
| GET | `/api/scans/{scan_id}` | Yes | Get scan detail + logs + findings |
| DELETE | `/api/scans/{scan_id}` | Yes | Cancel running/queued scan |
| POST | `/api/scans/{scan_id}/retry` | Yes | Retry failed/cancelled scan |
| GET | `/api/scans/{scan_id}/findings` | Yes | Findings for scan |
| GET | `/api/scans/{scan_id}/logs` | Yes | Logs for scan |
| POST | `/api/scans/authenticated` | Yes | Create authenticated scan |

**Scan Types**: `website`, `network`, `api`, `ssl_tls`, `headers`, `fuzzer`, `robots`, `authenticated`

### Findings
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/findings` | Yes | List findings (filter: severity, status) |
| POST | `/api/findings` | Yes | Create finding manually |
| POST | `/api/findings/bulk` | Yes | Bulk update findings |
| PATCH | `/api/findings/{finding_id}` | Yes | Update finding (status, etc.) |
| GET | `/api/findings/{finding_id}/detail` | Yes | Full finding detail (evidence, comments, attachments) |
| PATCH | `/api/findings/{finding_id}` | Yes | Extended finding update |
| GET | `/api/findings/{finding_id}/comments` | Yes | List comments |
| POST | `/api/findings/{finding_id}/comments` | Yes | Add comment |

### Scheduled Scans
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/scheduled-scans` | Yes | List scheduled scans |
| POST | `/api/scheduled-scans` | Yes | Create scheduled scan |
| GET | `/api/scheduled-scans/{schedule_id}` | Yes | Get schedule detail |
| PATCH | `/api/scheduled-scans/{schedule_id}` | Yes | Update schedule |
| DELETE | `/api/scheduled-scans/{schedule_id}` | Yes | Delete schedule |
| POST | `/api/scheduled-scans/{schedule_id}/trigger` | Yes | Manually trigger schedule |

**Frequencies**: `daily`, `weekly`, `monthly`, `custom` (cron)

### Scan Templates
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/scan-templates` | Yes | List templates |
| POST | `/api/scan-templates` | Yes | Create template |
| GET | `/api/scan-templates/{template_id}` | Yes | Get template |
| PATCH | `/api/scan-templates/{template_id}` | Yes | Update template |
| DELETE | `/api/scan-templates/{template_id}` | Yes | Delete template |
| POST | `/api/scan-templates/{template_id}/use` | Yes | Create scan from template |

### Reports
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/reports` | Yes | List reports |
| POST | `/api/reports` | Yes | Generate report (Celery task) |
| GET | `/api/reports/{report_id}` | Yes | Get report detail |
| GET | `/api/reports/{report_id}/download` | Yes | Download report file |
| DELETE | `/api/reports/{report_id}` | Yes | Delete report |

**Formats**: `pdf`, `html`, `docx`, `json`, `csv`

### Report Templates
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/report-templates` | Yes | List templates |
| POST | `/api/report-templates` | Yes | Create template |
| GET | `/api/report-templates/{template_id}` | Yes | Get template |
| PATCH | `/api/report-templates/{template_id}` | Yes | Update template |
| DELETE | `/api/report-templates/{template_id}` | Yes | Delete template |

### Diff / Monitoring
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/diff/compare` | Yes | Compare two scans |
| GET | `/api/diff/latest` | Yes | Compare latest two scans for target |
| GET | `/api/diff/workspace` | Yes | All target diffs in workspace |
| GET | `/api/diff/alerts` | Yes | Diff alerts above severity threshold |
| POST | `/api/diff/run` | Yes | Run diff check for workspace |

### Robots (Automation)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/robots` | Yes | List robots |
| POST | `/api/robots` | Yes | Create robot |
| GET | `/api/robots/runs` | Yes | List robot runs |
| GET | `/api/robots/runs/{run_id}` | Yes | Get run detail |
| GET | `/api/robots/{robot_id}` | Yes | Get robot |
| PATCH | `/api/robots/{robot_id}` | Yes | Update robot |
| DELETE | `/api/robots/{robot_id}` | Yes | Delete robot |
| POST | `/api/robots/{robot_id}/run` | Yes | Run robot |

### Dashboard & Analytics
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/dashboard/analytics` | Yes | Dashboard analytics |
| GET | `/api/workspace/usage` | Yes | Workspace usage stats |

### Attack Surface
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/attack-surface` | Yes | Attack surface map (group_by, query) |
| GET | `/api/attack-surface/stats` | Yes | Attack surface statistics |

### Integrations
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/integrations` | Yes | List integrations (configured/enabled) |
| POST | `/api/integrations/{int_id}` | Yes | Configure integration |
| PATCH | `/api/integrations/{int_id}/toggle` | Yes | Enable/disable integration |

**Catalog**: slack, teams, jira, webhook, github, discord, aws, vanta

### Billing (Stripe)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/billing/checkout` | Yes | Create checkout session |
| POST | `/api/billing/portal` | Yes | Create billing portal session |
| POST | `/api/billing/webhook` | No | Stripe webhook |
| GET | `/api/billing/subscription` | Yes | Get subscription + limits |
| POST | `/api/billing/subscription/cancel` | Yes | Cancel subscription |
| POST | `/api/billing/subscription/resume` | Yes | Resume subscription |

### MFA (TOTP)
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/mfa/status` | Yes | MFA status |
| POST | `/api/mfa/totp/setup` | Yes | Setup TOTP (returns QR/secret) |
| POST | `/api/mfa/totp/enable` | Yes | Enable TOTP with token |
| POST | `/api/mfa/totp/disable` | Yes | Disable TOTP |
| POST | `/api/mfa/totp/verify` | Yes | Verify TOTP token |
| POST | `/api/mfa/recovery-codes` | Yes | Generate recovery codes |
| POST | `/api/mfa/recovery-codes/verify` | Yes | Verify recovery code |

### SSO
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/sso/saml/metadata` | No | SAML metadata XML |
| POST | `/api/sso/saml/acs` | No | SAML ACS (not implemented) |
| GET | `/api/sso/oidc/config` | No | OIDC config |
| GET/POST | `/api/sso/oidc/callback` | No | OIDC callback (not implemented) |

### Health & Metrics
| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | No | Health check |
| GET | `/metrics` | No | Prometheus metrics |

---

## Socket.IO Events (`/socket.io`)

### Client → Server
| Event | Payload | Description |
|-------|---------|-------------|
| `connect` | `{workspace_id?, user_id?, token?}` | Authenticate & join workspace room |
| `subscribe` | `{scan_id?, asset_id?}` | Join scan/asset room for realtime updates |
| `unsubscribe` | `{scan_id?, asset_id?}` | Leave scan/asset room |

### Server → Client (broadcast to `workspace:{id}` room)
| Event | Payload | Trigger |
|-------|---------|---------|
| `connected` | `{workspace_id, socket_id}` | On connect |
| `scan_started` | scan object | Scan queued |
| `scan_progress` | scan object | Periodic broadcast loop |
| `scan_completed` | scan object | Scan finished |
| `scan_failed` | scan object | Scan failed |
| `finding_created` | finding object | New finding inserted |
| `asset_updated` | asset object | Asset updated |

---

## Celery Tasks

| Task | Queue | Description |
|------|-------|-------------|
| `run_scan_task` | scanners | Execute scan (nuclei, nmap, etc.) |
| `cancel_scan` | scanners | Cancel running scan |
| `retry_failed_scan` | scanners | Retry helper |
| `run_robot_task` | scanners | Execute robot automation |
| `run_authenticated_scan` | scanners | Execute authenticated scan |
| `generate_report` | default | Generate report (PDF/DOCX) |
| Scheduler beat | scheduler | Trigger scheduled scans |

---

## Database Models (SQLAlchemy Async)

| Model | Key Fields | Relationships |
|-------|------------|---------------|
| `User` | id, email, hashed_password, full_name, role, is_active, is_verified, last_login, mfa_secret, mfa_enabled, recovery_codes | WorkspaceMember, APIKey, Finding (assigned_to, verified_by) |
| `Workspace` | id, name, slug, plan, asset_limit, concurrent_scan_limit, scheduled_scan_limit, settings (JSONB), stripe_* | Asset, Scan, Finding, ScheduledScan, ScanTemplate, Report, Robot, WorkspaceMember |
| `WorkspaceMember` | id, workspace_id, user_id, role (owner/admin/member/viewer) | User, Workspace |
| `Asset` | id, workspace_id, target, type (hostname/ip/cidr/url), description, risk_level, risk_score, total_scans, vulnerabilities_count, deleted_at | Scan, Finding, Workspace |
| `Scan` | id, workspace_id, asset_id, name, type, target, status, progress, intensity, is_authenticated, auth_config, scanner_config, celery_task_id, started_at, completed_at, error_message, findings_count, critical_count, high_count, medium_count, low_count, info_count | Asset, Finding, ScanLog, ScheduledScan |
| `ScanLog` | id, scan_id, level, message, step, progress, meta | Scan |
| `ScanTemplate` | id, workspace_id, name, description, category, scan_type, intensity, scanner_config, is_authenticated, auth_config, is_system, is_public, usage_count | Workspace |
| `Finding` | id, workspace_id, scan_id, asset_id, title, description, severity, status, target_url, parameter, method, cwe_id, cve_ids, cvss_score, source_scanner, evidence (JSONB), reproduction_steps, proof_of_concept, remediation, remediation_complexity, references, tags, fingerprint, is_duplicate, duplicate_of, assigned_to, verified_by, verified_at, fixed_at, closed_at, source_finding_id, source_rule_id, compliance_mappings | Scan, Asset, FindingComment, FindingAttachment |
| `FindingComment` | id, finding_id, user_id, content, is_internal | Finding, User |
| `FindingAttachment` | id, finding_id, filename, file_size, mime_type, uploaded_by, uploaded_at | Finding |
| `Report` | id, workspace_id, template_id, scan_ids[], finding_ids[], asset_ids[], title, description, format, status, file_path, file_size, page_count, generation_error, generation_duration_seconds, severity_filter[], status_filter[], date_range, compliance_frameworks[], download_count, last_downloaded_at, expires_at, completed_at | Workspace |
| `ReportTemplate` | id, workspace_id, name, description, type, compliance_frameworks[], template_content, template_variables, logo_path, primary_color, secondary_color, font_family, footer_text, sections[], default_formats[], is_default, is_system | Workspace |
| `ScheduledScan` | id, workspace_id, name, description, scan_type, target, asset_ids[], intensity, is_authenticated, auth_config, scanner_config, frequency, cron_expression, timezone, start_time, end_time, max_duration_minutes, status, last_run, next_run, last_run_status, last_run_error, consecutive_failures, notify_on_*, max_retries, retry_delay_minutes, notification_integration_ids[] | Workspace |
| `Robot` | id, workspace_id, name, description, script, status, schedule, last_run, next_run | RobotRun, Workspace |
| `RobotRun` | id, robot_id, status, started_at, completed_at, output, error | Robot |
| `AuthToken` (base) | PasswordResetToken, EmailVerificationToken, InviteToken | User |
| `APIKey` | id, user_id, name, key_hash, prefix, expires_at, last_used_at, is_active | User |

---

## Actual Features Present

| Feature | Backend | Frontend | Notes |
|---------|---------|----------|-------|
| User registration/login/JWT | ✅ | ✅ | Access + refresh tokens, bcrypt |
| Workspace & team management | ✅ | ✅ | Roles: owner/admin/member/viewer |
| Asset/target management | ✅ | ✅ | Domain, IP, CIDR, URL; soft delete |
| Scan execution (multiple types) | ✅ | ✅ | Queued via Celery, realtime progress |
| Scan scheduling | ✅ | ✅ | Cron + frequencies, scheduler beat |
| Scan templates | ✅ | ✅ | Reusable scan configs |
| Findings management | ✅ | ✅ | CRUD, bulk update, comments, attachments |
| Reports generation | ✅ | ✅ | PDF/DOCX/HTML/JSON/CSV, Celery task |
| Report templates | ✅ | ✅ | Customizable templates |
| Diff/monitoring | ✅ | ✅ | Scan comparison, alerts |
| Robots/automation | ✅ | ✅ | Custom scripts, scheduled runs |
| Attack surface mapping | ✅ | ✅ | Hostname, IP, port, service, tech |
| Integrations | ✅ | ✅ | 8 catalog items, webhook events |
| MFA (TOTP + recovery codes) | ✅ | ❓ | Backend only, check frontend |
| SSO (SAML/OIDC) | ✅ (partial) | ❓ | Metadata endpoints only |
| Billing (Stripe) | ✅ | ✅ | Checkout, portal, webhooks |
| Authenticated scanning | ✅ | ❓ | Form/login/cookie auth configs |
| API keys | ✅ | ✅ | For programmatic access |
| Prometheus metrics | ✅ | - | /metrics endpoint |
| Health check | ✅ | - | /api/health |
| Socket.IO realtime | ✅ | ✅ | Scan progress, findings, assets |

---

## Endpoints for F1 Auth Phase

- **Register**: `POST /api/auth/register` — body: `{email, password, full_name?}`
- **Login**: `POST /api/auth/login` — body: `{email, password}`
- **Refresh**: `POST /api/auth/refresh` — body: `{refresh_token}`
- **Logout**: `POST /api/auth/logout` — header: `Authorization: Bearer <access>`
- **Me**: `GET /api/auth/me` — header: `Authorization: Bearer <access>`

---

## Checklist Mapping Notes

### Features in checklist but NOT in code → mark `[~] — N/A: fitur tidak ada`
- None found yet — all major checklist areas have backend implementation

### Features in code but NOT in checklist → add to TAMBAHAN
- MFA/TOTP (backend complete, frontend unknown)
- SSO SAML/OIDC (backend partial, metadata only)
- Billing/Stripe subscription management
- API Keys management
- Robots/automation scripting
- Diff/monitoring (scan comparison, alerts)
- Attack surface mapping
- Authenticated scanning
- Report templates (customizable)
- Finding attachments & comments
- Prometheus metrics / health endpoint
- Integration webhook dispatch (finding_created, scan_completed, etc.)

---

## Scope Compliance Check

- Frontend ports 3000/3001: **NOT RUNNING** (built dist exists)
- Backend port 8000: **RUNNING** (Starlette, no /docs)
- Postgres 5433: **RUNNING**
- Redis 6379: **RUNNING**
- Celery workers: **RUNNING** (scanners + scheduler queues)
- Socket.IO: **RUNNING** on `/socket.io`
- Allowed scan targets: `scanme.nmap.org`, `testphp.vulnweb.com`, `testasp.vulnweb.com`, `127.0.0.1:3002`, `127.0.0.1:8081`
- Negative test inputs (SSRF): `127.0.0.1`, `localhost`, `10.0.0.1`, `192.168.1.1`, `169.254.169.254`, `::1`, `0.0.0.0`

---

## Open Questions for F0

1. Frontend dev server not running — need to start `npm run dev` in frontend/ or serve `dist/` for testing
2. No `/docs` endpoint (Starlette, not FastAPI) — API docs must be read from source
3. MFA/SSO frontend pages — need to verify if Settings page includes MFA setup
4. Local lab targets (Juice Shop/DVWA) — not confirmed available