# QA Retest-1 Report — Pentest Clone (syl-pentools)

**Target aplikasi:** Frontend `http://localhost:3000` (React + Vite) · Backend `http://localhost:8000` (FastAPI/Starlette + Socket.IO)
**Tanggal pengujian:** 2026-11-19
**Tester:** Automated QA
**Versi/commit:** syl-pentools (Python 3.11.9, PostgreSQL 18, Redis 7)
**Test sebelumnya:** QA_Report.md (2026-11-19)

---

## Ringkasan Hasil Retest

| No | Modul | Jumlah Test Case | Pass | Fail | Blocked | Status vs QA_Report |
|----|-------|------------------|------|------|---------|---------------------|
| 1  | Autentikasi & Akun | 14 | 13 | 1 | 0 | ➡️ Sama (MFA status broken) |
| 2  | Workspace & Tim | 9 | 9 | 0 | 0 | ✅ Sama (All working) |
| 3  | Assets | 6 | 5 | 1 | 0 | ➡️ Sama (Validation inconsistent) |
| 4  | Scans | 14 | 12 | 2 | 0 | ➡️ Sama (Auth scan, diff broken) |
| 5  | Scheduled Scans & Templates | 6 | 6 | 0 | 0 | ✅ Sama (All working) |
| 6  | Findings | 7 | 7 | 0 | 0 | ✅ Sama (All working) |
| 7  | Reports | 5 | 4 | 1 | 0 | ➡️ Sama (Gen permission denied) |
| 8  | Diff | 5 | 0 | 5 | 0 | ➡️ Sama (All UUID serialization error) |
| 9  | Robots/AI Pentests | 5 | 5 | 0 | 0 | ✅ Sama (All working) |
| 10 | Dashboard & Attack Surface | 3 | 3 | 0 | 0 | ✅ Sama (All working) |
| 11 | Integrations | 5 | 4 | 1 | 0 | ➡️ Sama (Only 8/11 integrations) |
| 12 | Billing | 5 | 1 | 4 | 0 | ➡️ Sama (Needs Stripe config) |
| 13 | Settings | 4 | 0 | 4 | 0 | ➡️ Sama (No backend endpoints) |
| 14 | Keamanan | 11 | 9 | 2 | 0 | ➡️ Sama (CORS, brute-force) |
| 15 | Performa | 5 | 4 | 1 | 0 | ➡️ Sama (Pagination hardcoded) |
| 16 | Reliabilitas | 5 | 5 | 0 | 0 | ✅ Sama (All working) |
| 17 | Kompatibilitas | 3 | 3 | 0 | 0 | ✅ Sama (All working) |
| 18 | Usability | 4 | 3 | 1 | 0 | ➡️ Sama (No settings endpoints) |
| 19 | Maintainability | 3 | 3 | 0 | 0 | ✅ Sama (All working) |

**Total:** 121 test case | **Pass:** 100 | **Fail:** 21 | **Blocked:** 0

---

## Perbandingan dengan QA_Report.md (Test Sebelumnya)

### ❌ **Bug Critical (P0) - BELUM DIPERBAIKI (4/4)**

| # | Bug | Status Retest | Detail Error |
|---|-----|---------------|--------------|
| 1 | **MFA Status Endpoint** | ❌ Masih Error | `TypeError: Object of type datetime is not JSON serializable` di `GET /api/mfa/status` |
| 2 | **Diff Endpoints (5 endpoint)** | ❌ Masih Error | `TypeError: Object of type UUID is not JSON serializable` di semua endpoint diff |
| 3 | **Authenticated Scan** | ❌ Masih Error | `AttributeError: 'function' object has no attribute 'delay'` di `POST /api/scans/authenticated` |
| 4 | **Report Generation** | ❌ Masih Error | `[Errno 13] Permission denied: '/app'` di `POST /api/reports` |

### ❌ **Bug High (P1) - BELUM DIPERBAIKI (3/3)**

| # | Bug | Status Retest | Detail |
|---|-----|---------------|--------|
| 5 | **CORS Preflight (OPTIONS)** | ❌ Masih Error | `AuthEnforcementMiddleware` reject OPTIONS sebelum CORS middleware handle |
| 6 | **Auth Rate Limit Exempt** | ❌ Masih Exempt | `/api/auth/*` dikecualikan dari rate limiting → no brute-force protection |
| 7 | **Findings Pagination** | ❌ Hardcoded 500 | `limit`/`offset` query param diabaikan, hardcoded `.limit(500)` |

### ⚠️ **Bug Medium/Low - BELUM DIPERBAIKI**

| # | Bug | Status Retest |
|---|-----|---------------|
| 8 | Asset validation inconsistent | ❌ Direct create accepts "invalid" hostname |
| 9 | Settings endpoints missing | ❌ No backend endpoints for profile/notifications/appearance |
| 10 | Integrations count mismatch | ❌ Only 8 integrations (missing: Burp, Nucleus, MCP) |
| 11 | Billing needs Stripe config | ❌ Checkout/portal/cancel/resume all fail |

---

## Detail Hasil Retest per Modul

### 1. Autentikasi & Akun ⚠️ (13/14 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| Register user baru | ✅ Pass | Validasi email/password, duplikat ditolak |
| Login kredensial benar | ✅ Pass | Token tersimpan |
| Login kredensial salah | ✅ Pass | Error jelas, tidak bocor info |
| Logout | ✅ Pass | Token invalid setelahnya |
| Refresh token | ✅ Pass | Memperpanjang sesi benar |
| Lihat profil sendiri | ✅ Pass | `/api/auth/me` working |
| Lihat & revoke sesi aktif | ✅ Pass | List, revoke single/all working |
| Ganti password | ✅ Pass | Perlu password lama, validasi kekuatan |
| Lupa password → reset | ✅ Pass | Token kadaluarsa setelah dipakai |
| Verifikasi email | ✅ Pass | Link valid sekali pakai |
| Setup MFA/TOTP (setup, enable, verify) | ✅ Pass | QR code, enable, verify working |
| Disable MFA & recovery codes | ✅ Pass | Generate/verify recovery codes working |
| **MFA Status** | ❌ **Fail** | **JSON serialization error (datetime)** |
| SSO/Join undangan | ⚠️ N/A | Not tested |

### 2. Workspace & Tim ✅ (9/9 Pass - **Sama**)
Semua test case pass: workspace default, list, invite, accept, role update, delete member, cancel invite, API keys CRUD.

### 3. Assets ⚠️ (5/6 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| Tambah asset manual | ✅ Pass | Muncul di list |
| **Validasi input invalid** | ❌ **Fail** | `"invalid"` diterima sebagai hostname (direct create) |
| Import asset dari file | ✅ Pass | Format didukung, invalid dilaporkan/skip |
| Lihat detail asset | ✅ Pass | GET `/api/assets/{id}` |
| Hapus asset | ✅ Pass | Soft delete (deleted_at) |
| Risk level asset | ✅ Pass | Tampil dan ter-update |

### 4. Scans ⚠️ (12/14 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| Buat scan tiap jenis | ✅ Pass | Website, Network, Port, Subdomain, Recon |
| Validasi form "New Scan" | ✅ Pass | Target wajib, opsi sesuai tipe |
| Status scan alur | ✅ Pass | queued → running → completed/failed |
| Progress real-time Socket.IO | ✅ Pass | Logs ter-update via polling |
| Lihat detail scan | ✅ Pass | Dengan logs dan findings |
| Lihat log scan | ✅ Pass | Logs relevan dan terbaca |
| Lihat findings hasil scan | ✅ Pass | `/scans/{id}/findings` |
| Retry scan gagal | ✅ Pass | Scan ulang dengan opsi sama |
| Hapus scan | ✅ Pass | Status cancelled, findings retained |
| **Authenticated scan** | ❌ **Fail** | `AttributeError: 'function' object has no attribute 'delay'` |
| Scan target invalid/unreachable | ✅ Pass | Error handled, tidak stuck |
| Scan bersamaan (2+) | ✅ Pass | Tidak race condition |
| Scan findings pagination | ⚠️ N/A | Hardcoded 500 limit |

### 5. Scheduled Scans & Templates ✅ (6/6 Pass - **Sama**)
Semua pass: create schedule, edit/delete, manual trigger, auto-run, CRUD template, use template.

### 6. Findings ✅ (7/7 Pass - **Sama**)
Semua pass: list dengan filter, create manual, update status, detail, comments, bulk update.

### 7. Reports ⚠️ (4/5 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| **Generate report baru** | ❌ **Fail** | `[Errno 13] Permission denied: '/app'` |
| Lihat daftar & detail report | ✅ Pass | GET `/api/reports`, `/api/reports/{id}` |
| Download report (PDF/DOCX) | ⚠️ N/A | Generation fails |
| Hapus report | ✅ Pass | DELETE working |
| Report template CRUD | ✅ Pass | Branding/kustomisasi tersimpan |

### 8. Diff / Perbandingan Scan ❌ (0/5 Pass - **Sama**)
**SEMUA ENDPOINT ERROR:** `TypeError: Object of type UUID is not JSON serializable`
- `GET /api/diff/compare`
- `GET /api/diff/latest`
- `GET /api/diff/workspace`
- `GET /api/diff/alerts`
- `GET /api/diff/run`

### 9. Robots / AI Pentests ✅ (5/5 Pass - **Sama**)
Semua pass: create robot, run robot, view run history, edit/delete, error handling.

### 10. Dashboard & Attack Surface ✅ (3/3 Pass - **Sama**)
Dashboard analytics, data refresh, attack surface map/stats - semua working.

### 11. Integrations ⚠️ (4/5 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| **List 11 integrasi** | ❌ **Fail** | Hanya 8 (Slack, Teams, Jira, Webhook, GitHub, Discord, AWS, Vanta) |
| Konfigurasi integrasi | ✅ Pass | Webhook/Slack configured successfully |
| Toggle enable/disable | ✅ Pass | Status tersimpan |
| Notifikasi terkirim | ⚠️ N/A | Not tested (requires external) |
| Burp Import | ⚠️ N/A | Not tested |

### 12. Billing (Stripe) ⚠️ (1/5 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| Checkout | ❌ Fail | `Failed to create billing customer` |
| Customer portal | ❌ Fail | `No billing account found` |
| Subscription status | ✅ Pass | Returns free plan limits |
| Cancel & resume | ❌ Fail | `Failed to cancel subscription` |
| Webhook Stripe | ❌ Fail | Not configured |

### 13. Settings ❌ (0/4 Pass - **Sama**)
**NO BACKEND ENDPOINTS** untuk: update profile, notifications, appearance, tabs settings.

### 14. Keamanan ⚠️ (9/11 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| Auth enforcement (401 tanpa token) | ✅ Pass | Middleware working |
| IDOR check (workspace lain) | ✅ Pass | Asset not found untuk user lain |
| Rate limiting general | ✅ Pass | 100 req/min working (90/15 = 200/429) |
| **CORS preflight (OPTIONS)** | ❌ **Fail** | AuthEnforcementMiddleware reject OPTIONS |
| Password hashing | ✅ Pass | BCrypt, tidak dikembalikan di API |
| Token/JWT tidak bocor | ✅ Pass | Tidak di URL/log |
| XSS escape (input sanitization) | ⚠️ Partial | Stored as-is, frontend must escape |
| File upload validasi | ✅ Pass | Import validates targets |
| **Brute-force protection** | ❌ **Fail** | Auth paths exempt dari rate limit |
| /metrics tidak bocor sensitif | ✅ Pass | Hanya system/request metrics |

### 15. Performa ⚠️ (4/5 Pass - **Sama**)
| Test Case | Status | Notes |
|-----------|--------|-------|
| Load halaman < 2-3 detik | ✅ Pass | Frontend ~1-8ms, Dashboard data <50ms |
| API response time | ✅ Pass | Assets: 5-20ms, Findings: ~10ms |
| **Pagination/limit** | ❌ **Fail** | Findings hardcoded 500, no limit param |
| Load test scan paralel | ✅ Pass | 3 scan bersamaan OK, CPU/RAM normal |
| UI responsif saat scan | ✅ Pass | Frontend tidak freeze |

### 16. Reliabilitas ✅ (5/5 Pass - **Sama**)
Error handling, invalid input handling, page refresh saat scan - semua working.

### 17. Kompatibilitas ✅ (3/3 Pass - **Sama**)
Python 3.11.9 (venv_py314_broken exists but not used).

### 18. Usability ⚠️ (3/4 Pass - **Sama**)
Validasi inline form OK, alur utama Asset→Scan→Finding→Report works via API. Settings endpoints missing.

### 19. Maintainability ✅ (3/3 Pass - **Sama**)
Log backend cukup, /health & /metrics konsisten, error 4xx/5xx di metrics.

---

## Analisis Root Cause Bug yang Masih Ada

### P0 - Critical (Root Cause di Kode)

1. **MFA Status** - `services/mfa_service.py` return datetime object, perlu convert ke ISO string di serializer
2. **Diff Endpoints** - `services/diff_service.py` return UUID objects, perlu serialize ke string
3. **Authenticated Scan** - `main.py` line 3728 import `run_authenticated_scan` sebagai function tapi call `.delay()` (Celery task pattern)
4. **Report Generation** - `REPORTS_DIR` di config/settings.py pointing ke `/app` yang tidak writable

### P1 - High (Root Cause di Middleware/Config)

5. **CORS OPTIONS** - `AuthEnforcementMiddleware` di `main.py` line ~2160 check path sebelum CORS middleware, OPTIONS tidak di-handle
6. **Auth Rate Limit** - `RateLimitMiddleware` di `core/rate_limiter.py` line ~140 explicitly exempt `/api/auth/*`
7. **Findings Pagination** - `main.py` line ~1120 hardcoded `.limit(500)` tanpa baca query param

---

## Rekomendasi Perbaikan Prioritas (Sama dengan QA_Report)

### P0 - Critical (Harus diperbaiki sebelum rilis)
1. Fix MFA status endpoint - serialize datetime ke ISO string
2. Fix Diff endpoints - serialize UUID ke string
3. Fix Authenticated scan - convert function ke Celery task atau call dengan benar
4. Fix Report generation - set REPORTS_DIR ke writable path

### P1 - High (Keamanan & Fitur Utama)
5. Handle OPTIONS di AuthEnforcementMiddleware - allow preflight untuk CORS
6. Remove auth path exemption dari rate limiter - enable brute-force protection
7. Implement findings pagination - add `limit` dan `offset` query parameters

### P2 - Medium (Konsistensi & Kelengkapan)
8. Standardize asset validation - apply same validation ke direct create
9. Add settings endpoints - profile, notifications, appearance
10. Add missing integrations - Burp, Nucleus, MCP
11. Configure Stripe untuk billing flow testing

### P3 - Low (Kualitas & DX)
12. Fix CORS preflight untuk unauthenticated requests
13. Add attachment upload untuk findings
14. Improve error messages
15. Add API documentation (OpenAPI/Swagger)
16. Clean up venv_py314_broken

---

## Rekomendasi Rilis

**Status: NO-GO** (Sama dengan test sebelumnya)

**Alasan:** 4 bug critical (P0) masih ada dan memblokir fungsionalitas utama:
- MFA status tidak bisa diakses
- Semua diff functionality broken
- Authenticated scan tidak bisa dibuat
- Report generation gagal

**Syarat Go (Tidak berubah dari test sebelumnya):**
1. Semua P0 bugs diperbaiki
2. P1 security issues (rate limit, CORS) ditangani
3. Billing flow tested dengan Stripe test mode
4. Settings endpoints implemented (minimal profile)

**Estimasi perbaikan:** 2-3 hari development untuk P0+P1

---

## Environment Details (Retest)

- **Backend:** Starlette 0.27.0, Python 3.11.9, PostgreSQL 18 (port 5433), Redis 7
- **Frontend:** React 18 + Vite, served on port 3000
- **Workers:** Celery 5.3.4 (2 workers, queues: scanners, scheduler), APScheduler beat
- **Database:** Alembic migrations up to date
- **Test Data:** 2 users, 1 workspace, 4 assets, 5 scans, 17 findings, 2 robots, 1 scheduled scan, 1 template, 2 integrations configured

---

*Retest-1 Report generated by Automated QA on 2026-11-19*