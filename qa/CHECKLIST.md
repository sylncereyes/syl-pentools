# QA Checklist — Syl-Pentools
Status: `[ ]` todo · `[x]` lulus · `[!]` gagal (BUG-XXX) · `[~]` blocked / N/A / MANUAL
Prioritas: P0 kritis · P1 tinggi · P2 sedang · P3 rendah
Item untuk fitur yang tidak ada → `[~] — N/A: fitur tidak ada`.

## SETUP (F0)
- [x] SETUP-01 (P0) Smoke: frontend, API /api/health, Socket.IO, Postgres, Redis, Celery — bukti: qa/evidence/SETUP-01/
- [x] SETUP-02 (P0) Discovery selesai: qa/reports/app_map.md — bukti: qa/evidence/SETUP-02/
- [x] SETUP-03 (P1) Checklist dipetakan ke fitur nyata atau N/A — bukti: qa/evidence/SETUP-03/
- [x] SETUP-04 (P1) Akun uji User A tersedia. User B dibuat saat F1 — bukti: qa/evidence/SETUP-04/
- [~] SETUP-05 (P2) Lab target lokal (Juice Shop/DVWA) tersedia atau pakai target publik legal — N/A: target lokal tidak dikonfirmasi, pakai target publik di scope

## AUTH (F1)
- [ ] AUTH-01 (P0) Register data valid berhasil
- [ ] AUTH-02 (P0) Register email duplikat ditolak
- [ ] AUTH-03 (P1) Validasi email dan password policy
- [ ] AUTH-04 (P1) Body kosong / tipe salah / JSON rusak → 4xx, bukan 500
- [ ] AUTH-05 (P2) Mass assignment: role/is_admin saat register diabaikan
- [ ] AUTH-06 (P0) Login valid → token diterima, UI redirect dashboard
- [ ] AUTH-07 (P0) Password salah → 401/400 dengan pesan generik
- [ ] AUTH-08 (P0) Endpoint terproteksi tanpa token / token rusak → 401
- [ ] AUTH-09 (P0) JWT alg:none, signature salah, claim role dimanipulasi → ditolak
- [ ] AUTH-10 (P0) Access token expired → refresh berhasil
- [ ] AUTH-11 (P1) Refresh token: rotation, reuse detection, revoke saat logout
- [ ] AUTH-12 (P0) Logout: token tidak valid lagi (jika ada blacklist) dan state UI bersih
- [ ] AUTH-13 (P1) Token tidak valid setelah ganti password
- [ ] AUTH-14 (P1) Rate limit / lockout login (maks sesuai limits)
- [ ] AUTH-15 (P1) Back button setelah logout tidak menampilkan halaman terproteksi
- [ ] AUTH-16 (P1) Forgot/reset password, token sekali pakai dan expiry
- [ ] AUTH-17 (P0) Ubah password butuh password lama
- [ ] AUTH-18 (P0) Response user tidak memuat hash/field internal
- [ ] AUTH-19 (P2) Profil: edit, upload avatar (tipe/ukuran), API key
- [ ] AUTH-20 (P2) Timing login user ada vs tidak ada tidak berbeda signifikan

## TARGET (F2)
- [ ] TGT-01 (P0) Tambah target: domain, subdomain, IP, CIDR, URL
- [ ] TGT-02 (P0) Format invalid (spasi, `..`, 300 char, skema aneh) → 4xx
- [ ] TGT-03 (P0) negative_test_inputs (loopback, private, metadata) ditolak
- [ ] TGT-04 (P0) Verifikasi kepemilikan (DNS/meta/file), jika ada
- [ ] TGT-05 (P0) Scan intrusif pada target belum terverifikasi diblokir, jika ada
- [ ] TGT-06 (P0) Target User A tidak bisa dilihat/diubah/dihapus User B (IDOR)
- [ ] TGT-07 (P1) Edit, hapus target dan dampak ke scan/schedule
- [ ] TGT-08 (P1) Duplikat target
- [ ] TGT-09 (P1) Kredensial/auth config target terenkripsi (cek DB via SELECT) dan masked di API
- [ ] TGT-10 (P2) Import bulk, tag, filter, search, batas jumlah
- [ ] TGT-11 (P2) IDN/unicode dan wildcard/exclusion

## SCANNER (F3)
- [ ] SCAN-01 (P0) Start scan default ke target legal → Queued → Running → Finished
- [ ] SCAN-02 (P0) Status konsisten di UI, API, dan DB
- [ ] SCAN-03 (P0) Progress/log real-time via Socket.IO
- [ ] SCAN-04 (P0) Stop scan menghentikan task Celery
- [ ] SCAN-05 (P1) Rescan / clone konfigurasi
- [ ] SCAN-06 (P1) Target unreachable/DNS gagal → Failed dengan pesan jelas, tidak hang
- [ ] SCAN-07 (P1) Sertifikat invalid / redirect chain ditangani
- [ ] SCAN-08 (P1) Scan paralel dan batas konkurensi
- [ ] SCAN-09 (P1) Double-click start tidak membuat task ganda
- [ ] SCAN-10 (P1) Scan tetap berjalan setelah browser ditutup
- [ ] SCAN-11 (P1) Scheduler: buat jadwal, edit, pause, hapus; berjalan tepat waktu (queue scheduler)
- [ ] SCAN-12 (P1) Timezone jadwal benar
- [ ] SCAN-13 (P2) History: filter, search, sort, pagination
- [ ] SCAN-14 (P2) Compare dua scan
- [ ] SCAN-15 (P1) Recon: subdomain, DNS, WHOIS, fingerprint (yang ada)
- [ ] SCAN-16 (P1) Network: port scan, service detection (yang ada)
- [ ] SCAN-17 (P1) Web scanner: true positive pada lab (DVWA/Juice Shop/vulnweb), false positive pada target bersih
- [ ] SCAN-18 (P2) API Fuzzer: input, wordlist, rate limit, hasil
- [ ] SCAN-19 (P2) Robots task dan fitur terkait
- [ ] SCAN-20 (P2) SSL/TLS, headers, CORS checker (yang ada)
- [ ] SCAN-21 (P1) Parameter scan tidak bisa command injection (opsi tool, argumen)
- [ ] SCAN-22 (P2) Worker down/restart saat scan — MANUAL

## FINDINGS & LAPORAN (F4)
- [ ] FIND-01 (P0) Detail finding lengkap (severity, CVSS/CWE, evidence, remediation)
- [ ] FIND-02 (P0) Severity konsisten dengan skor
- [ ] FIND-03 (P0) Evidence/payload di-escape (tidak ada stored XSS di UI)
- [ ] FIND-04 (P0) Finding User A tidak bisa diakses User B (IDOR)
- [ ] FIND-05 (P1) Ubah status (Open/Fixed/False Positive/…), assign, komentar
- [ ] FIND-06 (P2) Filter, sort, bulk action, deduplikasi
- [ ] RPT-01 (P0) Generate laporan (task Celery) berhasil dan akurat
- [ ] RPT-02 (P1) Format export yang tersedia (PDF/HTML/CSV/JSON)
- [ ] RPT-03 (P1) Payload/unicode di laporan tidak merusak layout dan tidak mengeksekusi script
- [ ] RPT-04 (P0) Laporan User A tidak bisa diunduh User B
- [ ] RPT-05 (P2) Laporan besar, share link (expiry/revoke), jika ada

## API & WEBSOCKET (F5)
- [ ] API-01 (P0) Tanpa/invalid token → 401 di semua endpoint privat
- [ ] API-02 (P0) Semua endpoint ber-ID: akses resource user lain → 403/404
- [ ] API-03 (P1) CRUD targets/scans/findings/reports sesuai OpenAPI
- [ ] API-04 (P1) Validasi input → 400/422, tanpa 500/traceback
- [ ] API-05 (P1) Pagination, filter, sort konsisten
- [ ] API-06 (P1) Rate limiting (429)
- [ ] API-07 (P1) CORS: Origin tak dikenal + credentials ditolak
- [ ] API-08 (P2) POST ganda / idempotency
- [ ] API-09 (P2) /docs akurat dan tidak membocorkan endpoint internal
- [ ] API-10 (P2) Webhook / integrasi (label syl-pentools), jika ada
- [ ] WS-01 (P1) Socket.IO tanpa token / token palsu ditolak
- [ ] WS-02 (P0) Tidak bisa join room / subscribe scan milik user lain
- [ ] WS-03 (P1) Event tidak bocor lintas user
- [ ] WS-04 (P2) Reconnect setelah refresh token dan fallback polling

## SECURITY (F6)
- [ ] SEC-01 (P0) Broken access control: IDOR, forced browsing, privilege escalation
- [ ] SEC-02 (P0) Injection (SQLi/command/SSTI) pada input target, parameter scan, import
- [ ] SEC-03 (P0) XSS stored/reflected/DOM di hasil scan, nama target, komentar, laporan
- [ ] SEC-04 (P0) SSRF: scanner/webhook/import tidak bisa menjangkau internal/metadata
- [ ] SEC-05 (P0) Scanner tidak bisa diarahkan ke infrastruktur sendiri
- [ ] SEC-06 (P0) Blacklist domain sensitif (.gov, .mil, internal) berfungsi
- [ ] SEC-07 (P0) Pembatasan scan agresif (rate/thread cap)
- [ ] SEC-08 (P1) Security headers frontend dan API
- [ ] SEC-09 (P1) Debug mode, traceback, header versi/server bocor
- [ ] SEC-10 (P1) CSRF dan cookie flags, jika cookie dipakai
- [ ] SEC-11 (P1) Bypass kuota / bypass verifikasi target (business logic)
- [ ] SEC-12 (P1) File upload: tipe, ukuran, path traversal
- [ ] SEC-13 (P1) Mass assignment / parameter pollution
- [ ] SEC-14 (P1) Open redirect, clickjacking, host header injection
- [ ] SEC-15 (P1) Audit trail scan (siapa, target, kapan)
- [ ] SEC-16 (P1) Log tanpa data sensitif
- [ ] SEC-17 (P1) SAST: bandit + semgrep
- [ ] SEC-18 (P1) SCA: pip-audit + npm audit
- [ ] SEC-19 (P1) Secret scan di source (file:baris saja)
- [ ] SEC-20 (P2) ZAP baseline pasif terhadap API dan frontend
- [ ] SEC-21 (P2) Review docker-compose.yml: port terbuka, secret, user root
- [ ] SEC-22 (P1) Password tersimpan bcrypt (SELECT, tanpa mencetak hash)

## PERFORMANCE (F7)
- [ ] PERF-01 (P1) Load test API read (login, list) dalam limits
- [ ] PERF-02 (P1) p95 < threshold, error rate < threshold
- [ ] PERF-03 (P1) Banyak scan bersamaan: queue stabil
- [ ] PERF-04 (P2) Volume data besar: list dan pagination
- [ ] PERF-05 (P2) Socket.IO banyak koneksi
- [ ] PERF-06 (P2) Web Vitals pada build produksi — SEMI (npm run build && npm run preview)
- [ ] PERF-07 (P2) Jaringan lambat (throttling)
- [ ] PERF-08 (P2) Waktu generate laporan besar

## UI / UX / A11Y / KOMPATIBILITAS (F8)
- [ ] UI-01 (P1) Alur utama: daftar → target → scan → hasil → laporan
- [ ] UI-02 (P2) Pesan error jelas, loading/empty/success state
- [ ] UI-03 (P2) Konfirmasi aksi destruktif
- [ ] UI-04 (P2) Konsistensi UI dan terminologi
- [ ] UI-05 (P2) axe-core pada halaman publik, login, dashboard, hasil scan
- [ ] UI-06 (P2) Navigasi keyboard dan focus indicator
- [ ] UI-07 (P2) Kontras warna dan badge severity tidak hanya warna
- [ ] UI-08 (P1) Chromium dan Firefox (Playwright)
- [ ] UI-09 (P1) Viewport 320/375/768/1024/1366/1920 dan Pixel 7
- [ ] UI-10 (P2) Frontend berfungsi di port 3000 dan 3001 (CORS, Socket.IO origin)
- [ ] UI-11 (P2) Timezone dan format tanggal
- [ ] UI-12 (P3) Dark/light mode, shortcut, onboarding (jika ada)

## DATA & RELIABILITY (F9)
- [ ] DATA-01 (P1) UI ↔ API ↔ DB konsisten (SELECT)
- [ ] DATA-02 (P1) Race condition: request paralel create/start scan/kuota
- [ ] DATA-03 (P1) Hapus data: cascade, tanpa orphan row
- [ ] DATA-04 (P2) Constraint unique/FK/not null
- [ ] REL-01 (P1) Redis/DB/worker down → API fail gracefully — MANUAL
- [ ] REL-02 (P1) Restart API/worker tanpa kehilangan job — MANUAL
- [ ] REL-03 (P2) Health check endpoint
- [ ] REL-04 (P2) Backup/restore — MANUAL

## TAMBAHAN (hasil discovery)
<!-- Agent: tambahkan item baru di sini -->

## MANUAL / UAT
- [ ] UAT-01 (P1) Skenario persona pentester/security manager — MANUAL
- [ ] UAT-02 (P1) Validasi akurasi hasil scan oleh pentester — MANUAL
- [ ] UAT-03 (P1) Sign-off stakeholder — MANUAL

## Exit criteria
- 100% P0 dan ≥95% P1 dieksekusi dan lulus (kecuali N/A/MANUAL terdokumentasi)
- Tidak ada bug Critical/High terbuka; tidak ada vulnerability Critical/High terbuka
- Performance memenuhi threshold scope.yml; FINAL_REPORT.md dibuat dengan rekomendasi Go/No-Go
