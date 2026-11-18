import type { Asset, Finding, Integration, Scan } from '../store/useAppStore'

const BASE = (import.meta as any).env?.VITE_API_URL || ''

let authToken: string | null = null

export function setAuthToken(token: string | null) {
  authToken = token
  if (token) {
    localStorage.setItem('auth_token', token)
  } else {
    localStorage.removeItem('auth_token')
  }
}

export function getAuthToken(): string | null {
  if (authToken) return authToken
  if (typeof window !== 'undefined') {
    return localStorage.getItem('auth_token')
  }
  return null
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  const token = getAuthToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const workspaceId = typeof window !== 'undefined' ? localStorage.getItem('workspace_id') : null
  if (workspaceId) headers['X-Workspace-ID'] = workspaceId
  const response = await fetch(`${BASE}${path}`, {
    headers,
    ...init,
  })
  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const body = await response.json()
      if (body?.detail) message = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* ignore body parse errors */
    }
    if (response.status === 401 && token) {
      setAuthToken(null)
      if (typeof window !== 'undefined' && !window.location.pathname.startsWith('/login')) {
        window.location.assign('/login')
      }
    }
    throw new Error(message)
  }
  return response.json() as Promise<T>
}

export async function downloadWithAuth(path: string, filename: string): Promise<void> {
  const headers: Record<string, string> = {}
  const token = getAuthToken()
  if (token) headers['Authorization'] = `Bearer ${token}`
  const workspaceId = typeof window !== 'undefined' ? localStorage.getItem('workspace_id') : null
  if (workspaceId) headers['X-Workspace-ID'] = workspaceId
  const response = await fetch(`${BASE}${path}`, { headers })
  if (!response.ok) {
    let message = `Download failed (${response.status})`
    try {
      const body = await response.json()
      if (body?.detail) message = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } catch {
      /* ignore */
    }
    throw new Error(message)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}

export const authApi = {
  register: (payload: { email: string; password: string; full_name?: string }) =>
    request<{ access_token: string; refresh_token: string; token_type: string; user: UserInfo }>(
      '/api/auth/register',
      { method: 'POST', body: JSON.stringify(payload) }
    ),

  login: (payload: { email: string; password: string }) =>
    request<{ access_token: string; refresh_token: string; token_type: string; user: UserInfo }>(
      '/api/auth/login',
      { method: 'POST', body: JSON.stringify(payload) }
    ),

  refresh: (refresh_token: string) =>
    request<{ access_token: string; refresh_token: string; token_type: string }>(
      '/api/auth/refresh',
      { method: 'POST', body: JSON.stringify({ refresh_token }) }
    ),

  logout: () =>
    request<{ ok: boolean }>('/api/auth/logout', { method: 'POST' }),

  me: () =>
    request<UserInfo>('/api/auth/me'),
}

export interface UserInfo {
  id: string
  email: string
  full_name: string | null
  role: string
  is_active: boolean
  is_verified: boolean
  last_login: string | null
}

const SCAN_TYPE_LABELS: Record<string, string> = {
  website: 'Website Scanner',
  network: 'Network Scanner',
  port: 'Port Scanner',
  subdomain: 'Subdomain Finder',
  recon: 'Website Recon',
  password: 'Password Auditor',
  cms: 'CMS Scanner',
  api: 'API Scanner',
  cloud: 'Cloud Scanner',
  exploit: 'Exploitation (Sniper)',
  burp: 'Burp Import',
  fuzzer: 'URL Fuzzer',
  vhost: 'Virtual Host Finder',
  domain_finder: 'Domain Finder',
  google_hacking: 'Google Hacking',
  people_hunter: 'People Hunter',
  http_logger: 'HTTP Request Logger',
  ai_pentest: 'AI Pentest',
  full: 'Full Scan',
}

const SOURCE_LABELS: Record<string, string> = {
  WPScanScanner: 'WordPress Scanner',
  DrupalScanner: 'Drupal Scanner',
  NucleiCMSScanner: 'CMS Scanner',
  APIScanner: 'API Scanner',
  AzureScanner: 'Azure Scanner',
  GCPScanner: 'GCP Scanner',
  CloudScanner: 'Cloud Scanner',
  SniperExploiter: 'Sniper Exploiter',
  BurpImportScanner: 'Burp Import',
  NucleiScanner: 'Nuclei',
  NmapScanner: 'Nmap',
  SQLMapScanner: 'SQLMap',
}

const SCAN_STATUS_MAP: Record<string, Scan['status']> = {
  pending: 'pending',
  queued: 'pending',
  running: 'running',
  retrying: 'running',
  completed: 'completed',
  failed: 'failed',
  cancelled: 'failed',
  paused: 'pending',
}

const FINDING_STATUS_MAP: Record<string, Finding['status']> = {
  open: 'open',
  verified: 'verified',
  false_positive: 'false_positive',
  fixed: 'fixed',
  ignored: 'open',
  risk_accepted: 'open',
}

export type RawScan = {
  id: string
  scan_id?: string
  name?: string
  type: string
  target: string
  status: string
  progress?: number
  findings_count?: number
  error_message?: string | null
  started_at?: string
  completed_at?: string
  created_at?: string
}

export type RawFinding = {
  id: string
  title: string
  description?: string
  severity: string
  status: string
  target_url?: string
  source_scanner?: string
  created_at?: string
}

export type RawAsset = {
  id: string
  target: string
  type: string
  description?: string
  risk_level: string
  scans?: number
  created_at?: string
}

export type RawWorkspace = {
  id: string
  name: string
  asset_limit: number
  scan_limit: number
}

export interface BootstrapData {
  workspace: RawWorkspace
  assets: RawAsset[]
  scans: RawScan[]
  findings: RawFinding[]
  integrations: Integration[]
}

export function mapScan(raw: RawScan): Scan {
  return {
    id: raw.id,
    type: SCAN_TYPE_LABELS[raw.type] || raw.type,
    target: raw.target,
    status: SCAN_STATUS_MAP[raw.status] || 'pending',
    progress: Math.round(raw.progress ?? 0),
    startedAt: raw.started_at || raw.created_at || new Date().toISOString(),
    completedAt: raw.completed_at || undefined,
    findings: raw.findings_count,
  }
}

export function mapFinding(raw: RawFinding): Finding {
  return {
    id: raw.id,
    title: raw.title,
    target: raw.target_url || '',
    riskLevel: (['critical', 'high', 'medium', 'low'].includes(raw.severity) ? raw.severity : 'low') as Finding['riskLevel'],
    status: FINDING_STATUS_MAP[raw.status] || 'open',
    source: SOURCE_LABELS[raw.source_scanner || ''] || raw.source_scanner || 'Scanner',
    scanDate: (raw.created_at || new Date().toISOString()).slice(0, 10),
  }
}

export function mapAsset(raw: RawAsset): Asset {
  return {
    id: raw.id,
    target: raw.target,
    type: raw.type === 'ip_address' || raw.type === 'ip' ? 'ip' : 'hostname',
    description: raw.description || undefined,
    riskLevel: (raw.risk_level as Asset['riskLevel']) || 'none',
    scans: raw.scans ?? 0,
    createdAt: raw.created_at || new Date().toISOString(),
  }
}

export const api = {
  bootstrap: (workspaceId?: string | null) =>
    request<BootstrapData>(`/api/bootstrap${workspaceId ? `?workspace_id=${encodeURIComponent(workspaceId)}` : ''}`),

  createScan: (payload: {
    type: string
    target: string
    intensity?: string
    asset_type?: string
    is_authenticated?: boolean
  }) => request<RawScan>('/api/scans', { method: 'POST', body: JSON.stringify(payload) }),

  retryScan: (id: string) => request<RawScan>(`/api/scans/${id}/retry`, { method: 'POST' }),

  cancelScan: (id: string) => request<{ ok: boolean }>(`/api/scans/${id}`, { method: 'DELETE' }),

  createAsset: (payload: { target: string; type?: string; description?: string }) =>
    request<RawAsset>('/api/assets', { method: 'POST', body: JSON.stringify(payload) }),

  deleteAsset: (id: string) => request<{ ok: boolean }>(`/api/assets/${id}`, { method: 'DELETE' }),

  updateFinding: (id: string, payload: { status?: string }) =>
    request<RawFinding>(`/api/findings/${id}`, { method: 'PATCH', body: JSON.stringify(payload) }),

  toggleIntegration: (id: string) =>
    request<{ enabled: boolean }>(`/api/integrations/${id}/toggle`, { method: 'PATCH' }),

  configureIntegration: (id: string, config: Record<string, unknown>) =>
    request<{ ok: boolean; enabled: boolean }>(`/api/integrations/${id}`, {
      method: 'POST',
      body: JSON.stringify({ config, enabled: true }),
    }),

  attackSurface: (opts?: { workspaceId?: string | null; groupBy?: string; q?: string }) => {
    const params = new URLSearchParams()
    if (opts?.workspaceId) params.set('workspace_id', opts.workspaceId)
    if (opts?.groupBy) params.set('group_by', opts.groupBy)
    if (opts?.q) params.set('q', opts.q)
    const qs = params.toString()
    return request<SurfaceData>(`/api/attack-surface${qs ? `?${qs}` : ''}`)
  },
}


export interface TeamMember {
  id: string
  email: string | null
  full_name: string | null
  avatar_url: string | null
  role: 'owner' | 'admin' | 'member' | 'viewer'
  joined_at: string | null
  last_login: string | null
  is_active: boolean
  is_current_user: boolean
}

export interface PendingInvite {
  id: string
  email: string
  role: string
  expires_at: string | null
  created_at: string | null
}

export interface TeamResponse {
  workspace: { id: string; name: string; plan: string; team_member_limit: number | null }
  members: TeamMember[]
  pending_invites: PendingInvite[]
  roles: string[]
}

export interface ApiKeyRecord {
  id: string
  name: string
  prefix: string
  scopes: string[]
  last_used: string | null
  expires_at: string | null
  created_at: string | null
  revoked: boolean
  key?: string
}

export interface WorkspaceSummary {
  id: string
  name: string
  slug: string
  plan: string
  role: string | null
  asset_limit: number | null
  concurrent_scan_limit: number | null
  scheduled_scan_limit: number | null
  team_member_limit: number | null
}

export const workspaceApi = {
  list: () => request<WorkspaceSummary[]>('/api/workspaces'),
}

export const teamApi = {
  members: () => request<TeamResponse>('/api/team/members'),
  invite: (payload: { email: string; role: string }) =>
    request<PendingInvite & { token: string }>('/api/team/invites', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  acceptInvite: (token: string) =>
    request<{ ok: boolean; workspace_id: string; role: string }>('/api/team/invite/accept', {
      method: 'POST',
      body: JSON.stringify({ token }),
    }),
  updateRole: (userId: string, role: string) =>
    request<TeamMember>(`/api/team/members/${userId}`, {
      method: 'PATCH',
      body: JSON.stringify({ role }),
    }),
  removeMember: (userId: string) =>
    request<{ ok: boolean }>(`/api/team/members/${userId}`, { method: 'DELETE' }),
  cancelInvite: (inviteId: string) =>
    request<{ ok: boolean }>(`/api/team/invites/${inviteId}`, { method: 'DELETE' }),
}

export const apiKeysApi = {
  list: () => request<ApiKeyRecord[]>('/api/api-keys'),
  create: (payload: { name: string; scopes?: string[]; expires_days?: number | null }) =>
    request<ApiKeyRecord>('/api/api-keys', { method: 'POST', body: JSON.stringify(payload) }),
  revoke: (id: string) => request<{ ok: boolean }>(`/api/api-keys/${id}`, { method: 'DELETE' }),
}

export interface RobotStep {
  tool: string
  intensity?: string
}

export interface RobotStepState {
  index: number
  tool: string
  intensity: string
  targets: string[]
  scan_ids: string[]
  status: string
  findings: number
  discovered: string[]
  error: string | null
}

export interface RobotRun {
  id: string
  robot_id: string
  workspace_id: string
  target: string
  status: string
  current_step: number
  total_steps: number
  steps_state: RobotStepState[]
  scan_ids: string[]
  error_message: string | null
  started_at: string | null
  completed_at: string | null
  created_at: string | null
}

export interface Robot {
  id: string
  workspace_id: string
  name: string
  description: string | null
  steps: RobotStep[]
  step_count: number
  max_targets: number
  is_active: boolean
  schedule_cron: string | null
  created_at: string | null
  updated_at: string | null
  last_run: RobotRun | null
}

export interface ScheduledScanRecord {
  id: string
  name: string
  description: string | null
  scan_type: string
  target: string
  intensity: string
  frequency: string
  cron_expression: string | null
  timezone: string
  status: string
  last_run: string | null
  next_run: string | null
  last_run_status: string | null
  last_run_error: string | null
  created_at: string | null
}

export const schedulesApi = {
  list: () => request<ScheduledScanRecord[]>('/api/scheduled-scans'),
  create: (payload: Record<string, unknown>) =>
    request<ScheduledScanRecord>('/api/scheduled-scans', { method: 'POST', body: JSON.stringify(payload) }),
  update: (id: string, payload: Record<string, unknown>) =>
    request<ScheduledScanRecord>(`/api/scheduled-scans/${id}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  remove: (id: string) => request<{ ok: boolean }>(`/api/scheduled-scans/${id}`, { method: 'DELETE' }),
  trigger: (id: string) => request<Record<string, unknown>>(`/api/scheduled-scans/${id}/trigger`, { method: 'POST' }),
}

export interface ScanTemplateRecord {
  id: string
  name: string
  description: string | null
  scan_type: string
  intensity: string
  is_shared: boolean
  created_at: string | null
}

export const scanTemplatesApi = {
  list: () => request<ScanTemplateRecord[]>('/api/scan-templates'),
  create: (payload: Record<string, unknown>) =>
    request<ScanTemplateRecord>('/api/scan-templates', { method: 'POST', body: JSON.stringify(payload) }),
  remove: (id: string) => request<{ ok: boolean }>(`/api/scan-templates/${id}`, { method: 'DELETE' }),
  use: (id: string, target: string) =>
    request<Record<string, unknown>>(`/api/scan-templates/${id}/use`, { method: 'POST', body: JSON.stringify({ target }) }),
}

export interface ReportRecord {
  id: string
  title: string
  description: string | null
  format: string
  status: string
  file_size: number | null
  page_count: number | null
  generation_error: string | null
  created_at: string | null
  completed_at: string | null
}

export interface ReportTemplateRecord {
  id: string
  name: string
  description: string | null
  type: string
  compliance_frameworks: string[]
  default_formats: string[]
  is_default: boolean
  is_system: boolean
  created_at: string | null
}

export const reportsApi = {
  list: () => request<ReportRecord[]>('/api/reports'),
  create: (payload: { title: string; description?: string; format?: string; scan_ids: string[]; template_id?: string }) =>
    request<ReportRecord>('/api/reports', { method: 'POST', body: JSON.stringify(payload) }),
  remove: (id: string) => request<{ ok: boolean }>(`/api/reports/${id}`, { method: 'DELETE' }),
  download: (id: string, filename: string) => downloadWithAuth(`/api/reports/${id}/download`, filename),
}

export const reportTemplatesApi = {
  list: () => request<ReportTemplateRecord[]>('/api/report-templates'),
  create: (payload: Record<string, unknown>) =>
    request<ReportTemplateRecord>('/api/report-templates', { method: 'POST', body: JSON.stringify(payload) }),
  remove: (id: string) => request<{ ok: boolean }>(`/api/report-templates/${id}`, { method: 'DELETE' }),
}

export const assetsApi = {
  import: (payload: { targets: string; type?: string }) =>
    request<{ created: string[]; skipped: string[]; over_limit: string[]; invalid: string[]; count: number }>(
      '/api/assets/import',
      { method: 'POST', body: JSON.stringify(payload) },
    ),
}

export const findingsApi = {
  create: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>('/api/findings', { method: 'POST', body: JSON.stringify(payload) }),
}

export interface UsageBucket {
  used: number
  limit: number | null
}

export interface WorkspaceUsage {
  plan: string
  assets: UsageBucket
  running: UsageBucket
  waiting: UsageBucket
  scheduled: UsageBucket
  team: UsageBucket
}

export interface DayActivity {
  date: string
  total: number
  completed: number
  failed: number
  findings: number
}

export interface DashboardAnalytics {
  days: number
  usage: WorkspaceUsage
  open_findings: number
  scans_total: number
  scans_by_day: DayActivity[]
  findings_by_severity: Record<string, number>
  findings_total: number
  scan_types: { type: string; count: number }[]
  top_assets: { target: string; findings: number }[]
}

export const dashboardApi = {
  analytics: (days = 14) => request<DashboardAnalytics>(`/api/dashboard/analytics?days=${days}`),
  usage: () => request<WorkspaceUsage>('/api/workspace/usage'),
}

export const robotsApi = {
  list: () => request<Robot[]>('/api/robots'),
  get: (id: string) => request<Robot>(`/api/robots/${id}`),
  create: (payload: { name: string; description?: string; steps: RobotStep[]; max_targets?: number }) =>
    request<Robot>('/api/robots', { method: 'POST', body: JSON.stringify(payload) }),
  update: (id: string, payload: Partial<{ name: string; description: string; steps: RobotStep[]; max_targets: number; is_active: boolean }>) =>
    request<Robot>(`/api/robots/${id}`, { method: 'PATCH', body: JSON.stringify(payload) }),
  remove: (id: string) => request<{ ok: boolean }>(`/api/robots/${id}`, { method: 'DELETE' }),
  run: (id: string, target: string) =>
    request<RobotRun>(`/api/robots/${id}/run`, { method: 'POST', body: JSON.stringify({ target }) }),
  runs: (robotId?: string) =>
    request<RobotRun[]>(`/api/robots/runs${robotId ? `?robot_id=${robotId}` : ''}`),
  runDetail: (runId: string) => request<RobotRun>(`/api/robots/runs/${runId}`),
}

export interface SurfacePort {
  port: number
  protocol: string
  service: string | null
  product: string | null
  version: string | null
  state: string
  target: string
  url: string | null
}

export interface SurfaceHost {
  key: string
  ip: string | null
  hostname: string | null
  hostnames: string[]
  os: string | null
  os_accuracy: string | null
  url: string | null
  screenshot: string | null
  ports: SurfacePort[]
  port_count: number
  technologies: string[]
  vulns: { critical: number; high: number; medium: number; low: number; info: number }
  vuln_count: number
  risk_level: string | null
  risk_score: number | null
  last_seen: string | null
}

export interface SurfaceData {
  workspace_id: string
  generated_at: string
  last_scan_at: string | null
  group_by: string
  summary: {
    hosts: number
    ports: number
    services: number
    technologies: number
    findings: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  services: string[]
  technology_list: string[]
  rows: SurfaceHost[]
}