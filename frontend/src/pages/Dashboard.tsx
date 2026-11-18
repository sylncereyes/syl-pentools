import { useEffect, useState } from 'react'
import { useAppStore } from '../store/useAppStore'
import { useSocket } from '../context/SocketContext'
import { dashboardApi, type DashboardAnalytics } from '../lib/api'
import { Server, Activity, Bug, Plus, Link as LinkIcon, CalendarClock } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import type { LucideIcon } from 'lucide-react'

export function Dashboard() {
  const { assets, scans, findings, workspaceId } = useAppStore()
  const { onScanEvent } = useSocket()
  const [analytics, setAnalytics] = useState<DashboardAnalytics | null>(null)
  const runningScans = scans.filter(s => s.status === 'running').length
  const openFindings = findings.filter(f => f.status === 'open').length

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const data = await dashboardApi.analytics(14)
        if (!cancelled) setAnalytics(data)
      } catch {
        /* dashboard still renders from the store when analytics is unavailable */
      }
    }
    void load()
    return () => { cancelled = true }
  }, [workspaceId])

  const usage = analytics?.usage
  useEffect(() => {
    const unsubscribe = onScanEvent((event) => {
      if (event.scan_id) {
        const idx = scans.findIndex(s => s.id === event.scan_id)
        if (idx !== -1) {
          // Update scan in store
          // This would need to be done through the store
        }
      }
    })
    return unsubscribe
  }, [onScanEvent])

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Dashboard</h1>
          <p className="text-slate-500 mt-1">Workspace overview - last 14 days</p>
        </div>
        <NavLink to="/scans/new" className="btn-primary flex items-center gap-2 px-4 py-2">
          <Plus size={18} /> New Scan
        </NavLink>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Assets" value={`${usage?.assets.used ?? assets.length}/${usage?.assets.limit ?? '∞'}`} icon={Server} color="bg-blue-500" trend="Asset quota this cycle" />
        <StatCard label="Running Scans" value={`${usage?.running.used ?? runningScans}/${usage?.running.limit ?? '∞'}`} icon={Activity} color="bg-yellow-500" trend={`${usage?.waiting.used ?? 0} waiting in queue`} />
        <StatCard label="Open Findings" value={analytics?.open_findings ?? openFindings} icon={Bug} color="bg-red-500" trend={`${analytics?.findings_total ?? findings.length} findings in ${analytics?.days ?? 14}d`} />
        <StatCard label="Scheduled Scans" value={`${usage?.scheduled.used ?? 0}/${usage?.scheduled.limit ?? '∞'}`} icon={CalendarClock} color="bg-purple-500" trend={`${usage?.team.used ?? 0}/${usage?.team.limit ?? '∞'} team members`} />
      </div>

      {/* Sections */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Vulnerability Summary */}
        <Card title="Vulnerability Summary" subtitle="Workspace overview - last 14 days">
          {findings.length === 0 ? (
            <EmptyState icon={Bug} title="No findings yet" description="Start a scan to discover vulnerabilities" action={<NavLink to="/scans/new" className="btn-primary px-4 py-2">Start a scan</NavLink>} />
          ) : (
            <FindingSummary findings={findings} />
          )}
        </Card>

        {/* Latest Scans */}
        <Card title="Latest Scans" subtitle="Showing recent scan activity">
          {scans.length === 0 ? (
            <EmptyState icon={Activity} title="No scans yet" description="Create your first scan to get started" action={<NavLink to="/scans/new" className="btn-primary px-4 py-2">Start a scan</NavLink>} />
          ) : (
            <ScanList scans={scans.slice(0, 5)} />
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card title="Scan Activity" subtitle={`Scans per day — last ${analytics?.days ?? 14} days`}>
          {analytics && analytics.scans_total > 0 ? (
            <ActivityChart days={analytics.scans_by_day} />
          ) : (
            <p className="text-sm text-slate-500 py-6 text-center">No scan activity in this period yet.</p>
          )}
        </Card>

        <Card title="Top Assets by Open Findings" subtitle="Where to look first">
          {analytics && analytics.top_assets.length > 0 ? (
            <div className="space-y-3">
              {analytics.top_assets.map((asset) => (
                <div key={asset.target} className="flex items-center justify-between">
                  <span className="text-sm font-medium text-slate-800 truncate">{asset.target}</span>
                  <span className="text-xs font-mono text-slate-600">{asset.findings}</span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-slate-500 py-6 text-center">No open findings on tracked assets.</p>
          )}
        </Card>
      </div>

      {analytics && (
        <Card title="Severity Mix" subtitle={`Findings created in the last ${analytics.days} days`}>
          <div className="grid grid-cols-5 gap-3">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map((level) => (
              <div key={level} className="rounded-lg border border-slate-200 p-3 text-center">
                <p className="text-2xl font-bold text-slate-900">{analytics.findings_by_severity[level] ?? 0}</p>
                <p className="text-xs capitalize text-slate-500 mt-1">{level}</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Quick Actions */}
      <Card title="Quick Actions">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <ActionCard icon={Server} title="Add Asset" description="Add a hostname or IP to scan" href="/assets" />
          <ActionCard icon={Activity} title="New Scan" description="Launch a vulnerability scan" href="/scans/new" />
          <ActionCard icon={LinkIcon} title="Integrations" description="Connect Slack, Jira, Teams, etc." href="/integrations" />
        </div>
      </Card>
    </div>
  )
}

function StatCard({ label, value, icon: Icon, color, trend }: { label: string; value: number | string; icon: LucideIcon; color: string; trend: string }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-slate-500">{label}</p>
          <p className="text-3xl font-bold text-slate-900 mt-1">{value}</p>
          <p className="text-xs text-slate-500 mt-2">{trend}</p>
        </div>
        <div className={`p-3 rounded-xl ${color} flex items-center justify-content text-white`}><Icon size={24} /></div>
      </div>
    </div>
  )
}

function Card({ title, subtitle, children }: { title: string; subtitle?: string; children: React.ReactNode }) {
  return (
    <div className="bg-white rounded-xl border border-slate-200">
      <div className="px-5 py-4 border-b border-slate-200">
        <h3 className="font-semibold text-slate-900">{title}</h3>
        {subtitle && <p className="text-sm text-slate-500 mt-0.5">{subtitle}</p>}
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

function EmptyState({ icon: Icon, title, description, action }: { icon: LucideIcon; title: string; description: string; action: React.ReactNode }) {
  return (
    <div className="text-center py-10">
      <div className="mx-auto text-slate-300"><Icon size={48} /></div>
      <h4 className="mt-4 font-medium text-slate-900">{title}</h4>
      <p className="text-sm text-slate-500 mt-1">{description}</p>
      <div className="mt-4">{action}</div>
    </div>
  )
}

function FindingSummary({ findings }: { findings: any[] }) {
  const byRisk = findings.reduce((acc, f) => { acc[f.riskLevel] = (acc[f.riskLevel] || 0) + 1; return acc }, {} as Record<string, number>)
  const risks = ['critical', 'high', 'medium', 'low'] as const
  return (
    <div className="space-y-3">
      {risks.map(risk => (
        <div key={risk} className="flex items-center justify-between">
          <span className="text-sm font-medium capitalize">{risk}</span>
          <div className="flex items-center gap-3">
            <div className={`h-2 w-24 rounded bg-${risk === 'critical' ? 'red' : risk === 'high' ? 'orange' : risk === 'medium' ? 'yellow' : 'green'}-500`} />
            <span className="text-sm font-mono text-slate-600">{byRisk[risk] || 0}</span>
          </div>
        </div>
      ))}
    </div>
  )
}

function ScanList({ scans }: { scans: any[] }) {
  return (
    <div className="space-y-3">
      {scans.map(scan => (
        <div key={scan.id} className="flex items-center justify-between py-3 border-b border-slate-100 last:border-0">
          <div className="flex items-center gap-3">
            <div className={`w-2 h-2 rounded-full ${scan.status === 'running' ? 'bg-yellow-500 animate-pulse' : scan.status === 'completed' ? 'bg-green-500' : scan.status === 'failed' ? 'bg-red-500' : 'bg-slate-400'}`} />
            <div>
              <p className="text-sm font-medium text-slate-900">{scan.type}</p>
              <p className="text-xs text-slate-500">{scan.target}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {scan.status === 'running' && scan.progress > 0 && (
              <div className="w-24 h-1.5 bg-slate-200 rounded-full overflow-hidden">
                <div className="h-full bg-yellow-500 rounded-full transition-all duration-300" style={{ width: `${scan.progress}%` }} />
              </div>
            )}
            <span className={`text-xs font-medium px-2 py-1 rounded ${scan.status === 'running' ? 'status-running' : scan.status === 'completed' ? 'status-completed' : scan.status === 'failed' ? 'status-failed' : 'status-pending'}`}>
              {scan.status}
              {scan.status === 'running' && scan.progress > 0 && <span className="ml-1 text-xs">{Math.round(scan.progress)}%</span>}
            </span>
          </div>
        </div>
      ))}
    </div>
  )
}

function ActionCard({ icon: Icon, title, description, href }: { icon: LucideIcon; title: string; description: string; href: string }) {
  return (
    <NavLink to={href} className="p-4 border border-slate-200 rounded-xl hover:border-blue-300 hover:bg-blue-50 transition-colors group">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-slate-100 rounded-lg group-hover:bg-blue-100 transition-colors text-slate-600 group-hover:text-blue-600"><Icon size={20} /></div>
        <div>
          <p className="font-medium text-slate-900">{title}</p>
          <p className="text-sm text-slate-500">{description}</p>
        </div>
      </div>
    </NavLink>
  )
}
function ActivityChart({ days }: { days: { date: string; total: number; completed: number; failed: number }[] }) {
  const max = Math.max(1, ...days.map((d) => d.total))
  return (
    <div className="flex items-end gap-1 h-40">
      {days.map((day) => {
        const totalH = Math.max(2, Math.round((day.total / max) * 100))
        const failedH = day.total ? Math.max(0, Math.round((day.failed / max) * 100)) : 0
        return (
          <div key={day.date} className="flex-1 flex flex-col items-center justify-end gap-1 group">
            <div className="relative w-full flex flex-col justify-end" style={{ height: '100%' }}>
              <div className="w-full rounded-t bg-indigo-500/80 group-hover:bg-indigo-600 transition-colors" style={{ height: `${totalH}%` }}>
                {failedH > 0 && <div className="w-full bg-red-500 rounded-t" style={{ height: `${Math.min(100, Math.round((failedH / totalH) * 100))}%` }} />}
              </div>
            </div>
            <span className="text-[10px] text-slate-400 rotate-0">{day.date.slice(5)}</span>
            <span className="text-[10px] text-slate-500 opacity-0 group-hover:opacity-100">{day.total}</span>
          </div>
        )
      })}
    </div>
  )
}
