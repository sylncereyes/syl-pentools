import { useState, useEffect, FormEvent } from 'react'
import { useAppStore } from '../store/useAppStore'
import { useSocket } from '../context/SocketContext'
import { Plus, Search, Filter, Calendar, Clock, Play, Pause, RotateCcw, Eye, Download, ChevronLeft, ChevronRight, CheckCircle, AlertTriangle, Activity, Columns, Filter as FilterIcon } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { schedulesApi, type ScheduledScanRecord } from '../lib/api'
import { formatDistanceToNow } from 'date-fns'

function DropdownMenu({ trigger, children, align = 'right' }: { trigger: React.ReactNode; children: React.ReactNode; align?: 'left' | 'right' }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative" onClick={() => setOpen(!open)}>
      <div>{trigger}</div>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className={`fixed z-50 mt-2 w-56 bg-white rounded-lg border border-slate-200 shadow-lg py-1 ${align === 'right' ? 'right-0' : 'left-0'}`}>
            {children}
          </div>
        </>
      )}
    </div>
  )
}

const statusConfig = {
  pending: { label: 'Pending', className: 'status-pending', icon: Clock },
  running: { label: 'Running', className: 'status-running', icon: Play },
  completed: { label: 'Completed', className: 'status-completed', icon: CheckCircle },
  failed: { label: 'Failed', className: 'status-failed', icon: AlertTriangle },
}

const scanTypes = [
  { id: 'website', name: 'Website Scanner', desc: 'Discover XSS, SQLi, RCE and 70+ web application issues.' },
  { id: 'network', name: 'Network Scanner', desc: 'Check for 10,000+ CVEs and server misconfigurations.' },
  { id: 'port', name: 'Port Scanner', desc: 'Detect open ports and fingerprint services.' },
  { id: 'subdomain', name: 'Subdomain Finder', desc: 'Discover subdomains of a domain.' },
  { id: 'recon', name: 'Website Recon', desc: 'Fingerprint web technologies of target website.' },
  { id: 'password', name: 'Password Auditor', desc: 'Discover weak credentials in network services and web apps.' },
  { id: 'cms', name: 'CMS Scanner', desc: 'WordPress, Drupal and other CMS vulnerability checks.' },
  { id: 'api', name: 'API Scanner', desc: 'Test REST/GraphQL APIs for auth and injection flaws.' },
  { id: 'cloud', name: 'Cloud Scanner', desc: 'Review Azure and GCP configuration exposure.' },
  { id: 'exploit', name: 'Exploitation (Sniper)', desc: 'Validate exploitability of discovered issues.' },
  { id: 'burp', name: 'Burp Import', desc: 'Import Burp Suite XML findings into the workspace.' },
  { id: 'fuzzer', name: 'URL Fuzzer', desc: 'Directory and file discovery with ffuf.' },
  { id: 'vhost', name: 'Virtual Host Finder', desc: 'Discover hidden virtual hosts on the target.' },
  { id: 'domain_finder', name: 'Domain Finder', desc: 'Related domains via certificate transparency.' },
  { id: 'google_hacking', name: 'Google Hacking', desc: 'Search-engine dorks for exposed data.' },
  { id: 'people_hunter', name: 'People Hunter', desc: 'OSINT email and people harvesting.' },
  { id: 'http_logger', name: 'HTTP Request Logger', desc: 'Capture HTTP request/response pairs.' },
]

export function Scans() {
  const { scans, createScan, updateScan } = useAppStore()
  const { isConnected, onScanEvent, subscribeToScan, unsubscribeFromScan } = useSocket()
  const [search, setSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [tab, setTab] = useState<'all' | 'scheduled'>('all')
  const [schedules, setSchedules] = useState<ScheduledScanRecord[]>([])
  const [scheduleForm, setScheduleForm] = useState({ name: '', scan_type: 'website', target: '', frequency: 'daily' })
  const [scheduleError, setScheduleError] = useState<string | null>(null)
  const [scheduleBusy, setScheduleBusy] = useState(false)

  const loadSchedules = async () => {
    try {
      setSchedules(await schedulesApi.list())
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : 'Failed to load schedules')
    }
  }

  useEffect(() => {
    void loadSchedules()
  }, [])

  const submitSchedule = async (e: FormEvent) => {
    e.preventDefault()
    setScheduleError(null)
    if (!scheduleForm.name.trim() || !scheduleForm.target.trim()) {
      setScheduleError('Name and target are required')
      return
    }
    setScheduleBusy(true)
    try {
      await schedulesApi.create({ ...scheduleForm, name: scheduleForm.name.trim(), target: scheduleForm.target.trim() })
      setScheduleForm({ name: '', scan_type: scheduleForm.scan_type, target: '', frequency: scheduleForm.frequency })
      await loadSchedules()
    } catch (err) {
      setScheduleError(err instanceof Error ? err.message : 'Failed to create schedule')
    } finally {
      setScheduleBusy(false)
    }
  }

  // Subscribe to real-time scan events
  useEffect(() => {
    const unsubscribe = onScanEvent((event) => {
      if (event.scan_id) {
        const validStatuses = ['pending', 'running', 'completed', 'failed'] as const
        const status = validStatuses.includes(event.status as any) ? event.status : undefined
        updateScan(event.scan_id, {
          status: status as 'pending' | 'running' | 'completed' | 'failed' | undefined,
          progress: event.progress,
          findings: event.findings_count,
        })
      }
    })
    return unsubscribe
  }, [onScanEvent, updateScan])

  // Subscribe to running scans
  useEffect(() => {
    const runningScans = scans.filter(s => s.status === 'running')
    runningScans.forEach(scan => subscribeToScan(scan.id))
    return () => {
      runningScans.forEach(scan => unsubscribeFromScan(scan.id))
    }
  }, [scans, subscribeToScan, unsubscribeFromScan])

  const filteredScans = scans
    .filter(s => !search || s.target.toLowerCase().includes(search.toLowerCase()) || s.type.toLowerCase().includes(search.toLowerCase()))
    .filter(s => statusFilter === 'all' || s.status === statusFilter)

  const handleNewScan = async (typeId: string) => {
    const target = window.prompt('Target to scan (hostname, IP or URL):', 'example.com')
    if (!target || !target.trim()) return
    try {
      const scan = await createScan({ type: typeId, target: target.trim() })
      subscribeToScan(scan.id)
    } catch {
      /* error is surfaced in the store */
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Scans</h1>
          <p className="text-slate-500 mt-1">Showing all scans from the current workspace.</p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-100 text-sm">
            <span className={isConnected ? 'w-2 h-2 rounded-full bg-green-500' : 'w-2 h-2 rounded-full bg-red-500'} />
            <span className={isConnected ? 'text-green-700' : 'text-red-700'}>
              {isConnected ? 'Live' : 'Offline'}
            </span>
          </div>
          <NavLink to="/scans/new" className="btn-primary flex items-center gap-2 px-4 py-2"><Plus size={18} /> New scan</NavLink>
        </div>
      </div>

      <div className="flex items-center gap-2 border-b border-slate-200">
        <button onClick={() => setTab('all')} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === 'all' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>All scans</button>
        <button onClick={() => setTab('scheduled')} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === 'scheduled' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>Scheduled</button>
      </div>

      {tab === 'scheduled' && (
        <div className="space-y-4">
          <form onSubmit={submitSchedule} className="bg-white rounded-xl border border-slate-200 p-4 grid grid-cols-1 md:grid-cols-5 gap-3 items-end">
            <div className="md:col-span-1">
              <label className="text-xs font-medium text-slate-500">Name</label>
              <input className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={scheduleForm.name} onChange={e => setScheduleForm({...scheduleForm, name: e.target.value})} placeholder="Nightly web scan" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500">Scan type</label>
              <select className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={scheduleForm.scan_type} onChange={e => setScheduleForm({...scheduleForm, scan_type: e.target.value})}>
                {scanTypes.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500">Target</label>
              <input className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={scheduleForm.target} onChange={e => setScheduleForm({...scheduleForm, target: e.target.value})} placeholder="example.com" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500">Frequency</label>
              <select className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={scheduleForm.frequency} onChange={e => setScheduleForm({...scheduleForm, frequency: e.target.value})}>
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>
            <button type="submit" disabled={scheduleBusy} className="btn-primary px-4 py-2">{scheduleBusy ? 'Saving…' : 'Schedule scan'}</button>
          </form>
          {scheduleError && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{scheduleError}</div>}
          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Name</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Type</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Target</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Frequency</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Next run</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase">Last run</th>
                  <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase pr-5">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {schedules.length === 0 ? (
                  <tr><td colSpan={7} className="px-5 py-10 text-center text-sm text-slate-500">No scheduled scans yet.</td></tr>
                ) : schedules.map(sch => (
                  <tr key={sch.id} className="hover:bg-slate-50">
                    <td className="px-5 py-3 font-medium text-slate-900">{sch.name}</td>
                    <td className="px-5 py-3 text-sm text-slate-600">{sch.scan_type}</td>
                    <td className="px-5 py-3 text-sm text-slate-600 font-mono">{sch.target}</td>
                    <td className="px-5 py-3 text-sm text-slate-600 capitalize">{sch.frequency}</td>
                    <td className="px-5 py-3 text-sm text-slate-600">{sch.next_run ? new Date(sch.next_run).toLocaleString() : '—'}</td>
                    <td className="px-5 py-3 text-sm text-slate-600">
                      {sch.last_run ? new Date(sch.last_run).toLocaleString() : '—'}
                      {sch.last_run_status && <span className="ml-2 text-xs text-slate-400">{sch.last_run_status}</span>}
                    </td>
                    <td className="px-5 py-3 text-right pr-5">
                      <button className="text-xs text-blue-600 hover:underline mr-3" onClick={async () => { await schedulesApi.trigger(sch.id); await loadSchedules() }}>Run now</button>
                      <button className="text-xs text-red-600 hover:underline" onClick={async () => { await schedulesApi.remove(sch.id); await loadSchedules() }}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {tab === 'all' && (<>
      {/* Scheduled scans alert */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex items-start gap-3">
        <Calendar className="mt-0.5 text-blue-600" size={20} />
        <div className="flex-1">
          <p className="font-medium text-blue-900">Behind the login, beyond the scan</p>
          <p className="text-sm text-blue-700 mt-1">Wednesday, Jan 18 — Join our webinar on authenticated scanning.</p>
        </div>
        <button className="btn-secondary text-sm px-3 py-1">Save your spot</button>
      </div>

      {/* Search/Filters */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-4">
        <div className="relative flex-1 min-w-[250px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
          <input type="text" placeholder="Search scans..." value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
        </div>
        <DropdownMenu trigger={<button className="btn-secondary flex items-center gap-2 px-4 py-2"><FilterIcon size={18} /> Filters</button>}>
          <div className="p-2 border-b border-slate-200">
            <p className="px-2 py-1 text-xs font-medium text-slate-500 uppercase">Status</p>
          </div>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('all')}>All Status</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('running')}>Running</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('completed')}>Completed</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('failed')}>Failed</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('pending')}>Pending</button>
          <div className="p-2 border-b border-slate-200">
            <p className="px-2 py-1 text-xs font-medium text-slate-500 uppercase">Scan Type</p>
          </div>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Website Scanner</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Network Scanner</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Port Scanner</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Subdomain Finder</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Website Recon</button>
          <hr className="my-1 border-slate-200" />
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('all')}>Clear all filters</button>
        </DropdownMenu>
        <DropdownMenu trigger={<button className="btn-secondary flex items-center gap-2 px-4 py-2"><Columns size={18} /> Table options</button>}>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Actions
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Scan Type
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Target
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Status
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Progress
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Started
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Details
          </label>
          <hr className="my-1 border-slate-200" />
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Reset to defaults</button>
        </DropdownMenu>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Actions</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Scan Type</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Target</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Progress</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Started</th>
              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wider pr-5">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {filteredScans.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-5 py-12 text-center">
                  <div className="text-center py-10">
                    <Activity size={48} className="mx-auto text-slate-300" />
                    <h4 className="mt-4 font-medium text-slate-900">You don't have any scans yet.</h4>
                    <p className="text-sm text-slate-500 mt-1">Create your first scan to get started</p>
                    <NavLink to="/scans/new" className="btn-primary mt-4 px-4 py-2 inline-block">New scan</NavLink>
                  </div>
                </td>
              </tr>
            ) : (
              filteredScans.map(scan => {
                const cfg = statusConfig[scan.status]
                const Icon = cfg.icon
                return (
                  <tr key={scan.id} className="hover:bg-slate-50">
                    <td className="px-5 py-4">
                      <div className="flex items-center gap-1">
                        {scan.status === 'running' && <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Pause"><Pause size={14} /></button>}
                        {scan.status === 'pending' && <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Start"><Play size={14} /></button>}
                        <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="View"><Eye size={14} /></button>
                        <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Retry"><RotateCcw size={14} /></button>
                        <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Download report"><Download size={14} /></button>
                      </div>
                    </td>
                    <td className="px-5 py-4 font-medium text-slate-900">{scan.type}</td>
                    <td className="px-5 py-4 text-sm text-slate-600 font-mono">{scan.target}</td>
                    <td className="px-5 py-4">
                      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${cfg.className}`}>
                        <Icon size={12} /> {cfg.label}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <div className="w-32 h-2 bg-slate-200 rounded-full overflow-hidden">
                        <div className={`h-full rounded-full transition-all duration-500 ${scan.status === 'running' ? 'bg-yellow-500' : scan.status === 'completed' ? 'bg-green-500' : scan.status === 'failed' ? 'bg-red-500' : 'bg-slate-300'}`}
                          style={{ width: `${scan.progress}%` }} />
                      </div>
                    </td>
                    <td className="px-5 py-4 text-sm text-slate-600">{formatDistanceToNow(new Date(scan.startedAt), { addSuffix: true })}</td>
                    <td className="px-5 py-4 text-right pr-5 text-sm text-slate-500">
                      {scan.findings !== undefined && <span className="font-medium text-slate-900">{scan.findings} findings</span>}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="px-5 py-3 border-t border-slate-200 flex items-center justify-between">
          <p className="text-sm text-slate-500">Displaying {filteredScans.length} scans</p>
          <div className="flex items-center gap-2">
            <select className="border border-slate-300 rounded px-3 py-1 text-sm"><option>10</option><option>25</option><option>50</option></select>
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100 disabled:opacity-50"><ChevronLeft size={16} /></button>
            <button className="px-3 py-1 border border-blue-500 text-blue-600 rounded bg-blue-50 text-sm">1</button>
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100"><ChevronRight size={16} /></button>
          </div>
        </div>
      </div>

      </>)}

      {tab === 'all' && (
      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <h3 className="font-semibold text-slate-900 mb-4">Quick Start — Scan Types</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {scanTypes.map(type => (
            <button key={type.id} onClick={() => handleNewScan(type.id)} className="p-4 border border-slate-200 rounded-xl hover:border-blue-300 hover:bg-blue-50 transition-colors text-left">
              <p className="font-medium text-slate-900">{type.name}</p>
              <p className="text-sm text-slate-500 mt-1">{type.desc}</p>
            </button>
          ))}
        </div>
      </div>
      )}
    </div>
  )
}