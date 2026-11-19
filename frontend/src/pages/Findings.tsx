import { useState, FormEvent } from 'react'
import { useAppStore } from '../store/useAppStore'
import { Search, Filter, ChevronLeft, ChevronRight, AlertTriangle, CheckCircle, XCircle, Clock, Shield, ExternalLink, Flag, Plus, LucideIcon } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { findingsApi } from '../lib/api'

type RiskLevel = 'critical' | 'high' | 'medium' | 'low'
type FindingStatus = 'open' | 'verified' | 'false_positive' | 'fixed'

const riskConfig: Record<RiskLevel, { label: string; className: string; icon: LucideIcon }> = {
  critical: { label: 'Critical', className: 'bg-red-100 text-red-700 border-red-200', icon: Shield },
  high: { label: 'High', className: 'bg-orange-100 text-orange-700 border-orange-200', icon: AlertTriangle },
  medium: { label: 'Medium', className: 'bg-yellow-100 text-yellow-700 border-yellow-200', icon: AlertTriangle },
  low: { label: 'Low', className: 'bg-green-100 text-green-700 border-green-200', icon: Flag },
}

const findingTemplates = [
  { name: 'SQL Injection', severity: 'high', description: 'User-controlled input reaches a SQL query without parameterization.', remediation: 'Use parameterized queries or a safe ORM API.' },
  { name: 'Cross-Site Scripting (XSS)', severity: 'medium', description: 'Unescaped user input is reflected into an HTML response.', remediation: 'Encode output contextually and apply a strict CSP.' },
  { name: 'Cross-Site Request Forgery (CSRF)', severity: 'medium', description: 'State-changing request lacks anti-CSRF protection.', remediation: 'Require anti-CSRF tokens and SameSite cookies.' },
  { name: 'Insecure Direct Object Reference (IDOR)', severity: 'high', description: 'Object identifier is accepted without an ownership check.', remediation: 'Enforce authorization on every object access.' },
  { name: 'Server-Side Request Forgery (SSRF)', severity: 'high', description: 'Server fetches a user-supplied URL without allowlisting.', remediation: 'Allowlist outbound destinations and block metadata ranges.' },
  { name: 'Missing Security Headers', severity: 'low', description: 'Response omits HSTS, CSP or X-Content-Type-Options.', remediation: 'Add the missing response headers at the edge.' },
  { name: 'Remote Code Execution (RCE)', severity: 'critical', description: 'User input is evaluated by an interpreter with server privileges.', remediation: 'Remove dynamic evaluation and patch the affected component.' },
]

const statusConfig: Record<FindingStatus, { label: string; className: string; icon: LucideIcon }> = {
  open: { label: 'Open', className: 'bg-blue-100 text-blue-700', icon: Clock },
  verified: { label: 'Verified', className: 'bg-green-100 text-green-700', icon: CheckCircle },
  false_positive: { label: 'False Positive', className: 'bg-slate-100 text-slate-700', icon: XCircle },
  fixed: { label: 'Fixed', className: 'bg-purple-100 text-purple-700', icon: CheckCircle },
}



const emptyForm = { target: '', title: '', severity: 'medium', description: '', remediation: '', cvss_score: '' }

export function Findings() {
  const { findings, bootstrap } = useAppStore()
  const [search, setSearch] = useState('')
  const [riskFilter, setRiskFilter] = useState<string>('all')
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [tab, setTab] = useState<'all' | 'templates'>('all')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ ...emptyForm })
  const [formError, setFormError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const openForm = (template?: typeof findingTemplates[number]) => {
    setFormError(null)
    setForm({
      ...emptyForm,
      title: template?.name ?? '',
      severity: template?.severity ?? 'medium',
      description: template?.description ?? '',
      remediation: template?.remediation ?? '',
    })
    setShowForm(true)
  }

  const submitFinding = async (e: FormEvent) => {
    e.preventDefault()
    setFormError(null)
    if (!form.target.trim() || !form.title.trim()) {
      setFormError('Target and title are required')
      return
    }
    setSaving(true)
    try {
      await findingsApi.create({
        target: form.target.trim(),
        title: form.title.trim(),
        severity: form.severity,
        description: form.description.trim() || undefined,
        remediation: form.remediation.trim() || undefined,
        cvss_score: form.cvss_score === '' ? undefined : Number(form.cvss_score),
      })
      setShowForm(false)
      setForm({ ...emptyForm })
      await bootstrap()
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Could not save finding')
    } finally {
      setSaving(false)
    }
  }

  const allFindings = findings
  const filteredFindings = allFindings
    .filter(f => !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.target.toLowerCase().includes(search.toLowerCase()))
    .filter(f => riskFilter === 'all' || f.riskLevel === riskFilter)
    .filter(f => statusFilter === 'all' || f.status === statusFilter)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Findings</h1>
          <p className="text-slate-500 mt-1">Unlock manual findings</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-secondary flex items-center gap-2 px-4 py-2" onClick={() => openForm()}><Plus size={18} /> Add finding</button>
        </div>
      </div>

      <div className="flex items-center gap-2 border-b border-slate-200">
        <button onClick={() => setTab('all')} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === 'all' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>All findings</button>
        <button onClick={() => setTab('templates')} className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === 'templates' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-700'}`}>Templates</button>
      </div>

      {showForm && (
        <form onSubmit={submitFinding} className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="font-semibold text-slate-900">Add manual finding</h3>
            <button type="button" className="text-sm text-slate-500 hover:text-slate-700" onClick={() => setShowForm(false)}>Cancel</button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="md:col-span-2">
              <label className="text-xs font-medium text-slate-500">Target</label>
              <input className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={form.target} onChange={e => setForm({...form, target: e.target.value})} placeholder="example.com" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500">Severity</label>
              <select className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={form.severity} onChange={e => setForm({...form, severity: e.target.value})}>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500">CVSS score</label>
              <input type="number" step="0.1" min="0" max="10" className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={form.cvss_score} onChange={e => setForm({...form, cvss_score: e.target.value})} placeholder="7.5" />
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-slate-500">Title</label>
            <input className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={form.title} onChange={e => setForm({...form, title: e.target.value})} placeholder="Stored XSS in profile bio" />
          </div>
          <div>
            <label className="text-xs font-medium text-slate-500">Description</label>
            <textarea rows={3} className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={form.description} onChange={e => setForm({...form, description: e.target.value})} />
          </div>
          <div>
            <label className="text-xs font-medium text-slate-500">Remediation</label>
            <textarea rows={2} className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={form.remediation} onChange={e => setForm({...form, remediation: e.target.value})} />
          </div>
          {formError && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{formError}</div>}
          <button type="submit" disabled={saving} className="btn-primary px-4 py-2">{saving ? 'Saving…' : 'Save finding'}</button>
        </form>
      )}

      {tab === 'templates' && (
        <div className="bg-white rounded-xl border border-slate-200 p-4">
          <h3 className="font-semibold text-slate-900 mb-1">Finding templates</h3>
          <p className="text-sm text-slate-500 mb-3">Start from a common weakness and fill in the target.</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {findingTemplates.map(t => (
              <button key={t.name} onClick={() => openForm(t)} className="p-4 border border-slate-200 rounded-lg hover:border-blue-300 hover:bg-blue-50 text-left">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium text-slate-900">{t.name}</span>
                  <span className={`text-xs px-2 py-0.5 rounded-full border ${riskConfig[(t.severity === 'info' ? 'low' : t.severity) as RiskLevel].className}`}>{t.severity}</span>
                </div>
                <p className="text-xs text-slate-500 mt-2">{t.description}</p>
              </button>
            ))}
          </div>
        </div>
      )}

      {tab === 'all' && (<>

      {/* Search/Filters */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-4">
        <div className="relative flex-1 min-w-[250px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
          <input type="text" placeholder="Search findings..." value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
        </div>
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)} className="px-4 py-2 border border-slate-300 rounded-lg text-sm">
          <option value="all">All Risk Levels</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className="px-4 py-2 border border-slate-300 rounded-lg text-sm">
          <option value="all">All Status</option>
          <option value="open">Open</option>
          <option value="verified">Verified</option>
          <option value="false_positive">False Positive</option>
          <option value="fixed">Fixed</option>
        </select>
        <button className="btn-secondary flex items-center gap-2 px-4 py-2"><Filter size={18} /> Filters off</button>
        <button className="btn-secondary flex items-center gap-2 px-4 py-2">Table options</button>
      </div>

      {/* Table */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Verified</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Finding</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Target</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Risk</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Source</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Scan Date</th>
              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wider pr-5">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {filteredFindings.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-5 py-12 text-center">
                  <div className="text-center py-10">
                    <Shield size={48} className="mx-auto text-slate-300" />
                    <h4 className="mt-4 font-medium text-slate-900">Findings will be displayed here after your first scan.</h4>
                    <p className="text-sm text-slate-500 mt-1">Run a scan to discover vulnerabilities</p>
                    <NavLink to="/scans/new" className="btn-primary mt-4 px-4 py-2 inline-block">Go to the Assets Page</NavLink>
                  </div>
                </td>
              </tr>
            ) : (
              filteredFindings.map(finding => {
                const riskLevel = finding.riskLevel as RiskLevel
                const findingStatus = finding.status as FindingStatus
                const risk = riskConfig[riskLevel]
                const status = statusConfig[findingStatus]
                const RiskIcon = risk.icon
                const StatusIcon = status.icon
                return (
                  <tr key={finding.id} className="hover:bg-slate-50">
                    <td className="px-5 py-4">
                      <input type="checkbox" className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500" />
                    </td>
                    <td className="px-5 py-4">
                      <p className="font-medium text-slate-900">{finding.title}</p>
                    </td>
                    <td className="px-5 py-4 text-sm text-slate-600 font-mono">{finding.target}</td>
                    <td className="px-5 py-4">
                      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium border ${risk.className}`}>
                        <RiskIcon size={12} /> {risk.label}
                      </span>
                    </td>
                    <td className="px-5 py-4">
                      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${status.className}`}>
                        <StatusIcon size={12} /> {status.label}
                      </span>
                    </td>
                    <td className="px-5 py-4 text-sm text-slate-600">{finding.source}</td>
                    <td className="px-5 py-4 text-sm text-slate-600">{finding.scanDate}</td>
                    <td className="px-5 py-4 text-right pr-5">
                      <div className="flex items-center justify-end gap-1">
                        <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="View"><ExternalLink size={14} /></button>
                        <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Edit"><Flag size={14} /></button>
                      </div>
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="px-5 py-3 border-t border-slate-200 flex items-center justify-between">
          <p className="text-sm text-slate-500">Displaying {filteredFindings.length} findings</p>
          <div className="flex items-center gap-2">
            <select className="border border-slate-300 rounded px-3 py-1 text-sm"><option>10</option><option>25</option><option>50</option></select>
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100 disabled:opacity-50"><ChevronLeft size={16} /></button>
            <button className="px-3 py-1 border border-blue-500 text-blue-600 rounded bg-blue-50 text-sm">1</button>
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100"><ChevronRight size={16} /></button>
          </div>
        </div>
      </div>
      </>)}
    </div>
  )
}