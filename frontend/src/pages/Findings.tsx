import { useState, FormEvent } from 'react'
import { useAppStore } from '../store/useAppStore'
import { Search, Filter, ChevronLeft, ChevronRight, AlertTriangle, CheckCircle, XCircle, Clock, Shield, ExternalLink, Flag, Plus, LucideIcon, Edit, Eye, Trash2, X, FileText, Globe, Link2, Columns, Filter as FilterIcon } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { findingsApi } from '../lib/api'

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
  const [selectedFinding, setSelectedFinding] = useState<typeof findings[0] | null>(null)
  const [showViewModal, setShowViewModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editForm, setEditForm] = useState({ ...emptyForm })
  const [editSaving, setEditSaving] = useState(false)

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

  const handleView = (finding: typeof findings[0]) => {
    setSelectedFinding(finding)
    setShowViewModal(true)
  }

  const handleEdit = (finding: typeof findings[0]) => {
    setEditForm({
      target: finding.target,
      title: finding.title,
      severity: finding.riskLevel,
      description: '',
      remediation: '',
      cvss_score: '',
    })
    setSelectedFinding(finding)
    setShowEditModal(true)
  }

  const handleEditSubmit = async (e: FormEvent) => {
    e.preventDefault()
    if (!selectedFinding) return
    setEditSaving(true)
    try {
      const token = localStorage.getItem('auth_token')
      const res = await fetch(`/api/findings/${selectedFinding.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
        body: JSON.stringify({ 
          status: editForm.severity ? undefined : undefined,
          title: editForm.title,
          severity: editForm.severity,
          description: editForm.description || undefined,
          remediation: editForm.remediation || undefined,
          cvss_score: editForm.cvss_score === '' ? undefined : Number(editForm.cvss_score),
        }),
      })
      if (res.ok) {
        await bootstrap()
        setShowEditModal(false)
        setSelectedFinding(null)
      } else {
        alert('Failed to update finding')
      }
    } catch {
      alert('Failed to update finding')
    } finally {
      setEditSaving(false)
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
        <DropdownMenu trigger={<button className="btn-secondary flex items-center gap-2 px-4 py-2"><FilterIcon size={18} /> Filters</button>}>
          <div className="p-2 border-b border-slate-200">
            <p className="px-2 py-1 text-xs font-medium text-slate-500 uppercase">Risk Level</p>
          </div>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setRiskFilter('all')}>All Risk Levels</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setRiskFilter('critical')}>Critical</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setRiskFilter('high')}>High</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setRiskFilter('medium')}>Medium</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setRiskFilter('low')}>Low</button>
          <div className="p-2 border-b border-slate-200">
            <p className="px-2 py-1 text-xs font-medium text-slate-500 uppercase">Status</p>
          </div>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('all')}>All Status</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('open')}>Open</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('verified')}>Verified</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('false_positive')}>False Positive</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => setStatusFilter('fixed')}>Fixed</button>
          <hr className="my-1 border-slate-200" />
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100" onClick={() => { setRiskFilter('all'); setStatusFilter('all'); }}>Clear all filters</button>
        </DropdownMenu>
        <DropdownMenu trigger={<button className="btn-secondary flex items-center gap-2 px-4 py-2"><Columns size={18} /> Table options</button>}>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Verified
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Finding
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Target
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Risk
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Status
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Source
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Scan Date
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
                        <button onClick={() => handleView(finding)} className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="View"><Eye size={14} /></button>
                        <button onClick={() => handleEdit(finding)} className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Edit"><Edit size={14} /></button>
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

      {/* View Finding Modal */}
      {showViewModal && selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => { setShowViewModal(false); setSelectedFinding(null); }}>
          <div className="bg-white rounded-xl p-6 w-full max-w-3xl mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">Finding Details</h2>
              <button onClick={() => { setShowViewModal(false); setSelectedFinding(null); }} className="p-2 text-slate-400 hover:text-slate-600"><X size={20} /></button>
            </div>
            <div className="space-y-4">
              <div className="flex items-center gap-3">
                <h3 className="text-lg font-semibold text-slate-900">{selectedFinding.title}</h3>
                {(() => {
                  const RiskIcon = riskConfig[selectedFinding.riskLevel as RiskLevel].icon;
                  return (
                    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded-full text-xs font-medium border ${riskConfig[selectedFinding.riskLevel as RiskLevel].className}`}>
                      <RiskIcon size={12} /> {riskConfig[selectedFinding.riskLevel as RiskLevel].label}
                    </span>
                  );
                })()}
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-500">Target</label>
                  <p className="font-mono text-sm text-slate-900">{selectedFinding.target}</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">Status</label>
                  {(() => {
                    const StatusIcon = statusConfig[selectedFinding.status as FindingStatus].icon;
                    return (
                      <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${statusConfig[selectedFinding.status as FindingStatus].className}`}>
                        <StatusIcon size={12} /> {statusConfig[selectedFinding.status as FindingStatus].label}
                      </span>
                    );
                  })()}
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">Source</label>
                  <p className="text-sm text-slate-600">{selectedFinding.source}</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">Scan Date</label>
                  <p className="text-sm text-slate-600">{selectedFinding.scanDate}</p>
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-slate-200">
              <button onClick={() => { setShowViewModal(false); setShowEditModal(true); }} className="btn-secondary px-4 py-2">Edit</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Finding Modal */}
      {showEditModal && selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => { setShowEditModal(false); setSelectedFinding(null); }}>
          <div className="bg-white rounded-xl p-6 w-full max-w-2xl mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">Edit Finding</h2>
              <button onClick={() => { setShowEditModal(false); setSelectedFinding(null); }} className="p-2 text-slate-400 hover:text-slate-600"><X size={20} /></button>
            </div>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                <div className="md:col-span-2">
                  <label className="text-xs font-medium text-slate-500">Target</label>
                  <input className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={editForm.target} onChange={e => setEditForm({...editForm, target: e.target.value})} placeholder="example.com" />
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500">Severity</label>
                  <select className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={editForm.severity} onChange={e => setEditForm({...editForm, severity: e.target.value})}>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-medium text-slate-500">CVSS score</label>
                  <input type="number" step="0.1" min="0" max="10" className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={editForm.cvss_score} onChange={e => setEditForm({...editForm, cvss_score: e.target.value})} placeholder="7.5" />
                </div>
              </div>
              <div>
                <label className="text-xs font-medium text-slate-500">Title</label>
                <input className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={editForm.title} onChange={e => setEditForm({...editForm, title: e.target.value})} placeholder="Stored XSS in profile bio" />
              </div>
              <div>
                <label className="text-xs font-medium text-slate-500">Description</label>
                <textarea rows={3} className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={editForm.description} onChange={e => setEditForm({...editForm, description: e.target.value})} />
              </div>
              <div>
                <label className="text-xs font-medium text-slate-500">Remediation</label>
                <textarea rows={2} className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={editForm.remediation} onChange={e => setEditForm({...editForm, remediation: e.target.value})} />
              </div>
              <div className="flex justify-end gap-3 pt-4">
                <button type="button" className="btn-secondary px-4 py-2" onClick={() => { setShowEditModal(false); setSelectedFinding(null); }}>Cancel</button>
                <button type="submit" disabled={editSaving} className="btn-primary px-4 py-2">{editSaving ? 'Saving…' : 'Save changes'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}