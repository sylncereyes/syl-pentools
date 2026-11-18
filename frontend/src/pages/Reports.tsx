import { useEffect, useState, FormEvent } from 'react'
import { FileText, Download, Plus, Trash2, ChevronLeft, ChevronRight } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { useAppStore } from '../store/useAppStore'
import { reportsApi, reportTemplatesApi, type ReportRecord, type ReportTemplateRecord } from '../lib/api'

export function Reports() {
  const [activeTab, setActiveTab] = useState<'reports' | 'templates' | 'branding'>('reports')
  const [refresh, setRefresh] = useState(0)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Reports</h1>
          <p className="text-slate-500 mt-1">See, manage, and download all the reports you created from Scan results, Scans, or Findings.</p>
        </div>
        <NavLink to="/scans/new" className="btn-primary flex items-center gap-2 px-4 py-2"><Plus size={18} /> Create a Report</NavLink>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="border-b border-slate-200 flex gap-1 p-1 bg-slate-50">
          {(['reports', 'templates', 'branding'] as const).map(tab => (
            <button key={tab} onClick={() => setActiveTab(tab)} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeTab === tab ? 'bg-white text-blue-600 shadow-sm' : 'text-slate-600 hover:text-slate-900 hover:bg-slate-100'}`}>
              {tab === 'reports' ? 'Engagements' : tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        <div className="p-5">
          {activeTab === 'reports' && <ReportsTab key={`r-${refresh}`} onChanged={() => setRefresh(v => v + 1)} />}
          {activeTab === 'templates' && <TemplatesTab key={`t-${refresh}`} onChanged={() => setRefresh(v => v + 1)} />}
          {activeTab === 'branding' && <BrandingTab />}
        </div>
      </div>
    </div>
  )
}

function ReportsTab({ onChanged }: { onChanged: () => void }) {
  const { scans } = useAppStore()
  const [reports, setReports] = useState<ReportRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [title, setTitle] = useState('')
  const [format, setFormat] = useState('pdf')
  const [selectedScans, setSelectedScans] = useState<string[]>([])
  const [busy, setBusy] = useState(false)
  const completedScans = scans.filter(s => s.status === 'completed')

  const load = async () => {
    setLoading(true)
    try {
      setReports(await reportsApi.list())
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load reports')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { void load() }, [])

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    if (!title.trim() || selectedScans.length === 0) {
      setError('Title and at least one completed scan are required')
      return
    }
    setBusy(true)
    try {
      await reportsApi.create({ title: title.trim(), format, scan_ids: selectedScans })
      setShowForm(false)
      setTitle('')
      setSelectedScans([])
      await load()
      onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create report')
    } finally {
      setBusy(false)
    }
  }

  const download = async (report: ReportRecord) => {
    try {
      await reportsApi.download(report.id, `${report.title.replace(/\s+/g, '_')}.${report.format}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Download failed')
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500">{reports.length} report(s)</p>
        <button className="btn-secondary px-3 py-2 text-sm" onClick={() => setShowForm(v => !v)}>{showForm ? 'Cancel' : 'New report'}</button>
      </div>
      {error && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{error}</div>}
      {showForm && (
        <form onSubmit={submit} className="border border-slate-200 rounded-xl p-4 space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2">
              <label className="text-xs font-medium text-slate-500">Title</label>
              <input className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={title} onChange={e => setTitle(e.target.value)} placeholder="Q4 external assessment" />
            </div>
            <div>
              <label className="text-xs font-medium text-slate-500">Format</label>
              <select className="w-full mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={format} onChange={e => setFormat(e.target.value)}>
                <option value="pdf">PDF</option>
                <option value="docx">DOCX</option>
              </select>
            </div>
          </div>
          <div>
            <label className="text-xs font-medium text-slate-500">Completed scans</label>
            <div className="mt-1 max-h-40 overflow-auto border border-slate-200 rounded-lg divide-y divide-slate-100">
              {completedScans.length === 0 ? <p className="px-3 py-2 text-sm text-slate-500">No completed scans yet.</p> : completedScans.map(s => (
                <label key={s.id} className="flex items-center gap-2 px-3 py-2 text-sm text-slate-700">
                  <input type="checkbox" checked={selectedScans.includes(s.id)} onChange={e => setSelectedScans(prev => e.target.checked ? [...prev, s.id] : prev.filter(id => id !== s.id))} />
                  <span className="font-medium">{s.type}</span>
                  <span className="font-mono text-slate-500">{s.target}</span>
                </label>
              ))}
            </div>
          </div>
          <button type="submit" disabled={busy} className="btn-primary px-4 py-2">{busy ? 'Generating…' : 'Generate report'}</button>
        </form>
      )}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Report</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Format</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Status</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Date</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Size</th>
              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wider pr-5">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {loading ? (
              <tr><td colSpan={6} className="px-5 py-8 text-center text-sm text-slate-500">Loading reports…</td></tr>
            ) : reports.length === 0 ? (
              <tr><td colSpan={6} className="px-5 py-8 text-center text-sm text-slate-500">No reports yet.</td></tr>
            ) : reports.map(report => (
              <tr key={report.id} className="hover:bg-slate-50">
                <td className="px-5 py-4 font-medium text-slate-900">{report.title}</td>
                <td className="px-5 py-4 text-sm text-slate-600 uppercase">{report.format}</td>
                <td className="px-5 py-4">
                  <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-medium ${report.status === 'ready' ? 'bg-green-100 text-green-700' : report.status === 'failed' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'}`}>
                    {report.status}
                  </span>
                </td>
                <td className="px-5 py-4 text-sm text-slate-600">{report.created_at ? new Date(report.created_at).toLocaleDateString() : '—'}</td>
                <td className="px-5 py-4 text-sm text-slate-600">{report.file_size ? `${Math.round(report.file_size / 1024)} KB` : '—'}</td>
                <td className="px-5 py-4 text-right pr-5">
                  <div className="flex items-center justify-end gap-1">
                    {report.status === 'ready' && <button className="p-1.5 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Download" onClick={() => void download(report)}><Download size={14} /></button>}
                    <button className="p-1.5 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded" title="Delete" onClick={async () => { await reportsApi.remove(report.id); await load() }}><Trash2 size={14} /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <div className="px-5 py-3 border-t border-slate-200 flex items-center justify-between">
          <p className="text-sm text-slate-500">Displaying {reports.length} reports</p>
          <div className="flex items-center gap-2">
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100 disabled:opacity-50"><ChevronLeft size={16} /></button>
            <button className="px-3 py-1 border border-blue-500 text-blue-600 rounded bg-blue-50 text-sm">1</button>
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100"><ChevronRight size={16} /></button>
          </div>
        </div>
      </div>
    </div>
  )
}

function TemplatesTab({ onChanged }: { onChanged: () => void }) {
  const [templates, setTemplates] = useState<ReportTemplateRecord[]>([])
  const [name, setName] = useState('')
  const [type, setType] = useState('technical')
  const [error, setError] = useState<string | null>(null)

  const load = async () => {
    try {
      setTemplates(await reportTemplatesApi.list())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load templates')
    }
  }
  useEffect(() => { void load() }, [])

  const create = async (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) return
    try {
      await reportTemplatesApi.create({ name: name.trim(), type })
      setName('')
      await load()
      onChanged()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create template')
    }
  }

  return (
    <div className="space-y-4">
      <form onSubmit={create} className="flex flex-wrap gap-3 items-end">
        <div>
          <label className="text-xs font-medium text-slate-500">Template name</label>
          <input className="mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={name} onChange={e => setName(e.target.value)} placeholder="Client-facing technical" />
        </div>
        <div>
          <label className="text-xs font-medium text-slate-500">Type</label>
          <select className="mt-1 px-3 py-2 border border-slate-300 rounded-lg text-sm" value={type} onChange={e => setType(e.target.value)}>
            <option value="executive">Executive</option>
            <option value="technical">Technical</option>
            <option value="compliance">Compliance</option>
            <option value="custom">Custom</option>
          </select>
        </div>
        <button type="submit" className="btn-primary px-4 py-2">Add template</button>
      </form>
      {error && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{error}</div>}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {templates.map(template => (
          <div key={template.id} className="bg-white border border-slate-200 rounded-xl p-5">
            <div className="p-3 bg-slate-100 rounded-lg w-12 h-12 mb-3"><FileText size={24} className="text-slate-600" /></div>
            <h4 className="font-semibold text-slate-900">{template.name}</h4>
            <p className="text-sm text-slate-500 mt-1 capitalize">{template.type}{template.is_system ? ' · built-in' : ''}</p>
            <div className="mt-3 flex items-center gap-2 text-xs text-slate-500">
              {(template.default_formats.length ? template.default_formats : ['pdf']).map(f => <span key={f} className="px-2 py-1 bg-slate-100 rounded uppercase">{f}</span>)}
            </div>
            {!template.is_system && (
              <button className="btn-secondary w-full mt-4 px-3 py-2 text-sm" onClick={async () => { await reportTemplatesApi.remove(template.id); await load() }}>Delete</button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function BrandingTab() {
  return (
    <div className="space-y-6">
      <div className="bg-white border border-slate-200 rounded-xl p-5">
        <h3 className="font-semibold text-slate-900 mb-4">Branded Reports & Emails</h3>
        <p className="text-slate-500 mb-4">Customize your reports with your company branding.</p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Company Name</label>
            <input type="text" placeholder="Your Company" className="w-full px-3 py-2 border border-slate-300 rounded-lg" />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Logo</label>
            <input type="file" accept="image/*" className="w-full px-3 py-2 border border-slate-300 rounded-lg" />
          </div>
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-slate-700 mb-1">Primary Color</label>
            <input type="color" defaultValue="#2563eb" className="w-12 h-10 border border-slate-300 rounded-lg cursor-pointer" />
          </div>
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-slate-700 mb-1">Footer Text</label>
            <textarea rows={3} className="w-full px-3 py-2 border border-slate-300 rounded-lg" placeholder="Confidential — For authorized recipients only" />
          </div>
        </div>
        <div className="mt-6 flex justify-end">
          <button className="btn-primary px-6 py-2">Save Branding</button>
        </div>
      </div>
    </div>
  )
}
