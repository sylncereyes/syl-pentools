import { useState, type ChangeEvent } from 'react'
import { useAppStore } from '../store/useAppStore'
import { Plus, Search, Filter, Upload, Trash2, Edit, Eye, Server, ChevronLeft, ChevronRight, X, Check, Shield, Globe, Cpu, Columns, Filter as FilterIcon, X as XIcon } from 'lucide-react'
import { assetsApi, api } from '../lib/api'

function DropdownMenu({ trigger, children, align = 'right' }: { trigger: React.ReactNode; children: React.ReactNode; align?: 'left' | 'right' }) {
  const [open, setOpen] = useState(false)
  const dropdownRef = useState<HTMLDivElement>(null)

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

const riskColors = { none: 'bg-slate-100 text-slate-600', low: 'bg-green-100 text-green-700', medium: 'bg-yellow-100 text-yellow-700', high: 'bg-orange-100 text-orange-700', critical: 'bg-red-100 text-red-700' }
const riskIcons = { none: Globe, low: Shield, medium: Shield, high: Shield, critical: Shield }

export function Assets() {
  const { assets, createAsset, bootstrap, deleteAsset } = useAppStore()
  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [newAsset, setNewAsset] = useState({ target: '', type: 'hostname' as 'hostname' | 'ip', description: '' })
  const [importing, setImporting] = useState(false)
  const [importResult, setImportResult] = useState<string | null>(null)
  const [importError, setImportError] = useState<string | null>(null)
  const [selectedAsset, setSelectedAsset] = useState<typeof assets[0] | null>(null)
  const [showViewModal, setShowViewModal] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editAsset, setEditAsset] = useState({ target: '', type: 'hostname' as 'hostname' | 'ip', description: '' })
  const [showDeleteConfirm, setShowDeleteConfirm] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  const handleImportFile = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file) return
    setImportError(null)
    setImportResult(null)
    setImporting(true)
    try {
      const text = await file.text()
      const result = await assetsApi.import({ targets: text, type: 'hostname' })
      await bootstrap()
      const parts = [`Imported ${result.count} target(s)`]
      if (result.skipped.length) parts.push(`${result.skipped.length} duplicate(s) skipped`)
      if (result.invalid.length) parts.push(`${result.invalid.length} invalid line(s)`)
      if (result.over_limit.length) parts.push(`${result.over_limit.length} over plan limit`)
      setImportResult(parts.join(' · '))
    } catch (err) {
      setImportError(err instanceof Error ? err.message : 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  const filteredAssets = assets.filter(a =>
    a.target.toLowerCase().includes(search.toLowerCase()) ||
    a.description?.toLowerCase().includes(search.toLowerCase())
  )

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!newAsset.target.trim()) return
    try {
      await createAsset({
        target: newAsset.target.trim(),
        type: newAsset.type,
        description: newAsset.description.trim() || undefined,
      })
      setNewAsset({ target: '', type: 'hostname', description: '' })
      setShowModal(false)
    } catch {
      /* error is surfaced in the store */
    }
  }

  const handleView = (asset: typeof assets[0]) => {
    setSelectedAsset(asset)
    setShowViewModal(true)
  }

  const handleEdit = (asset: typeof assets[0]) => {
    setEditAsset({ target: asset.target, type: asset.type as 'hostname' | 'ip', description: asset.description || '' })
    setSelectedAsset(asset)
    setShowEditModal(true)
  }

  const handleEditSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!editAsset.target.trim() || !selectedAsset) return
    try {
      const token = localStorage.getItem('auth_token')
      const res = await fetch(`/api/assets/${selectedAsset.id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
        body: JSON.stringify({ target: editAsset.target.trim(), type: editAsset.type, description: editAsset.description.trim() || undefined }),
      })
      if (res.ok) {
        await bootstrap()
        setShowEditModal(false)
        setSelectedAsset(null)
      } else {
        alert('Failed to update asset')
      }
    } catch {
      alert('Failed to update asset')
    }
  }

  const handleDelete = async (assetId: string) => {
    if (!confirm('Are you sure you want to delete this asset? This action cannot be undone.')) return
    setDeleting(true)
    try {
      await deleteAsset(assetId)
      await bootstrap()
      setShowDeleteConfirm(null)
    } catch (err) {
      alert(err instanceof Error ? err.message : 'Failed to delete asset')
    } finally {
      setDeleting(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Assets</h1>
          <p className="text-slate-500 mt-1">An Asset is a hostname or an IP address of the system you want to scan.</p>
        </div>
        <div className="flex items-center gap-3">
          <button className="btn-secondary flex items-center gap-2 px-4 py-2" onClick={() => setShowModal(true)}>
            <Plus size={18} /> Add target
          </button>
          <label className={`btn-secondary flex items-center gap-2 px-4 py-2 cursor-pointer ${importing ? 'opacity-60' : ''}`}>
            <Upload size={18} /> {importing ? 'Importing…' : 'Import targets from .txt'}
            <input type="file" accept=".txt,text/plain" className="hidden" onChange={handleImportFile} disabled={importing} />
          </label>
        </div>
      </div>

      {importResult && <div className="rounded-lg bg-green-50 border border-green-200 px-4 py-2 text-sm text-green-700">{importResult}</div>}
      {importError && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{importError}</div>}

      {/* Search & Filters */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-4">
        <div className="relative flex-1 min-w-[250px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
          <input type="text" placeholder="Search assets..." value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
        </div>
        <DropdownMenu trigger={<button className="btn-secondary flex items-center gap-2 px-4 py-2"><FilterIcon size={18} /> Filters</button>}>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Risk Level: Critical</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Risk Level: High</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Risk Level: Medium</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Risk Level: Low</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Type: Hostname</button>
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Type: IP Address</button>
          <hr className="my-1 border-slate-200" />
          <button className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100">Clear all filters</button>
        </DropdownMenu>
        <DropdownMenu trigger={<button className="btn-secondary flex items-center gap-2 px-4 py-2"><Columns size={18} /> Table options</button>}>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Target
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Description
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Type
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Risk Level
          </label>
          <label className="w-full px-4 py-2 text-left text-sm text-slate-700 hover:bg-slate-100 flex items-center gap-2">
            <input type="checkbox" className="rounded border-slate-300 text-blue-600" checked /> Scans
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
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Target</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Description</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Type</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Risk Level</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Scans</th>
              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wider pr-5">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {filteredAssets.length === 0 ? (
              <tr>
                <td colSpan={6} className="px-5 py-12 text-center">
                  <div className="text-center py-10">
                    <Server size={48} className="mx-auto text-slate-300" />
                    <h4 className="mt-4 font-medium text-slate-900">You have no Assets yet.</h4>
                    <p className="text-sm text-slate-500 mt-1">Add your first target to start scanning</p>
                    <button className="btn-primary mt-4 px-4 py-2" onClick={() => setShowModal(true)}>Add target</button>
                  </div>
                </td>
              </tr>
            ) : (
              filteredAssets.map(asset => (
                <tr key={asset.id} className="hover:bg-slate-50">
                  <td className="px-5 py-4">
                    <div className="font-mono text-sm text-slate-900">{asset.target}</div>
                    <div className="text-xs text-slate-500">{asset.type}</div>
                  </td>
                  <td className="px-5 py-4 text-sm text-slate-600 max-w-xs truncate">{asset.description || '-'}</td>
                  <td className="px-5 py-4">
                    <span className="inline-flex items-center px-2 py-1 rounded-full text-xs font-medium bg-slate-100 text-slate-700">
                      {asset.type === 'hostname' ? '🌐 Hostname' : '🔢 IP Address'}
                    </span>
                  </td>
                  <td className="px-5 py-4">
                    <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${riskColors[asset.riskLevel]}`}>
                      {asset.riskLevel.charAt(0).toUpperCase() + asset.riskLevel.slice(1)}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-sm text-slate-600">{asset.scans}</td>
                  <td className="px-5 py-4 text-right pr-5">
                    <div className="flex items-center justify-end gap-1">
                      <button onClick={() => handleView(asset)} className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="View"><Eye size={16} /></button>
                      <button onClick={() => handleEdit(asset)} className="p-2 text-slate-400 hover:text-slate-600 hover:bg-slate-100 rounded" title="Edit"><Edit size={16} /></button>
                      <button onClick={() => setShowDeleteConfirm(asset.id)} className="p-2 text-slate-400 hover:text-red-600 hover:bg-red-50 rounded" title="Delete"><Trash2 size={16} /></button>
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {/* Pagination */}
        <div className="px-5 py-3 border-t border-slate-200 flex items-center justify-between">
          <p className="text-sm text-slate-500">Displaying {filteredAssets.length} assets</p>
          <div className="flex items-center gap-2">
            <select className="border border-slate-300 rounded px-3 py-1 text-sm"><option>10</option><option>25</option><option>50</option></select>
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100 disabled:opacity-50"><ChevronLeft size={16} /></button>
            <button className="px-3 py-1 border border-blue-500 text-blue-600 rounded bg-blue-50 text-sm">1</button>
            <button className="p-2 border border-slate-300 rounded hover:bg-slate-100"><ChevronRight size={16} /></button>
          </div>
        </div>
      </div>

      {/* Add Asset Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowModal(false)}>
          <div className="bg-white rounded-xl p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
            <h2 className="text-xl font-semibold mb-4">Add target</h2>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Target *</label>
                <input type="text" placeholder="example.com or 192.168.1.1" value={newAsset.target} onChange={e => setNewAsset({...newAsset, target: e.target.value})} required
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Type</label>
                <select value={newAsset.type} onChange={e => setNewAsset({...newAsset, type: e.target.value as 'hostname'|'ip'})}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                  <option value="hostname">Hostname</option>
                  <option value="ip">IP Address</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Description (optional)</label>
                <textarea placeholder="Internal web server" value={newAsset.description} onChange={e => setNewAsset({...newAsset, description: e.target.value})} rows={2}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
              </div>
              <div className="flex justify-end gap-3 pt-4">
                <button type="button" className="btn-secondary px-4 py-2" onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn-primary px-4 py-2">Add target</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* View Asset Modal */}
      {showViewModal && selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => { setShowViewModal(false); setSelectedAsset(null); }}>
          <div className="bg-white rounded-xl p-6 w-full max-w-lg mx-4 max-h-[80vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold">Asset Details</h2>
              <button onClick={() => { setShowViewModal(false); setSelectedAsset(null); }} className="p-2 text-slate-400 hover:text-slate-600"><X size={20} /></button>
            </div>
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-medium text-slate-500">Target</label>
                  <p className="font-mono text-sm text-slate-900">{selectedAsset.target}</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">Type</label>
                  <p className="text-sm text-slate-900">{selectedAsset.type === 'hostname' ? 'Hostname' : 'IP Address'}</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">Risk Level</label>
                  <span className={`inline-flex items-center px-2 py-1 rounded-full text-xs font-medium ${riskColors[selectedAsset.riskLevel]}`}>
                    {selectedAsset.riskLevel.charAt(0).toUpperCase() + selectedAsset.riskLevel.slice(1)}
                  </span>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">Scans</label>
                  <p className="text-sm text-slate-900">{selectedAsset.scans}</p>
                </div>
                <div className="col-span-2">
                  <label className="block text-xs font-medium text-slate-500">Description</label>
                  <p className="text-sm text-slate-600">{selectedAsset.description || '—'}</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">Created</label>
                  <p className="text-sm text-slate-900">{selectedAsset.createdAt ? new Date(selectedAsset.createdAt).toLocaleString() : '—'}</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500">ID</label>
                  <p className="font-mono text-xs text-slate-600">{selectedAsset.id}</p>
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6 pt-4 border-t border-slate-200">
              <button onClick={() => { setShowViewModal(false); setShowEditModal(true); }} className="btn-secondary px-4 py-2">Edit</button>
              <button onClick={() => { setShowViewModal(false); setShowDeleteConfirm(selectedAsset.id); }} className="btn-danger px-4 py-2">Delete</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit Asset Modal */}
      {showEditModal && selectedAsset && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => { setShowEditModal(false); setSelectedAsset(null); }}>
          <div className="bg-white rounded-xl p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
            <h2 className="text-xl font-semibold mb-4">Edit target</h2>
            <form onSubmit={handleEditSubmit} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Target *</label>
                <input type="text" placeholder="example.com or 192.168.1.1" value={editAsset.target} onChange={e => setEditAsset({...editAsset, target: e.target.value})} required
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Type</label>
                <select value={editAsset.type} onChange={e => setEditAsset({...editAsset, type: e.target.value as 'hostname'|'ip'})}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                  <option value="hostname">Hostname</option>
                  <option value="ip">IP Address</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Description (optional)</label>
                <textarea placeholder="Internal web server" value={editAsset.description} onChange={e => setEditAsset({...editAsset, description: e.target.value})} rows={2}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
              </div>
              <div className="flex justify-end gap-3 pt-4">
                <button type="button" className="btn-secondary px-4 py-2" onClick={() => { setShowEditModal(false); setSelectedAsset(null); }}>Cancel</button>
                <button type="submit" className="btn-primary px-4 py-2">Save changes</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowDeleteConfirm(null)}>
          <div className="bg-white rounded-xl p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
            <h2 className="text-xl font-semibold mb-2">Delete Asset</h2>
            <p className="text-slate-600 mb-6">Are you sure you want to delete this asset? This action cannot be undone.</p>
            <div className="flex justify-end gap-3">
              <button className="btn-secondary px-4 py-2" onClick={() => setShowDeleteConfirm(null)}>Cancel</button>
              <button className="btn-danger px-4 py-2" onClick={() => handleDelete(showDeleteConfirm)} disabled={deleting}>
                {deleting ? 'Deleting…' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}