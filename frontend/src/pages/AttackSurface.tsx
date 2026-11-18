import { Fragment, useEffect, useMemo, useState } from 'react'
import { Globe, RefreshCw, Search, Shield, Cpu, Network, Server, ChevronDown, ChevronRight } from 'lucide-react'
import { api, type SurfaceData, type SurfaceHost } from '../lib/api'

const GROUPS = [
  { id: 'hostname', label: 'Hostname' },
  { id: 'ip_address', label: 'IP Address' },
  { id: 'port', label: 'Port' },
  { id: 'protocol', label: 'Protocol' },
  { id: 'service', label: 'Service' },
  { id: 'technology', label: 'Technology' },
] as const

function severityBadge(count: number, kind: 'critical' | 'high' | 'medium' | 'low' | 'info') {
  if (!count) return null
  const styles: Record<string, string> = {
    critical: 'bg-red-100 text-red-700',
    high: 'bg-orange-100 text-orange-700',
    medium: 'bg-yellow-100 text-yellow-700',
    low: 'bg-blue-100 text-blue-700',
    info: 'bg-slate-100 text-slate-600',
  }
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${styles[kind]}`}>
      {count} {kind}
    </span>
  )
}

export function AttackSurface() {
  const [data, setData] = useState<SurfaceData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [groupBy, setGroupBy] = useState<string>('hostname')
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await api.attackSurface({ groupBy })
      setData(result)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load attack surface')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupBy])

  const rows = useMemo(() => {
    if (!data) return []
    const q = search.trim().toLowerCase()
    if (!q) return data.rows
    return data.rows.filter((r) =>
      (r.hostname || '').toLowerCase().includes(q) ||
      (r.ip || '').toLowerCase().includes(q) ||
      r.technologies.some((t) => t.toLowerCase().includes(q)) ||
      r.ports.some((p) => (p.service || '').toLowerCase().includes(q) || String(p.port).includes(q))
    )
  }, [data, search])

  const toggle = (key: string) =>
    setExpanded((prev) => ({ ...prev, [key]: !prev[key] }))

  const summary = data?.summary

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Attack Surface</h1>
          <p className="text-slate-500 mt-1">
            Centralized view of hosts, ports, services and technologies discovered for this workspace.
          </p>
        </div>
        <button className="btn-secondary flex items-center gap-2 px-4 py-2" onClick={() => void load()}>
          <RefreshCw size={18} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {summary && (
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { label: 'Hosts', value: summary.hosts, icon: Server },
            { label: 'Ports', value: summary.ports, icon: Network },
            { label: 'Services', value: summary.services, icon: Cpu },
            { label: 'Technologies', value: summary.technologies, icon: Globe },
            { label: 'Findings', value: summary.findings, icon: Shield },
            { label: 'Critical + High', value: summary.critical + summary.high, icon: Shield },
          ].map(({ label, value, icon: Icon }) => (
            <div key={label} className="bg-white rounded-xl border border-slate-200 p-4">
              <div className="flex items-center gap-2 text-slate-500 text-xs uppercase tracking-wide">
                <Icon size={14} /> {label}
              </div>
              <div className="mt-2 text-2xl font-semibold text-slate-900">{value}</div>
            </div>
          ))}
        </div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 p-4 flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[240px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
          <input
            type="text"
            placeholder="Search hosts, ports, services, technologies..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
        <label className="text-sm text-slate-600 flex items-center gap-2">
          Group by
          <select
            value={groupBy}
            onChange={(e) => setGroupBy(e.target.value)}
            className="border border-slate-300 rounded-lg px-3 py-2 text-sm bg-white"
          >
            {GROUPS.map((g) => (
              <option key={g.id} value={g.id}>{g.label}</option>
            ))}
          </select>
        </label>
        {data?.last_scan_at && (
          <span className="text-xs text-slate-400 ml-auto">
            Last scan: {new Date(data.last_scan_at).toLocaleString()}
          </span>
        )}
      </div>

      {error && (
        <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl p-4 text-sm">{error}</div>
      )}

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <table className="w-full">
          <thead className="bg-slate-50 border-b border-slate-200">
            <tr>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">IP address</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Hostname</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">OS</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Ports</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Technology</th>
              <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Risk</th>
              <th className="px-5 py-3 text-right text-xs font-semibold text-slate-500 uppercase tracking-wider pr-5">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200">
            {loading && !data ? (
              <tr><td colSpan={7} className="px-5 py-12 text-center text-slate-500">Loading attack surface…</td></tr>
            ) : rows.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-5 py-12 text-center">
                  <Globe size={48} className="mx-auto text-slate-300" />
                  <h4 className="mt-4 font-medium text-slate-900">Attack surface is empty</h4>
                  <p className="text-sm text-slate-500 mt-1">Run a scan to populate hosts, ports and technologies.</p>
                </td>
              </tr>
            ) : (
              rows.map((host: SurfaceHost) => {
                const isOpen = !!expanded[host.key]
                return (
                  <Fragment key={host.key}>
                    <tr className="hover:bg-slate-50">
                      <td className="px-5 py-3 text-sm font-mono text-slate-700">{host.ip || '—'}</td>
                      <td className="px-5 py-3 text-sm text-slate-900">
                        {host.hostname || '—'}
                        {host.url && (
                          <a href={host.url} target="_blank" rel="noreferrer" className="ml-2 text-xs text-blue-600 hover:underline">
                            open
                          </a>
                        )}
                      </td>
                      <td className="px-5 py-3 text-sm text-slate-600">
                        {host.os || '—'} {host.os_accuracy ? <span className="text-xs text-slate-400">({host.os_accuracy}%)</span> : null}
                      </td>
                      <td className="px-5 py-3 text-sm text-slate-600">
                        {host.port_count === 0 ? '—' : (
                          <div className="flex flex-wrap gap-1">
                            {host.ports.slice(0, 4).map((p) => (
                              <span key={`${p.port}/${p.protocol}`} className="px-1.5 py-0.5 bg-slate-100 rounded text-xs font-mono">
                                {p.port}/{p.protocol}
                              </span>
                            ))}
                            {host.port_count > 4 && <span className="text-xs text-slate-400">+{host.port_count - 4}</span>}
                          </div>
                        )}
                      </td>
                      <td className="px-5 py-3 text-sm text-slate-600">
                        {host.technologies.length === 0 ? '—' : (
                          <div className="flex flex-wrap gap-1">
                            {host.technologies.slice(0, 3).map((t) => (
                              <span key={t} className="px-1.5 py-0.5 bg-indigo-50 text-indigo-700 rounded text-xs">{t}</span>
                            ))}
                            {host.technologies.length > 3 && <span className="text-xs text-slate-400">+{host.technologies.length - 3}</span>}
                          </div>
                        )}
                      </td>
                      <td className="px-5 py-3">
                        <div className="flex flex-wrap gap-1">
                          {severityBadge(host.vulns.critical, 'critical')}
                          {severityBadge(host.vulns.high, 'high')}
                          {severityBadge(host.vulns.medium, 'medium')}
                          {severityBadge(host.vulns.low, 'low')}
                          {!host.vuln_count && <span className="text-xs text-slate-400">none</span>}
                        </div>
                      </td>
                      <td className="px-5 py-3 text-right pr-5">
                        <button className="text-slate-500 hover:text-slate-900" onClick={() => toggle(host.key)}>
                          {isOpen ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                        </button>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr key={`${host.key}-details`} className="bg-slate-50">
                        <td colSpan={7} className="px-5 py-4">
                          <div className="grid md:grid-cols-2 gap-4 text-sm">
                            <div>
                              <h5 className="font-semibold text-slate-700 mb-2">Ports & services</h5>
                              {host.ports.length === 0 ? (
                                <p className="text-slate-400">No ports discovered.</p>
                              ) : (
                                <ul className="space-y-1">
                                  {host.ports.map((p) => (
                                    <li key={`${p.port}/${p.protocol}`} className="font-mono text-xs text-slate-600">
                                      {p.port}/{p.protocol} · {p.service || 'unknown'}
                                      {p.product ? ` · ${p.product}` : ''}
                                      {p.version ? ` ${p.version}` : ''}
                                    </li>
                                  ))}
                                </ul>
                              )}
                            </div>
                            <div>
                              <h5 className="font-semibold text-slate-700 mb-2">Technologies</h5>
                              {host.technologies.length === 0 ? (
                                <p className="text-slate-400">No technologies fingerprinted.</p>
                              ) : (
                                <div className="flex flex-wrap gap-1">
                                  {host.technologies.map((t) => (
                                    <span key={t} className="px-2 py-0.5 bg-indigo-50 text-indigo-700 rounded text-xs">{t}</span>
                                  ))}
                                </div>
                              )}
                              {host.hostnames.length > 1 && (
                                <>
                                  <h5 className="font-semibold text-slate-700 mt-3 mb-1">Known hostnames</h5>
                                  <p className="text-xs text-slate-600 break-all">{host.hostnames.join(', ')}</p>
                                </>
                              )}
                              {host.last_seen && (
                                <p className="text-xs text-slate-400 mt-3">Last seen: {new Date(host.last_seen).toLocaleString()}</p>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
