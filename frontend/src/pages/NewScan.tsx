import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppStore } from '../store/useAppStore'
import { ArrowLeft, Check, Globe, Server, Wifi, Search, Code, Key, Shield, Cloud, Zap, FileCode, Globe2 } from 'lucide-react'
import { NavLink } from 'react-router-dom'

const scanTypes = [
  { id: 'website', name: 'Website Scanner', icon: Globe, desc: 'Discover XSS, SQLi, RCE and 70+ web application issues.', color: 'bg-blue-500', category: 'web' },
  { id: 'api', name: 'API Scanner (REST/GraphQL)', icon: Globe2, desc: 'OpenAPI/GraphQL schema parsing + fuzzing', color: 'bg-cyan-500', category: 'web' },
  { id: 'cms', name: 'WordPress/Drupal Scanner', icon: Shield, desc: 'WPScan + Nuclei CMS templates', color: 'bg-indigo-500', category: 'web' },
  { id: 'network', name: 'Network Scanner', icon: Server, desc: 'Check for 10,000+ CVEs and server misconfigurations.', color: 'bg-purple-500', category: 'network' },
  { id: 'port', name: 'Port Scanner', icon: Wifi, desc: 'Detect open ports and fingerprint services.', color: 'bg-green-500', category: 'network' },
  { id: 'subdomain', name: 'Subdomain Finder', icon: Search, desc: 'subfinder enumeration with DNS verification.', color: 'bg-orange-500', category: 'network' },
  { id: 'recon', name: 'Website Recon', icon: Code, desc: 'whatweb + HTTP header technology fingerprinting.', color: 'bg-pink-500', category: 'network' },
  { id: 'cloud', name: 'Cloud Scanner (Azure/GCP)', icon: Cloud, desc: 'Asset discovery + config auditing', color: 'bg-sky-500', category: 'cloud' },
  { id: 'exploit', name: 'Active Exploitation (Sniper)', icon: Zap, desc: 'SQLi, XSS, RCE auto-exploitation', color: 'bg-red-600', category: 'exploit' },
  { id: 'password', name: 'Password Auditor', icon: Key, desc: 'Anonymous and default credential exposure checks.', color: 'bg-red-500', category: 'auth' },
  { id: 'burp', name: 'Burp Import', icon: FileCode, desc: 'Import & normalize Burp Suite findings', color: 'bg-amber-500', category: 'import' },
  { id: 'fuzzer', name: 'URL Fuzzer', icon: Search, desc: 'Directory & file discovery with ffuf.', color: 'bg-lime-600', category: 'discovery' },
  { id: 'vhost', name: 'Virtual Host Finder', icon: Server, desc: 'Discover hidden virtual hosts with gobuster.', color: 'bg-teal-600', category: 'discovery' },
  { id: 'domain_finder', name: 'Domain Finder', icon: Globe, desc: 'Related domains via certificate transparency.', color: 'bg-emerald-600', category: 'discovery' },
  { id: 'google_hacking', name: 'Google Hacking', icon: Search, desc: 'Search-engine dorks for exposed data.', color: 'bg-yellow-600', category: 'osint' },
  { id: 'people_hunter', name: 'People Hunter', icon: Shield, desc: 'OSINT emails and hosts (theHarvester).', color: 'bg-fuchsia-600', category: 'osint' },
  { id: 'http_logger', name: 'HTTP Request Logger', icon: Code, desc: 'Capture and log HTTP request/response pairs.', color: 'bg-slate-600', category: 'web' },
]

export function NewScan() {
  const navigate = useNavigate()
  const { assets, createScan } = useAppStore()
  const [selectedType, setSelectedType] = useState<string | null>(null)
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const [target, setTarget] = useState('')
  const [options, setOptions] = useState({ authenticated: false, schedule: false, intensity: 'normal' })
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState('')

  const handleStart = async () => {
    if (!selectedType || !target.trim() || starting) return
    setStarting(true)
    setError('')
    try {
      await createScan({
        type: selectedType,
        target: target.trim(),
        intensity: options.intensity,
        is_authenticated: options.authenticated,
      })
      navigate('/scans')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not start scan')
    } finally {
      setStarting(false)
    }
  }

  const getPlaceholder = (type: string) => {
    switch (type) {
      case 'subdomain': return 'example.com'
      case 'cms': return 'https://example.com'
      case 'api': return 'https://api.example.com or /openapi.json'
      case 'cloud': return 'subscription-id or project-id'
      case 'exploit': return 'https://example.com or 192.168.1.1'
      case 'burp': return 'auto or /path/to/burp/export.xml'
      default: return 'https://example.com or 192.168.1.1'
    }
  }

  const getTargetHelp = (type: string) => {
    switch (type) {
      case 'website': return 'Enter a full URL (https://example.com)'
      case 'api': return 'Enter API base URL or OpenAPI spec URL'
      case 'cms': return 'Enter WordPress/Drupal site URL (https://example.com)'
      case 'subdomain': return 'Enter a root domain (example.com)'
      case 'cloud': return 'Enter Azure subscription ID or GCP project ID'
      case 'exploit': return 'Enter target URL or IP for exploitation'
      case 'burp': return 'Enter "auto" to scan directory, or path to Burp export file'
      case 'password': return 'Enter a full URL (https://example.com) or IP'
      default: return 'Enter a full URL (https://example.com) or IP address/CIDR'
    }
  }

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <NavLink to="/scans" className="inline-flex items-center gap-2 text-slate-600 hover:text-slate-900 text-sm font-medium">
        <ArrowLeft size={18} /> Back to Scans
      </NavLink>

      <div className="bg-white rounded-xl border border-slate-200 p-6">
        <h1 className="text-2xl font-bold text-slate-900">New scan</h1>
        <p className="text-slate-500 mt-1">Select a scan type and configure your target.</p>

        {/* Scan Type Selection */}
        <div className="mt-6">
          <h3 className="font-semibold text-slate-900 mb-3">Scan Type</h3>

          {/* Category tabs */}
          <div className="mb-4 flex flex-wrap gap-2">
            {['web', 'network', 'discovery', 'osint', 'cloud', 'exploit', 'auth', 'import'].map(cat => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  selectedCategory === cat
                    ? 'bg-blue-500 text-white'
                    : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                }`}
              >
                {cat.charAt(0).toUpperCase() + cat.slice(1)}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {scanTypes
              .filter(type => !selectedCategory || type.category === selectedCategory)
              .map(type => {
                const Icon = type.icon
                const isSelected = selectedType === type.id
                return (
                  <button
                    key={type.id}
                    onClick={() => setSelectedType(type.id)}
                    className={`p-4 border-2 rounded-xl transition-all text-left ${isSelected ? 'border-blue-500 bg-blue-50' : 'border-slate-200 hover:border-blue-300'}`}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`p-3 rounded-lg ${type.color}`}><Icon size={24} className="text-white" /></div>
                      <div>
                        <p className="font-medium text-slate-900">{type.name}</p>
                        <p className="text-sm text-slate-500">{type.desc}</p>
                      </div>
                    </div>
                    {isSelected && <Check className="text-blue-500 ml-auto" size={24} />}
                  </button>
                )
              })}
          </div>
        </div>

        {/* Target Configuration */}
        {selectedType && (
          <div className="mt-6 border-t border-slate-200 pt-6">
            <h3 className="font-semibold text-slate-900 mb-3">Target Configuration</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Target *</label>
                <input type="text" placeholder={getPlaceholder(selectedType)}
                  value={target} onChange={e => setTarget(e.target.value)}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
                <p className="text-xs text-slate-500 mt-1">
                  {getTargetHelp(selectedType)}
                </p>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={options.authenticated} onChange={e => setOptions({...options, authenticated: e.target.checked})}
                    className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500" />
                  <span className="text-sm text-slate-700">Authenticated scan (login required)</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={options.schedule} onChange={e => setOptions({...options, schedule: e.target.checked})}
                    className="w-4 h-4 rounded border-slate-300 text-blue-600 focus:ring-blue-500" />
                  <span className="text-sm text-slate-700">Schedule recurring scans</span>
                </label>
              </div>

              {options.authenticated && (
                <div className="bg-slate-50 rounded-lg p-4 border border-slate-200">
                  <p className="font-medium text-slate-900 mb-2">Authentication Settings</p>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                    <div><label className="block text-slate-500 mb-1">Username</label><input type="text" className="w-full px-3 py-2 border border-slate-300 rounded-lg" /></div>
                    <div><label className="block text-slate-500 mb-1">Password</label><input type="password" className="w-full px-3 py-2 border border-slate-300 rounded-lg" /></div>
                    <div className="md:col-span-2"><label className="block text-slate-500 mb-1">Custom Headers / Cookies</label><textarea className="w-full px-3 py-2 border border-slate-300 rounded-lg" rows={2} /></div>
                  </div>
                </div>
              )}

              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Scan Intensity</label>
                <select value={options.intensity} onChange={e => setOptions({...options, intensity: e.target.value})}
                  className="w-full max-w-xs px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                  <option value="light">Light (Fast, limited checks)</option>
                  <option value="normal">Normal (Balanced)</option>
                  <option value="aggressive">Aggressive (Thorough, slower)</option>
                </select>
              </div>
            </div>
          </div>
        )}

        {/* Asset Selection */}
        {assets.length > 0 && (
          <div className="mt-6 border-t border-slate-200 pt-6">
            <h3 className="font-semibold text-slate-900 mb-3">Or select from Assets</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 max-h-48 overflow-y-auto border border-slate-200 rounded-lg p-2">
              {assets.map(asset => (
                <label key={asset.id} className="flex items-center gap-2 p-2 hover:bg-slate-50 rounded cursor-pointer">
                  <input type="radio" name="asset-select" value={asset.target} onChange={e => setTarget(e.target.value)} className="text-blue-600" />
                  <span className="font-mono text-sm">{asset.target}</span>
                  <span className="text-xs text-slate-500">({asset.type})</span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="mt-8 border-t border-slate-200 pt-6">
          {error && <p className="mb-3 text-sm text-red-600">{error}</p>}
          <div className="flex justify-end gap-3">
            <NavLink to="/scans" className="btn-secondary px-6 py-2">Cancel</NavLink>
            <button onClick={handleStart} disabled={!selectedType || !target.trim() || starting} className="btn-primary px-6 py-2">
              {starting ? 'Starting…' : 'Start Scan'}
            </button>
          </div>
        </div>
      </div>

      {/* Quick Help */}
      <div className="bg-slate-50 rounded-xl p-5">
        <h4 className="font-semibold text-slate-900 mb-3 flex items-center gap-2"><Shield size={20} /> Which scan type should I choose?</h4>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
          <div className="bg-white p-3 rounded-lg border border-slate-200"><p className="font-medium text-slate-900">Web apps</p><p className="text-slate-500 mt-1">Website Scanner, API Scanner, CMS Scanner</p></div>
          <div className="bg-white p-3 rounded-lg border border-slate-200"><p className="font-medium text-slate-900">Infrastructure</p><p className="text-slate-500 mt-1">Network Scanner, Port Scanner</p></div>
          <div className="bg-white p-3 rounded-lg border border-slate-200"><p className="font-medium text-slate-900">Discovery</p><p className="text-slate-500 mt-1">Subdomain Finder, Website Recon</p></div>
          <div className="bg-white p-3 rounded-lg border border-slate-200"><p className="font-medium text-slate-900">Cloud</p><p className="text-slate-500 mt-1">Azure/GCP asset discovery & config audit</p></div>
          <div className="bg-white p-3 rounded-lg border border-slate-200"><p className="font-medium text-slate-900">Exploitation</p><p className="text-slate-500 mt-1">SQLi, XSS, RCE auto-exploitation</p></div>
          <div className="bg-white p-3 rounded-lg border border-slate-200"><p className="font-medium text-slate-900">Import</p><p className="text-slate-500 mt-1">Burp Suite findings import</p></div>
        </div>
      </div>
    </div>
  )
}