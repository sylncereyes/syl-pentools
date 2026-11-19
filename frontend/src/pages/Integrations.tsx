import { useState } from 'react'
import { useAppStore, type Integration } from '../store/useAppStore'
import { api } from '../lib/api'
import { MessageSquare, Users, Globe, Link2, Github, Cloud, Database, Zap, Shield, Search, Settings as SettingsIcon, ExternalLink, Plus, Minus } from 'lucide-react'

const integrations = [
  { id: 'teams', name: 'Microsoft Teams', icon: Users, description: 'View an instant summary of your scan results in your chosen Teams channel', color: 'bg-purple-600', docsUrl: '#', type: 'teams' as const },
  { id: 'slack', name: 'Slack', icon: MessageSquare, description: 'See a scan results digest on your Slack channel with custom notifications', color: 'bg-green-600', docsUrl: '#', type: 'slack' as const },
  { id: 'webhook', name: 'Webhook', icon: Globe, description: 'Get notifications when scan results include specific ports, CVEs, or risk levels', color: 'bg-blue-600', docsUrl: '#', type: 'webhook' as const },
  { id: 'jira', name: 'Jira', icon: Link2, description: 'Receive scan results directly to a Jira project for prioritization', color: 'bg-blue-400', docsUrl: '#', type: 'jira' as const },
  { id: 'github', name: 'GitHub Actions', icon: Github, description: 'Automatically test web apps for security issues before and after launching', color: 'bg-slate-700', docsUrl: '#', type: 'github' as const },
  { id: 'discord', name: 'Discord', icon: MessageSquare, description: 'Get the summary of your scans directly in your favorite Discord channel', color: 'bg-indigo-600', docsUrl: '#', type: 'discord' as const },
  { id: 'vanta', name: 'Vanta', icon: Shield, description: 'Automatically sync validated findings for smoother compliance operations', color: 'bg-teal-600', docsUrl: '#', type: 'vanta' as const },
  { id: 'burp', name: 'Burp Suite', icon: Zap, description: 'Push selected active issues from Burp into your Findings in seconds', color: 'bg-orange-600', docsUrl: '#', type: 'webhook' as const },
  { id: 'aws', name: 'AWS', icon: Cloud, description: 'Automatically import EC2 IPs, S3 bucket URLs for continuous monitoring', color: 'bg-orange-500', docsUrl: '#', type: 'aws' as const },
  { id: 'nucleus', name: 'Nucleus', icon: Database, description: 'Get findings from workspaces to your Nucleus projects', color: 'bg-pink-600', docsUrl: '#', type: 'webhook' as const },
  { id: 'mcp', name: 'Model Context Protocol', icon: Zap, description: 'Scan your applications using your favorite LLMs via MCP', color: 'bg-cyan-600', docsUrl: '#', type: 'webhook' as const },
  { id: 'cicd', name: 'Generic CI/CD', icon: Globe, description: 'Set up automatic security testing in your pipelines', color: 'bg-slate-600', docsUrl: '#', type: 'webhook' as const },
]

export function Integrations() {
  const { integrations: userIntegrations, setIntegrations, toggleIntegration } = useAppStore()
  const [search, setSearch] = useState('')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const backendIds = new Set(['slack', 'teams', 'jira', 'webhook', 'github', 'discord', 'aws', 'vanta'])
  const mergedIntegrations = integrations.map(i => ({
    ...i,
    configured: userIntegrations.find(ui => ui.id === i.id)?.configured ?? false,
    enabled: userIntegrations.find(ui => ui.id === i.id)?.enabled ?? false,
  }))

  const filtered = mergedIntegrations.filter(i =>
    i.name.toLowerCase().includes(search.toLowerCase()) ||
    i.description.toLowerCase().includes(search.toLowerCase())
  )

  const toggleEnabled = (id: string) => {
    if (backendIds.has(id) && userIntegrations.some(ui => ui.id === id)) {
      void toggleIntegration(id)
      return
    }
    const existing = userIntegrations.find(ui => ui.id === id)
    if (existing) {
      setIntegrations(userIntegrations.map(ui => ui.id === id ? { ...ui, enabled: !ui.enabled } : ui))
    } else {
      const catalogEntry = integrations.find(i => i.id === id)!
      setIntegrations([...userIntegrations, { ...catalogEntry, configured: true, enabled: true } as Integration])
    }
  }

  const configure = (id: string) => {
    const catalogEntry = integrations.find(i => i.id === id)!
    if (backendIds.has(id)) {
      const existing = userIntegrations.find(ui => ui.id === id)
      if (!existing) {
        void api.configureIntegration(id, {}).then(() => {
          setIntegrations([...userIntegrations, { ...catalogEntry, configured: true, enabled: true } as Integration])
        }).catch(() => undefined)
      }
    } else if (!userIntegrations.some(ui => ui.id === id)) {
      setIntegrations([...userIntegrations, { ...catalogEntry, configured: true, enabled: false } as Integration])
    }
    setExpandedId(expandedId === id ? null : id)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Integrations</h1>
          <p className="text-slate-500 mt-1">Connect external applications and services to get the latest updates from your scans.</p>
        </div>
      </div>

      {/* Search */}
      <div className="bg-white rounded-xl border border-slate-200 p-4 max-w-md">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" size={18} />
          <input type="text" placeholder="Search integrations..." value={search} onChange={e => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 border border-slate-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
{filtered.map(integration => {
          const isConfigured = integration.configured
          return (
            <IntegrationCard
              key={integration.id}
              integration={integration}
              isConfigured={isConfigured}
              isExpanded={expandedId === integration.id}
              onToggle={() => setExpandedId(expandedId === integration.id ? null : integration.id)}
              onConfigure={isConfigured ? () => setExpandedId(expandedId === integration.id ? null : integration.id) : () => configure(integration.id)}
              onToggleEnabled={isConfigured ? () => toggleEnabled(integration.id) : undefined}
              enabled={integration.enabled}
            />
          )
        })}
      </div>

      {/* Add Custom Integration */}
      <div className="bg-white rounded-xl border border-slate-200 border-dashed p-8 text-center">
        <Plus size={48} className="mx-auto text-slate-300 mb-4" />
        <h3 className="font-semibold text-slate-900 mb-1">Add Custom Integration</h3>
        <p className="text-slate-500 mb-4">Don't see your tool? Build a custom webhook integration.</p>
        <button className="btn-secondary px-6 py-2">Create Webhook</button>
      </div>
    </div>
  )
}

function IntegrationCard({
  integration,
  isConfigured,
  isExpanded,
  onToggle,
  onConfigure,
  onToggleEnabled,
  enabled,
}: {
  integration: typeof integrations[0]
  isConfigured: boolean
  isExpanded: boolean
  onToggle: () => void
  onConfigure: () => void
  onToggleEnabled?: () => void
  enabled?: boolean
}) {
  const Icon = integration.icon
  return (
    <div className={`bg-white rounded-xl border border-slate-200 p-5 transition-all ${isExpanded ? 'border-blue-300 shadow-md' : 'hover:border-blue-300'}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className={`p-3 rounded-xl ${integration.color} text-white`}><Icon size={24} /></div>
          <div>
            <h4 className="font-semibold text-slate-900">{integration.name}</h4>
            <p className="text-sm text-slate-500">{integration.description}</p>
          </div>
        </div>
        {isConfigured && (
          <label className="relative inline-flex items-center cursor-pointer">
            <input type="checkbox" checked={enabled} onChange={onToggleEnabled} className="peer w-5 h-5 rounded border-slate-300 text-blue-600 focus:ring-blue-500" />
            <div className="peer-focus:ring-2 peer-focus:ring-blue-500 peer-focus:ring-offset-2"></div>
          </label>
        )}
      </div>

      <div className="text-sm text-slate-600 mb-4 line-clamp-2">{integration.description}</div>

      {!isConfigured ? (
        <button onClick={onConfigure} className="btn-primary w-full justify-center px-4 py-2 text-sm">
          <Plus size={14} className="mr-1" /> Configure
        </button>
      ) : (
        <div className="space-y-3">
          <div className="flex items-center justify-between py-2 border-t border-slate-200">
            <span className="text-sm text-slate-600">Status</span>
            <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-medium ${enabled ? 'bg-green-100 text-green-700' : 'bg-slate-100 text-slate-600'}`}>
              {enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          <div className="flex gap-2">
            <button onClick={onToggle} className="btn-secondary flex-1 justify-center px-3 py-1.5 text-sm">
              {isExpanded ? <Minus size={14} /> : <SettingsIcon size={14} />} {isExpanded ? 'Hide Config' : 'Configure'}
            </button>
            <button className="btn-secondary px-3 py-1.5 text-sm"><ExternalLink size={14} /></button>
          </div>

          {isExpanded && (
            <div className="bg-slate-50 rounded-lg p-4 border border-slate-200 space-y-3 animate-slide-down">
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Webhook URL / API Endpoint</label>
                <input type="text" placeholder="https://your-webhook-endpoint.com" className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm" />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-700 mb-1">Authentication</label>
                <select className="w-full px-3 py-2 border border-slate-300 rounded-lg text-sm">
                  <option>Bearer Token</option>
                  <option>API Key</option>
                  <option>Basic Auth</option>
                  <option>No Auth</option>
                </select>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" className="rounded border-slate-300 text-blue-600" />
                  <span className="text-slate-600">Critical only</span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" className="rounded border-slate-300 text-blue-600" />
                  <span className="text-slate-600">High & above</span>
                </label>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" className="rounded border-slate-300 text-blue-600" />
                  <span className="text-slate-600">Include false positives</span>
                </label>
              </div>
              <button className="btn-secondary w-full justify-center px-3 py-1.5 text-sm">Save Configuration</button>
            </div>
          )}
        </div>
      )}
      <a href={integration.docsUrl} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-600 hover:underline mt-3 block text-center">Documentation</a>
    </div>
  )
}

// Add animation
const style = document.createElement('style')
style.textContent = `
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .animate-slide-down { animation: slideDown 0.2s ease-out; }
`
document.head.appendChild(style)