import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { LayoutDashboard, Server, Activity, Bug, FileText, Settings, Plus, Menu, X, Link as LinkIcon, Users, Zap, Activity as ActivityIcon, LogOut, ChevronDown, Bot } from 'lucide-react'
import { useAppStore } from '../store/useAppStore'
import { useAuth } from '../context/AuthContext'

const navItems = [
  { path: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/assets', label: 'Assets', icon: Server, badge: '0' },
  { path: '/scans', label: 'Scans', icon: Activity },
  { path: '/findings', label: 'Findings', icon: Bug },
  { path: '/attack-surface', label: 'Attack Surface', icon: ActivityIcon },
  { path: '/reports', label: 'Reports', icon: FileText },
  { path: '/robots', label: 'Robots', icon: Bot },
  { path: '/ai-pentests', label: 'AI Pentests', icon: Zap },
  { path: '/integrations', label: 'Integrations', icon: LinkIcon },
  { path: '/team', label: 'Team', icon: Users },
  { path: '/settings', label: 'Settings', icon: Settings },
]

export function Layout() {
  const location = useLocation()
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const { workspace, workspaces, workspaceId, loadWorkspaces, switchWorkspace } = useAppStore()
  const { user, logout } = useAuth()

  useEffect(() => {
    void loadWorkspaces()
  }, [loadWorkspaces])

  const handleLogout = async () => {
    await logout()
    setUserMenuOpen(false)
  }

  return (
    <div className="min-h-screen flex bg-slate-50">
      {/* Sidebar */}
      <aside className={`fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-slate-200 transition-transform duration-200 ${sidebarOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-16 items-center justify-between px-4 border-b border-slate-200">
          <span className="font-semibold text-slate-900">Pentest Clone</span>
          <button onClick={() => setSidebarOpen(false)} className="md:hidden p-1 text-slate-500 hover:text-slate-700"><X size={20} /></button>
        </div>
        <nav className="p-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname.startsWith(item.path)
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  isActive ? 'bg-blue-50 text-blue-700' : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
                }`}
              >
                <Icon size={18} aria-hidden="true" />
                <span>{item.label}</span>
              </NavLink>
            )
          })}
        </nav>
        <div className="absolute bottom-0 left-0 right-0 p-4 border-t border-slate-200">
          {workspaces.length > 1 ? (
            <select
              value={workspaceId || ''}
              onChange={(e) => void switchWorkspace(e.target.value)}
              className="w-full mb-2 border border-slate-300 rounded-lg px-2 py-1.5 text-xs bg-white text-slate-700"
              title="Switch workspace"
            >
              {workspaces.map((ws) => (
                <option key={ws.id} value={ws.id}>{ws.name}</option>
              ))}
            </select>
          ) : (
            <p className="text-xs text-slate-500 mb-2">{workspace.name}</p>
          )}
          <p className="text-xs text-slate-400">{workspace.assetLimit} assets • {workspace.scanLimit} concurrent scans</p>
        </div>
      </aside>

      {/* Mobile overlay */}
      {!sidebarOpen && (
        <div className="fixed inset-0 z-40 bg-black/50 md:hidden" onClick={() => setSidebarOpen(false)} />
      )}

      {/* Main content */}
      <main className={`flex-1 transition-all duration-200 ${sidebarOpen ? 'ml-64' : 'ml-0'}`}>
        {/* Top bar */}
        <header className="sticky top-0 z-30 h-16 bg-white border-b border-slate-200 flex items-center justify-between px-4 md:px-6">
          <button onClick={() => setSidebarOpen(true)} className="md:hidden p-2 text-slate-500 hover:text-slate-700"><Menu size={24} /></button>
          <div className="flex items-center gap-4 ml-auto">
            <NavLink to="/scans/new" className="btn-primary flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg">
              <Plus size={18} /> New Scan
            </NavLink>
            {/* User menu */}
            <div className="relative" onClick={(e) => e.stopPropagation()}>
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2 p-1 rounded-lg hover:bg-slate-100"
              >
                <div className="w-8 h-8 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-700 text-sm font-medium">
                  {user?.full_name?.[0] || user?.email?.[0]?.toUpperCase() || 'U'}
                </div>
                <span className="hidden md:block text-sm font-medium text-slate-700">{user?.full_name || user?.email}</span>
                <ChevronDown size={16} className="text-slate-500" />
              </button>
              {userMenuOpen && (
                <>
                  <div className="fixed inset-0 z-40" onClick={() => setUserMenuOpen(false)} />
                  <div className="absolute right-0 mt-2 w-48 bg-white rounded-md shadow-lg border border-slate-200 py-1 z-50">
                    <div className="px-4 py-2 border-b border-slate-100">
                      <p className="text-sm font-medium text-slate-900">{user?.full_name || 'User'}</p>
                      <p className="text-xs text-slate-500">{user?.email}</p>
                    </div>
                    <button
                      onClick={handleLogout}
                      className="w-full flex items-center gap-2 px-4 py-2 text-sm text-slate-700 hover:bg-slate-100"
                    >
                      <LogOut size={16} /> Sign out
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </header>

        {/* Page content */}
        <div className="p-4 md:p-6">
          <Outlet />
        </div>
      </main>
    </div>
  )
}

// Button styles
const style = document.createElement('style')
style.textContent = `
  .btn-primary { background:#2563eb; color:white; border:none; cursor:pointer; transition:background 0.15s; }
  .btn-primary:hover { background:#1d4ed8; }
  .btn-secondary { background:#f1f5f9; color:#334155; border:1px solid #e2e8f0; cursor:pointer; transition:all 0.15s; }
  .btn-secondary:hover { background:#e2e8f0; }
  .badge { background:#dbeafe; color:#1d4ed8; font-size:0.7rem; font-weight:600; padding:0.1rem 0.4rem; border-radius:9999px; }
  .risk-critical { background:#fef2f2; color:#dc2626; border-color:#fecaca; }
  .risk-high { background:#fff7ed; color:#c2410c; border-color:#ffedd5; }
  .risk-medium { background:#fefce8; color:#a16207; border-color:#fef08a; }
  .risk-low { background:#f0fdf4; color:#16a34a; border-color:#bbf7d0; }
  .status-running { background:#dbeafe; color:#1d4ed8; }
  .status-completed { background:#dcfce7; color:#16a34a; }
  .status-pending { background:#f1f5f9; color:#475569; }
  .status-failed { background:#fef2f2; color:#dc2626; }
`
document.head.appendChild(style)