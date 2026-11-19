import { useState, useEffect } from 'react'
import { User, Shield, Bell, Key, CreditCard, Users, Moon, Monitor, Save, Plus, CheckCircle, Sun } from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import BillingTabComponent from '../components/BillingTab'

type TabId = 'profile' | 'security' | 'mfa' | 'notifications' | 'appearance' | 'billing' | 'team' | 'api' | 'authenticated-scans'

export function Settings() {
  const [activeTab, setActiveTab] = useState<TabId>('profile')

  const tabs: { id: TabId; label: string; icon: LucideIcon }[] = [
    { id: 'profile', label: 'Profile', icon: User },
    { id: 'security', label: 'Security', icon: Shield },
    { id: 'mfa', label: 'MFA & SSO', icon: Shield },
    { id: 'notifications', label: 'Notifications', icon: Bell },
    { id: 'appearance', label: 'Appearance', icon: Monitor },
    { id: 'billing', label: 'Billing', icon: CreditCard },
    { id: 'team', label: 'Team', icon: Users },
    { id: 'api', label: 'API Keys', icon: Key },
    { id: 'authenticated-scans', label: 'Auth Scans', icon: Monitor },
  ]

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-900">Settings</h1>
          <p className="text-slate-500 mt-1">Manage your account and workspace settings.</p>
        </div>
      </div>

      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="flex flex-col md:flex-row">
          <nav className="w-full md:w-52 border-r border-slate-200 md:border-r-0 p-4 bg-slate-50">
            <ul className="space-y-1">
              {tabs.map(tab => {
                const Icon = tab.icon
                const isActive = activeTab === tab.id
                return (
                  <li key={tab.id}>
                    <button onClick={() => setActiveTab(tab.id)} className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${isActive ? 'bg-blue-50 text-blue-700' : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'}`}>
                      <Icon size={18} />
                      {tab.label}
                    </button>
                  </li>
                )
              })}
            </ul>
          </nav>

          <div className="flex-1 p-6">
            {activeTab === 'profile' && <ProfileTab />}
            {activeTab === 'security' && <SecurityTab setActiveTab={setActiveTab} />}
            {activeTab === 'mfa' && <MFATab />}
            {activeTab === 'notifications' && <NotificationsTab />}
            {activeTab === 'appearance' && <AppearanceTab />}
            {activeTab === 'billing' && <BillingTabComponent />}
            {activeTab === 'team' && <TeamTab />}
            {activeTab === 'api' && <APITab />}
            {activeTab === 'authenticated-scans' && <AuthenticatedScansTab />}
          </div>
        </div>
      </div>
    </div>
  )
}

function ProfileTab() {
  return (
    <form className="space-y-6 max-w-xl">
      <div className="flex items-center gap-4">
        <div className="w-20 h-20 rounded-full bg-slate-200 flex items-center justify-center text-2xl font-medium text-slate-600">U</div>
        <div>
          <h3 className="font-semibold text-slate-900">Profile Picture</h3>
          <p className="text-sm text-slate-500">JPG, GIF or PNG. Max 2MB.</p>
          <button className="btn-secondary mt-2 px-4 py-2 text-sm">Change Picture</button>
        </div>
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div><label className="block text-sm font-medium text-slate-700 mb-1">Full Name</label><input type="text" defaultValue="John Doe" className="w-full px-3 py-2 border border-slate-300 rounded-lg" /></div>
        <div><label className="block text-sm font-medium text-slate-700 mb-1">Email</label><input type="email" defaultValue="john@example.com" className="w-full px-3 py-2 border border-slate-300 rounded-lg" /></div>
      </div>
      <div><label className="block text-sm font-medium text-slate-700 mb-1">Bio</label><textarea rows={3} className="w-full px-3 py-2 border border-slate-300 rounded-lg" placeholder="Tell us about yourself..." /></div>
      <div className="flex justify-end">
        <button className="btn-primary px-6 py-2 flex items-center gap-2"><Save size={18} /> Save Changes</button>
      </div>
    </form>
  )
}

function SecurityTab({ setActiveTab }: { setActiveTab: (tab: TabId) => void }) {
  const [sessions, setSessions] = useState<Array<{id: string; ip_address: string | null; user_agent: string | null; created_at: string | null; expires_at: string | null; is_current: boolean}>>([])
  const [loadingSessions, setLoadingSessions] = useState(true)
  const [showChangePassword, setShowChangePassword] = useState(false)
  const [passwordForm, setPasswordForm] = useState({ current_password: '', new_password: '', confirm_password: '' })
  const [passwordError, setPasswordError] = useState<string | null>(null)
  const [passwordLoading, setPasswordLoading] = useState(false)

  const token = localStorage.getItem('auth_token')
  const authHeaders = { ...(token && { Authorization: `Bearer ${token}` }), 'Content-Type': 'application/json' }

  const loadSessions = async () => {
    setLoadingSessions(true)
    try {
      const res = await fetch('/api/auth/sessions', { headers: authHeaders })
      if (res.ok) {
        const data = await res.json()
        setSessions(data)
      }
    } catch (e) {
      console.error('Failed to load sessions:', e)
    } finally {
      setLoadingSessions(false)
    }
  }

  const revokeSession = async (sessionId: string) => {
    if (!confirm('Revoke this session?')) return
    try {
      const res = await fetch(`/api/auth/sessions/${sessionId}`, { method: 'DELETE', headers: authHeaders })
      if (res.ok) {
        setSessions(sessions.filter(s => s.id !== sessionId))
      } else {
        alert('Failed to revoke session')
      }
    } catch (e) {
      console.error('Failed to revoke session:', e)
    }
  }

  const revokeAllSessions = async () => {
    if (!confirm('Revoke all other sessions? You will stay logged in on this device.')) return
    try {
      const res = await fetch('/api/auth/sessions/revoke-all', { method: 'POST', headers: authHeaders, body: JSON.stringify({ keep_current: true }) })
      if (res.ok) {
        const data = await res.json()
        alert(`Revoked ${data.revoked} sessions`)
        loadSessions()
      } else {
        alert('Failed to revoke sessions')
      }
    } catch (e) {
      console.error('Failed to revoke all sessions:', e)
    }
  }

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setPasswordError(null)
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setPasswordError('Passwords do not match')
      return
    }
    if (passwordForm.new_password.length < 8) {
      setPasswordError('Password must be at least 8 characters')
      return
    }
    setPasswordLoading(true)
    try {
      const res = await fetch('/api/auth/change-password', {
        method: 'POST',
        headers: authHeaders,
        body: JSON.stringify({ current_password: passwordForm.current_password, new_password: passwordForm.new_password }),
      })
      if (res.ok) {
        setShowChangePassword(false)
        setPasswordForm({ current_password: '', new_password: '', confirm_password: '' })
        alert('Password changed successfully')
      } else {
        const err = await res.json()
        setPasswordError(err.detail || 'Failed to change password')
      }
    } catch (e) {
      setPasswordError('Failed to change password')
    } finally {
      setPasswordLoading(false)
    }
  }

  useEffect(() => { loadSessions() }, [])

  return (
    <div className="space-y-6 max-w-xl">
      <Section title="Two-Factor Authentication" description="Add an extra layer of security to your account.">
        <div className="flex items-center justify-between p-4 bg-green-50 border border-green-200 rounded-lg">
          <div>
            <p className="font-medium text-green-900">2FA Enabled</p>
            <p className="text-sm text-green-700">Authenticator app</p>
          </div>
          <button onClick={() => setActiveTab('mfa')} className="btn-secondary px-4 py-2 text-sm">Manage</button>
        </div>
      </Section>

      <Section title="Password" description="Your password was last changed 30 days ago.">
        <button onClick={() => setShowChangePassword(true)} className="btn-secondary px-4 py-2">Change Password</button>
      </Section>

      <Section title="Active Sessions" description="Manage where you're logged in.">
        <div className="space-y-2">
          {loadingSessions ? (
            <div className="text-sm text-slate-500">Loading sessions…</div>
          ) : sessions.length === 0 ? (
            <div className="text-sm text-slate-500">No active sessions</div>
          ) : (
            sessions.map(session => (
              <SessionRow
                key={session.id}
                session={session}
                onRevoke={revokeSession}
              />
            ))
          )}
          {!loadingSessions && sessions.length > 1 && (
            <button onClick={revokeAllSessions} className="btn-secondary text-sm px-3 py-1 mt-2">
              Revoke all other sessions
            </button>
          )}
        </div>
      </Section>

      {showChangePassword && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={() => setShowChangePassword(false)}>
          <div className="bg-white rounded-xl p-6 w-full max-w-md mx-4" onClick={e => e.stopPropagation()}>
            <h2 className="text-xl font-semibold mb-4">Change Password</h2>
            <form onSubmit={handleChangePassword} className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Current Password</label>
                <input type="password" value={passwordForm.current_password} onChange={e => setPasswordForm({...passwordForm, current_password: e.target.value})} required
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">New Password</label>
                <input type="password" value={passwordForm.new_password} onChange={e => setPasswordForm({...passwordForm, new_password: e.target.value})} required minLength={8}
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
              </div>
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1">Confirm New Password</label>
                <input type="password" value={passwordForm.confirm_password} onChange={e => setPasswordForm({...passwordForm, confirm_password: e.target.value})} required
                  className="w-full px-3 py-2 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
              </div>
              {passwordError && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-2 text-sm text-red-700">{passwordError}</div>}
              <div className="flex justify-end gap-3 pt-4">
                <button type="button" className="btn-secondary px-4 py-2" onClick={() => setShowChangePassword(false)}>Cancel</button>
                <button type="submit" disabled={passwordLoading} className="btn-primary px-4 py-2">{passwordLoading ? 'Changing…' : 'Change Password'}</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

function NotificationsTab() {
  return (
    <div className="space-y-6 max-w-xl">
      <Section title="Email Notifications" description="Choose what emails you receive.">
        <NotificationToggle label="Scan completed" description="When a scan finishes" enabled />
        <NotificationToggle label="Critical findings" description="When critical vulnerabilities are found" enabled />
        <NotificationToggle label="Scheduled scan reminders" description="Before scheduled scans run" enabled={false} />
        <NotificationToggle label="Weekly security digest" description="Summary of your security posture" enabled={false} />
        <NotificationToggle label="Product updates" description="New features and announcements" enabled />
      </Section>

      <Section title="In-App Notifications" description="Real-time alerts in the dashboard.">
        <NotificationToggle label="Scan status changes" description="Running, completed, failed" enabled />
        <NotificationToggle label="New findings" description="When vulnerabilities are discovered" enabled />
        <NotificationToggle label="Team activity" description="When teammates perform actions" enabled />
      </Section>
    </div>
  )
}

function AppearanceTab() {
  return (
    <div className="space-y-6 max-w-xl">
      <Section title="Theme" description="Choose your preferred color scheme.">
        <div className="grid grid-cols-3 gap-4">
          <ThemeOption name="Light" icon={Sun} selected={false} />
          <ThemeOption name="Dark" icon={Moon} selected={false} />
          <ThemeOption name="System" icon={Monitor} selected={true} />
        </div>
      </Section>

      <Section title="Density" description="Adjust spacing for your preference.">
        <div className="grid grid-cols-3 gap-4">
          <DensityOption name="Comfortable" selected={false} />
          <DensityOption name="Standard" selected={true} />
          <DensityOption name="Compact" selected={false} />
        </div>
      </Section>
    </div>
  )
}


function TeamTab() {
  return (
    <div className="space-y-6 max-w-xl">
      <Section title="Team Members" description="Invite and manage team access.">
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm text-slate-500">3 of 10 seats used</p>
          <button className="btn-primary px-4 py-2 text-sm">Invite Member</button>
        </div>
        <div className="space-y-2">
          <TeamRow name="John Doe" email="john@example.com" role="Owner" current />
          <TeamRow name="Sarah Smith" email="sarah@example.com" role="Admin" />
          <TeamRow name="Mike Wilson" email="mike@example.com" role="Member" />
        </div>
      </Section>

      <Section title="Roles & Permissions" description="Define what each role can do.">
        <table className="w-full text-sm">
          <thead><tr className="text-left text-slate-500"><th className="pb-2">Permission</th><th className="pb-2 text-center">Owner</th><th className="pb-2 text-center">Admin</th><th className="pb-2 text-center">Member</th></tr></thead>
          <tbody className="divide-y divide-slate-200">
            <RoleRow perm="View scans" owner admin member />
            <RoleRow perm="Start scans" owner admin member />
            <RoleRow perm="Manage assets" owner admin />
            <RoleRow perm="Configure integrations" owner admin />
            <RoleRow perm="Invite members" owner />
            <RoleRow perm="Billing access" owner />
          </tbody>
        </table>
      </Section>
    </div>
  )
}

function APITab() {
  return (
    <div className="space-y-6 max-w-xl">
      <Section title="API Keys" description="Manage your API access tokens.">
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm text-slate-500">API keys allow programmatic access to your workspace.</p>
          <button className="btn-primary px-4 py-2 text-sm"><Plus size={14} /> Generate Key</button>
        </div>
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <div className="flex items-center justify-between mb-2">
            <code className="font-mono text-sm bg-slate-100 px-2 py-1 rounded">sk_live_••••••••••••••••</code>
            <span className="text-xs text-green-700 bg-green-100 px-2 py-0.5 rounded">Active</span>
          </div>
          <p className="text-xs text-slate-500">Created Jan 10, 2024 • Last used 2 hours ago • Read + Write</p>
        </div>
        <p className="text-sm text-slate-500 mt-4">Keep your API keys secure. They provide full access to your workspace data.</p>
      </Section>
    </div>
  )
}

function MFATab() {
  const [totpEnabled, setTotpEnabled] = useState(false)
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([])
  const [setupSecret, setSetupSecret] = useState<string>('')
  const [setupQrCode, setSetupQrCode] = useState<string>('')
  const [setupStep, setSetupStep] = useState<'idle' | 'verify'>('idle')
  const [verifyToken, setVerifyToken] = useState('')

  const getAuthHeaders = () => {
    const token = localStorage.getItem('auth_token')
    return {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
    }
  }

  const handleSetupTotp = async () => {
    try {
      const res = await fetch('/api/mfa/totp/setup', {
        method: 'POST',
        headers: getAuthHeaders(),
      })
      if (res.ok) {
        const data = await res.json()
        setSetupSecret(data.secret)
        setSetupQrCode(data.qr_code)
        setSetupStep('verify')
      }
    } catch (e) {
      console.error('Failed to setup TOTP:', e)
    }
  }

  const handleEnableTotp = async () => {
    try {
      const res = await fetch('/api/mfa/totp/enable', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ token: verifyToken }),
      })
      if (res.ok) {
        setTotpEnabled(true)
        setSetupStep('idle')
        setVerifyToken('')
      } else {
        alert('Invalid token')
      }
    } catch (e) {
      console.error('Failed to enable TOTP:', e)
    }
  }

  const handleDisableTotp = async () => {
    if (!confirm('Disable two-factor authentication?')) return
    try {
      const res = await fetch('/api/mfa/totp/disable', {
        method: 'POST',
        headers: getAuthHeaders(),
      })
      if (res.ok) {
        setTotpEnabled(false)
        setRecoveryCodes([])
      }
    } catch (e) {
      console.error('Failed to disable TOTP:', e)
    }
  }

  const handleGenerateRecoveryCodes = async () => {
    try {
      const res = await fetch('/api/mfa/recovery-codes', {
        method: 'POST',
        headers: getAuthHeaders(),
      })
      if (res.ok) {
        const data = await res.json()
        setRecoveryCodes(data.codes)
      }
    } catch (e) {
      console.error('Failed to generate recovery codes:', e)
    }
  }

  if (totpEnabled) {
    return (
      <div className="space-y-6 max-w-xl">
        <Section title="Two-Factor Authentication (TOTP)" description="Add an extra layer of security using an authenticator app (Google Authenticator, Authy, 1Password, etc.).">
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-green-50 border border-green-200 rounded-lg">
              <div>
                <p className="font-medium text-green-900">2FA Enabled</p>
                <p className="text-sm text-green-700">Authenticator app</p>
              </div>
              <button onClick={handleDisableTotp} className="btn-danger px-4 py-2 text-sm">Disable 2FA</button>
            </div>
            
            <div className="flex gap-3">
              <button onClick={handleGenerateRecoveryCodes} className="btn-secondary px-4 py-2" disabled={recoveryCodes.length > 0}>
                {recoveryCodes.length > 0 ? 'Recovery Codes Generated' : 'Generate Recovery Codes'}
              </button>
              {recoveryCodes.length > 0 && (
                <button onClick={() => navigator.clipboard.writeText(recoveryCodes.join('\n'))} className="btn-secondary px-4 py-2">
                  Copy Codes
                </button>
              )}
            </div>

            {recoveryCodes.length > 0 && (
              <div className="bg-amber-50 border border-amber-200 rounded-lg p-4">
                <p className="font-medium text-amber-900 mb-2">Recovery Codes (save these securely!)</p>
                <div className="grid grid-cols-2 gap-2 text-sm font-mono bg-white p-3 rounded border">
                  {recoveryCodes.map((code, i) => (
                    <span key={i} className="px-2 py-1 bg-slate-50 rounded">{code}</span>
                  ))}
                </div>
                <p className="text-xs text-amber-700 mt-2">Each code can be used once. Store them securely.</p>
              </div>
            )}
          </div>
        </Section>

        <Section title="Single Sign-On (SSO)" description="Configure SAML or OIDC single sign-on for your team.">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
              <h5 className="font-semibold text-slate-900 mb-2 flex items-center gap-2"><Shield size={20} className="text-blue-500" /> SAML 2.0</h5>
              <p className="text-sm text-slate-500 mb-4">Configure SAML-based single sign-on for enterprise identity providers (Okta, Azure AD, etc.).</p>
              <button className="btn-secondary px-4 py-2 text-sm" disabled>Configure SAML (Coming Soon)</button>
              <p className="text-xs text-slate-500 mt-2">Requires Enterprise plan</p>
            </div>
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
              <h5 className="font-semibold text-slate-900 mb-2 flex items-center gap-2"><Monitor size={20} className="text-purple-500" /> OIDC / OpenID Connect</h5>
              <p className="text-sm text-slate-500 mb-4">Configure OpenID Connect for modern identity providers (Google, GitHub, Auth0, etc.).</p>
              <button className="btn-secondary px-4 py-2 text-sm" disabled>Configure OIDC (Coming Soon)</button>
              <p className="text-xs text-slate-500 mt-2">Requires Enterprise plan</p>
            </div>
          </div>
        </Section>
      </div>
    )
  }

  if (setupStep === 'idle') {
    return (
      <div className="space-y-6 max-w-xl">
        <Section title="Two-Factor Authentication (TOTP)" description="Add an extra layer of security using an authenticator app (Google Authenticator, Authy, 1Password, etc.).">
          <div className="text-center py-8">
            <Shield size={48} className="mx-auto text-slate-400 mb-4" />
            <h4 className="font-semibold text-slate-900 mb-2">Enable Two-Factor Authentication</h4>
            <p className="text-slate-500 mb-6 max-w-md mx-auto">Add an extra layer of security by requiring a time-based code from your authenticator app.</p>
            <button onClick={handleSetupTotp} className="btn-primary px-6 py-2">
              <Shield size={16} className="mr-2" /> Set Up 2FA
            </button>
          </div>
        </Section>

        <Section title="Single Sign-On (SSO)" description="Configure SAML or OIDC single sign-on for your team.">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
              <h5 className="font-semibold text-slate-900 mb-2 flex items-center gap-2"><Shield size={20} className="text-blue-500" /> SAML 2.0</h5>
              <p className="text-sm text-slate-500 mb-4">Configure SAML-based single sign-on for enterprise identity providers (Okta, Azure AD, etc.).</p>
              <button className="btn-secondary px-4 py-2 text-sm" disabled>Configure SAML (Coming Soon)</button>
              <p className="text-xs text-slate-500 mt-2">Requires Enterprise plan</p>
            </div>
            <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
              <h5 className="font-semibold text-slate-900 mb-2 flex items-center gap-2"><Monitor size={20} className="text-purple-500" /> OIDC / OpenID Connect</h5>
              <p className="text-sm text-slate-500 mb-4">Configure OpenID Connect for modern identity providers (Google, GitHub, Auth0, etc.).</p>
              <button className="btn-secondary px-4 py-2 text-sm" disabled>Configure OIDC (Coming Soon)</button>
              <p className="text-xs text-slate-500 mt-2">Requires Enterprise plan</p>
            </div>
          </div>
        </Section>
      </div>
    )
  }

  return (
    <div className="space-y-6 max-w-xl">
      <Section title="Two-Factor Authentication (TOTP)" description="Add an extra layer of security using an authenticator app (Google Authenticator, Authy, 1Password, etc.).">
        <div className="space-y-4">
          <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
            <p className="font-medium text-blue-900 mb-2">Scan QR Code</p>
            <div className="flex justify-center mb-4">
              <img src={setupQrCode} alt="QR Code" className="w-48 h-48 bg-white p-2 rounded" />
            </div>
            <p className="text-sm text-blue-700 text-center">Or enter manually: <code className="font-mono text-base bg-blue-100 px-2 py-1 rounded">{setupSecret}</code></p>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Enter 6-digit code from authenticator app</label>
            <input type="text" value={verifyToken} onChange={e => setVerifyToken(e.target.value)} maxLength={6} className="w-full px-3 py-2 border border-slate-300 rounded-lg text-center text-2xl tracking-widest" placeholder="000000" />
          </div>
          <div className="flex gap-3">
            <button onClick={() => setSetupStep('idle')} className="btn-secondary px-4 py-2">Cancel</button>
            <button onClick={handleEnableTotp} className="btn-primary px-6 py-2" disabled={verifyToken.length !== 6}>Verify & Enable</button>
          </div>
        </div>
      </Section>

      <Section title="Single Sign-On (SSO)" description="Configure SAML or OIDC single sign-on for your team.">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
            <h5 className="font-semibold text-slate-900 mb-2 flex items-center gap-2"><Shield size={20} className="text-blue-500" /> SAML 2.0</h5>
            <p className="text-sm text-slate-500 mb-4">Configure SAML-based single sign-on for enterprise identity providers (Okta, Azure AD, etc.).</p>
            <button className="btn-secondary px-4 py-2 text-sm" disabled>Configure SAML (Coming Soon)</button>
            <p className="text-xs text-slate-500 mt-2">Requires Enterprise plan</p>
          </div>
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-5">
            <h5 className="font-semibold text-slate-900 mb-2 flex items-center gap-2"><Monitor size={20} className="text-purple-500" /> OIDC / OpenID Connect</h5>
            <p className="text-sm text-slate-500 mb-4">Configure OpenID Connect for modern identity providers (Google, GitHub, Auth0, etc.).</p>
            <button className="btn-secondary px-4 py-2 text-sm" disabled>Configure OIDC (Coming Soon)</button>
            <p className="text-xs text-slate-500 mt-2">Requires Enterprise plan</p>
          </div>
        </div>
      </Section>
    </div>
  )
}

function AuthenticatedScansTab() {
  const [authConfigs, setAuthConfigs] = useState<Array<{id: string; name: string; auth_type: string; target: string; last_used?: string}>>([])
  const [_loading, _setLoading] = useState(false)

  const loadConfigs = async () => {
    try {
      const token = localStorage.getItem('auth_token')
      const res = await fetch('/api/auth/configs', {
        headers: { ...(token && { Authorization: `Bearer ${token}` }) },
      })
      if (res.ok) {
        const data = await res.json()
        setAuthConfigs(data)
      }
    } catch (e) {
      console.error('Failed to load auth configs:', e)
    }
  }

  useEffect(() => { loadConfigs() }, [])


  const handleNew = () => {
    alert('Add configuration - modal not implemented yet')
  }

  const handleEdit = (_config: any) => {
    alert('Edit configuration - modal not implemented yet')
  }

  const handleDelete = async (_id: string) => {
    if (!confirm('Delete this authentication configuration?')) return
    alert('Delete configuration - not implemented yet')
  }


  
  return (
    <div className="space-y-6 max-w-3xl">
      <Section title="Authentication Configurations" description="Save authentication profiles for behind-login scanning. Supports form-based, SSO, cookie, and header authentication.">
        <div className="flex items-center justify-between mb-4">
          <p className="text-sm text-slate-500">{authConfigs.length} configuration(s) saved</p>
          <button onClick={handleNew} className="btn-primary px-4 py-2 text-sm"><Plus size={14} /> Add Configuration</button>
        </div>

        {authConfigs.length === 0 ? (
          <div className="text-center py-12 bg-slate-50 rounded-xl">
            <Monitor size={48} className="mx-auto text-slate-400 mb-4" />
            <h4 className="font-semibold text-slate-900 mb-2">No Authentication Configurations</h4>
            <p className="text-slate-500 mb-6 max-w-md mx-auto">Create an authentication profile to scan behind-login applications.</p>
            <button onClick={handleNew} className="btn-primary px-6 py-2"><Plus size={14} className="mr-2" /> Create First Configuration</button>
          </div>
        ) : (
          <div className="space-y-3">
            {authConfigs.map(config => (
              <div key={config.id} className="bg-white border border-slate-200 rounded-lg p-4 flex items-center justify-between">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-blue-100 flex items-center justify-center">
                    <Monitor size={20} className="text-blue-600" />
                  </div>
                  <div>
                    <p className="font-medium text-slate-900">{config.name}</p>
                    <p className="text-sm text-slate-500 flex items-center gap-2">
                      <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs font-medium capitalize">{config.auth_type}</span>
                      <span className="text-slate-400">→</span>
                      <span className="font-mono text-sm">{config.target}</span>
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-500">Last used: {config.last_used || 'Never'}</span>
                  <button onClick={() => handleEdit(config)} className="btn-secondary px-3 py-1.5 text-sm">Edit</button>
                  <button onClick={() => handleDelete(config.id)} className="btn-danger px-3 py-1.5 text-sm">Delete</button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Section>

      <Section title="Launch Authenticated Scan" description="Run a scan using a saved authentication configuration.">
        <form className="space-y-4 max-w-xl">
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Authentication Configuration</label>
            <select className="w-full px-3 py-2 border border-slate-300 rounded-lg" required>
              <option value="">Select configuration...</option>
              {authConfigs.map(c => <option key={c.id} value={c.id}>{c.name} ({c.auth_type})</option>)}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-700 mb-1">Target URL</label>
            <input type="url" placeholder="https://app.example.com/dashboard" className="w-full px-3 py-2 border border-slate-300 rounded-lg" required />
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Scan Type</label>
              <select className="w-full px-3 py-2 border border-slate-300 rounded-lg">
                <option value="website">Website Scan</option>
                <option value="api">API Scan</option>
                <option value="full">Full Scan</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1">Intensity</label>
              <select className="w-full px-3 py-2 border border-slate-300 rounded-lg">
                <option value="light">Light</option>
                <option value="normal">Normal</option>
                <option value="aggressive">Aggressive</option>
              </select>
            </div>
          </div>
          <div className="flex justify-end">
            <button type="submit" className="btn-primary px-6 py-2 flex items-center gap-2"><Monitor size={18} /> Launch Authenticated Scan</button>
          </div>
        </form>
      </Section>
    </div>
  )
}

export function Section({ title, description, children }: { title: string; description: string; children: React.ReactNode }) {
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5">
      <h4 className="font-semibold text-slate-900 mb-1">{title}</h4>
      <p className="text-sm text-slate-500 mb-6">{description}</p>
      {children}
    </div>
  )
}

function NotificationToggle({ label, description, enabled }: { label: string; description: string; enabled: boolean }) {
  const [on, setOn] = useState(enabled)
  return (
    <label className="flex items-center justify-between py-3 border-b border-slate-100 last:border-0 cursor-pointer">
      <div>
        <p className="font-medium text-slate-900">{label}</p>
        <p className="text-sm text-slate-500">{description}</p>
      </div>
      <input type="checkbox" checked={on} onChange={e => setOn(e.target.checked)} className="w-5 h-5 rounded border-slate-300 text-blue-600 focus:ring-blue-500" />
    </label>
  )
}

function ThemeOption({ name, icon: Icon, selected }: { name: string; icon: LucideIcon; selected: boolean }) {
  return (
    <button className={`p-4 border-2 rounded-xl text-center transition-all ${selected ? 'border-blue-500 bg-blue-50' : 'border-slate-200 hover:border-blue-300'}`}>
      <Icon size={24} className="mx-auto mb-2 text-slate-600" />
      <p className="font-medium text-slate-900">{name}</p>
    </button>
  )
}

function DensityOption({ name, selected }: { name: string; selected: boolean }) {
  return (
    <button className={`p-4 border-2 rounded-xl text-center transition-all ${selected ? 'border-blue-500 bg-blue-50' : 'border-slate-200 hover:border-blue-300'}`}>
      <p className="font-medium text-slate-900">{name}</p>
    </button>
  )
}

export function PlanCard({ name, price, features, popular, onClick }: { name: string; price: string; features: string[]; popular?: boolean; onClick?: () => void }) {
  return (
    <div className={`bg-white border-2 rounded-xl p-6 relative ${popular ? 'border-blue-500' : 'border-slate-200'} cursor-pointer hover:shadow-lg transition-shadow`} onClick={onClick}>
      {popular && <div className="absolute -top-3 left-1/2 -translate-x-1/2 px-3 py-1 bg-blue-500 text-white text-xs font-medium rounded-full">Most Popular</div>}
      <h4 className="font-bold text-slate-900 text-lg">{name}</h4>
      <p className="text-3xl font-bold text-slate-900 mt-2">{price}</p>
      <ul className="mt-4 space-y-2">
        {features.map(f => (
          <li key={f} className="flex items-center gap-2 text-sm text-slate-600"><CheckCircle size={14} className="text-green-500" /> {f}</li>
        ))}
      </ul>
      <button className={`btn-primary w-full mt-6 px-4 py-2`}>{popular ? 'Get Started' : 'Upgrade'}</button>
    </div>
  )
}

export function LimitCard({ label, used, limit }: { label: string; used: number | string; limit: number | string }) {
  const percentage = typeof used === 'number' && typeof limit === 'number' && limit > 0 ? Math.min((used / limit) * 100, 100) : 0
  return (
    <div className="bg-white border border-slate-200 rounded-xl p-5">
      <div className="flex items-center justify-between mb-2">
        <span className="font-medium text-slate-900">{label}</span>
        <span className="text-sm text-slate-500 font-mono">{used} / {limit}</span>
      </div>
      <div className="h-2 bg-slate-200 rounded-full overflow-hidden">
        <div className="h-full bg-blue-500 rounded-full transition-all" style={{ width: `${percentage}%` }} />
      </div>
    </div>
  )
}

function SessionRow({ session, onRevoke }: { session: { id: string; ip_address: string | null; user_agent: string | null; created_at: string | null; expires_at: string | null; is_current: boolean }; onRevoke: (id: string) => void }) {
  const parseUA = (ua: string | null) => {
    if (!ua) return 'Unknown device'
    if (ua.includes('Chrome')) return 'Chrome'
    if (ua.includes('Firefox')) return 'Firefox'
    if (ua.includes('Safari')) return 'Safari'
    if (ua.includes('Edge')) return 'Edge'
    return 'Unknown browser'
  }
  const parseOS = (ua: string | null) => {
    if (!ua) return 'Unknown OS'
    if (ua.includes('Windows')) return 'Windows'
    if (ua.includes('Mac')) return 'macOS'
    if (ua.includes('Linux')) return 'Linux'
    if (ua.includes('Android')) return 'Android'
    if (ua.includes('iOS')) return 'iOS'
    return 'Unknown OS'
  }
  const browser = parseUA(session.user_agent)
  const os = parseOS(session.user_agent)
  const created = session.created_at ? new Date(session.created_at).toLocaleString() : 'Unknown'
  return (
    <div className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-full bg-slate-200 flex items-center justify-center text-slate-600 text-sm font-medium">{browser[0]}</div>
        <div>
          <p className="font-medium text-slate-900">{browser} on {os}</p>
          <p className="text-sm text-slate-500">
            {session.is_current ? 'Current session • ' : ''}
            Started {created}
            {session.ip_address && ` • ${session.ip_address}`}
          </p>
        </div>
      </div>
      {!session.is_current && (
        <button onClick={() => onRevoke(session.id)} className="btn-secondary text-sm px-3 py-1">Revoke</button>
      )}
    </div>
  )
}

function TeamRow({ name, email, role, current }: { name: string; email: string; role: string; current?: boolean }) {
  return (
    <div className="flex items-center justify-between p-3 bg-slate-50 rounded-lg">
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-full bg-slate-200 flex items-center justify-center text-slate-600 text-sm font-medium">{name[0]}</div>
        <div>
          <p className="font-medium text-slate-900">{name} {current && <span className="ml-2 text-xs text-blue-600 bg-blue-100 px-1.5 py-0.5 rounded">You</span>}</p>
          <p className="text-sm text-slate-500">{email}</p>
        </div>
      </div>
      <span className="px-2 py-1 text-xs font-medium rounded-full bg-slate-100 text-slate-600">{role}</span>
    </div>
  )
}

function RoleRow({ perm, owner, admin, member }: { perm: string; owner?: boolean; admin?: boolean; member?: boolean }) {
  return (
    <tr>
      <td className="py-2 font-medium text-slate-900">{perm}</td>
      <td className="py-2 text-center"><CheckCircle size={16} className={`mx-auto ${owner ? 'text-green-500' : 'text-slate-300'}`} /></td>
      <td className="py-2 text-center"><CheckCircle size={16} className={`mx-auto ${admin ? 'text-green-500' : 'text-slate-300'}`} /></td>
      <td className="py-2 text-center"><CheckCircle size={16} className={`mx-auto ${member ? 'text-green-500' : 'text-slate-300'}`} /></td>
    </tr>
  )
}