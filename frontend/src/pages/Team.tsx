import { useEffect, useState } from 'react'
import { Users, KeyRound, Copy, Trash2, UserPlus, Check, AlertTriangle, ShieldCheck } from 'lucide-react'
import { teamApi, apiKeysApi, type TeamResponse, type ApiKeyRecord, type TeamMember } from '../lib/api'
import { useAppStore } from '../store/useAppStore'

const ROLE_LABELS: Record<string, string> = {
  owner: 'Owner',
  admin: 'Admin',
  member: 'Member',
  viewer: 'Viewer',
}

function copy(text: string) {
  void navigator.clipboard?.writeText(text)
}

export function Team() {
  const { loadWorkspaces, workspaces, workspaceId } = useAppStore()
  const [data, setData] = useState<TeamResponse | null>(null)
  const [keys, setKeys] = useState<ApiKeyRecord[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [tab, setTab] = useState<'members' | 'keys'>('members')

  const [inviteEmail, setInviteEmail] = useState('')
  const [inviteRole, setInviteRole] = useState('member')
  const [inviteLink, setInviteLink] = useState<string | null>(null)

  const [keyName, setKeyName] = useState('')
  const [newKey, setNewKey] = useState<string | null>(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const [team, apiKeyList] = await Promise.all([teamApi.members(), apiKeysApi.list()])
      setData(team)
      setKeys(apiKeyList)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load team')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    void load()
  }, [workspaceId])

  useEffect(() => {
    void loadWorkspaces()
  }, [loadWorkspaces])

  const myRole = data?.members.find((m) => m.is_current_user)?.role
  const canManage = myRole === 'owner' || myRole === 'admin'

  const submitInvite = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setNotice(null)
    setInviteLink(null)
    try {
      const invite = await teamApi.invite({ email: inviteEmail.trim(), role: inviteRole })
      const link = `${window.location.origin}/join?token=${encodeURIComponent(invite.token)}`
      setInviteLink(link)
      setInviteEmail('')
      setNotice(`Invite created for ${invite.email}`)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create invite')
    }
  }

  const changeRole = async (member: TeamMember, role: string) => {
    setError(null)
    try {
      await teamApi.updateRole(member.id, role)
      await load()
      setNotice(`Updated ${member.email} to ${ROLE_LABELS[role] || role}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not update role')
    }
  }

  const removeMember = async (member: TeamMember) => {
    if (!confirm(`Remove ${member.email} from this workspace?`)) return
    setError(null)
    try {
      await teamApi.removeMember(member.id)
      await load()
      setNotice(`Removed ${member.email}`)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not remove member')
    }
  }

  const cancelInvite = async (id: string) => {
    setError(null)
    try {
      await teamApi.cancelInvite(id)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not cancel invite')
    }
  }

  const createKey = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setNewKey(null)
    try {
      const created = await apiKeysApi.create({ name: keyName.trim() || 'API key' })
      setNewKey(created.key || null)
      setKeyName('')
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not create API key')
    }
  }

  const revokeKey = async (id: string) => {
    if (!confirm('Revoke this API key? Applications using it will stop working.')) return
    setError(null)
    try {
      await apiKeysApi.revoke(id)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Could not revoke key')
    }
  }

  const activeWorkspace = workspaces.find((w) => w.id === workspaceId)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-900">Team</h1>
        <p className="text-slate-500 mt-1">
          Manage members, roles and API keys for {activeWorkspace?.name || data?.workspace.name || 'this workspace'}.
        </p>
      </div>

      {error && <div className="bg-red-50 border border-red-200 text-red-700 rounded-xl p-4 text-sm">{error}</div>}
      {notice && <div className="bg-emerald-50 border border-emerald-200 text-emerald-700 rounded-xl p-4 text-sm">{notice}</div>}

      <div className="flex gap-2 border-b border-slate-200">
        <button
          onClick={() => setTab('members')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === 'members' ? 'border-blue-600 text-blue-700' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
        >
          <Users size={16} /> Members {data ? `(${data.members.length})` : ''}
        </button>
        <button
          onClick={() => setTab('keys')}
          className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 -mb-px ${tab === 'keys' ? 'border-blue-600 text-blue-700' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
        >
          <KeyRound size={16} /> API keys {keys.length ? `(${keys.length})` : ''}
        </button>
      </div>

      {loading && !data ? (
        <div className="text-slate-500 text-sm">Loading team…</div>
      ) : tab === 'members' ? (
        <>
          <div className="grid md:grid-cols-3 gap-4">
            <div className="bg-white rounded-xl border border-slate-200 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Plan</p>
              <p className="mt-1 font-semibold text-slate-900 capitalize">{data?.workspace.plan || '—'}</p>
            </div>
            <div className="bg-white rounded-xl border border-slate-200 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Members</p>
              <p className="mt-1 font-semibold text-slate-900">
                {data?.members.length}{data?.workspace.team_member_limit ? ` / ${data.workspace.team_member_limit}` : ''}
              </p>
            </div>
            <div className="bg-white rounded-xl border border-slate-200 p-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Your role</p>
              <p className="mt-1 font-semibold text-slate-900">{ROLE_LABELS[myRole || ''] || '—'}</p>
            </div>
          </div>

          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Member</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Role</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Joined</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Last login</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {data?.members.map((member) => (
                  <tr key={member.id} className="hover:bg-slate-50">
                    <td className="px-5 py-3">
                      <div className="text-sm font-medium text-slate-900">
                        {member.full_name || member.email}
                        {member.is_current_user && <span className="ml-2 text-xs text-slate-400">(you)</span>}
                      </div>
                      <div className="text-xs text-slate-500">{member.email}</div>
                    </td>
                    <td className="px-5 py-3">
                      {canManage && !member.is_current_user ? (
                        <select
                          value={member.role}
                          onChange={(e) => void changeRole(member, e.target.value)}
                          className="border border-slate-300 rounded-lg px-2 py-1 text-sm bg-white"
                        >
                          {(data?.roles || ['admin', 'member', 'viewer']).map((role) => (
                            <option key={role} value={role}>{ROLE_LABELS[role] || role}</option>
                          ))}
                        </select>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 bg-slate-100 text-slate-700 rounded-full text-xs font-medium">
                          {member.role === 'owner' && <ShieldCheck size={12} />}
                          {ROLE_LABELS[member.role] || member.role}
                        </span>
                      )}
                    </td>
                    <td className="px-5 py-3 text-sm text-slate-600">
                      {member.joined_at ? new Date(member.joined_at).toLocaleDateString() : '—'}
                    </td>
                    <td className="px-5 py-3 text-sm text-slate-600">
                      {member.last_login ? new Date(member.last_login).toLocaleString() : '—'}
                    </td>
                    <td className="px-5 py-3 text-right pr-5">
                      {canManage && !member.is_current_user && member.role !== 'owner' && (
                        <button onClick={() => void removeMember(member)} className="text-slate-400 hover:text-red-600" title="Remove member">
                          <Trash2 size={16} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {canManage && (
            <div className="grid md:grid-cols-2 gap-4">
              <form onSubmit={submitInvite} className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
                <h2 className="font-semibold text-slate-900 flex items-center gap-2"><UserPlus size={18} /> Invite a teammate</h2>
                <input
                  type="email"
                  required
                  placeholder="teammate@company.com"
                  value={inviteEmail}
                  onChange={(e) => setInviteEmail(e.target.value)}
                  className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm"
                />
                <select value={inviteRole} onChange={(e) => setInviteRole(e.target.value)} className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm bg-white">
                  <option value="admin">Admin — manage workspace and team</option>
                  <option value="member">Member — run scans and view findings</option>
                  <option value="viewer">Viewer — read-only access</option>
                </select>
                <button type="submit" className="btn-primary px-4 py-2 rounded-lg text-sm font-medium">Create invite link</button>
                {inviteLink && (
                  <div className="bg-slate-50 border border-slate-200 rounded-lg p-3 space-y-2">
                    <p className="text-xs text-slate-500">Share this one-time link. It expires in 7 days.</p>
                    <div className="flex items-center gap-2">
                      <code className="flex-1 text-xs break-all text-slate-700">{inviteLink}</code>
                      <button type="button" onClick={() => copy(inviteLink)} className="p-1.5 text-slate-500 hover:text-slate-900" title="Copy link">
                        <Copy size={16} />
                      </button>
                    </div>
                  </div>
                )}
              </form>

              <div className="bg-white rounded-xl border border-slate-200 p-5">
                <h2 className="font-semibold text-slate-900 mb-3">Pending invites</h2>
                {!data?.pending_invites.length ? (
                  <p className="text-sm text-slate-500">No pending invites.</p>
                ) : (
                  <ul className="space-y-2">
                    {data.pending_invites.map((invite) => (
                      <li key={invite.id} className="flex items-center justify-between gap-2 text-sm">
                        <div>
                          <p className="text-slate-900">{invite.email}</p>
                          <p className="text-xs text-slate-500">
                            {ROLE_LABELS[invite.role] || invite.role}
                            {invite.expires_at ? ` · expires ${new Date(invite.expires_at).toLocaleDateString()}` : ''}
                          </p>
                        </div>
                        <button onClick={() => void cancelInvite(invite.id)} className="text-slate-400 hover:text-red-600" title="Cancel invite">
                          <Trash2 size={16} />
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </>
      ) : (
        <>
          <div className="bg-white rounded-xl border border-slate-200 p-5">
            <h2 className="font-semibold text-slate-900 mb-1">API keys</h2>
            <p className="text-sm text-slate-500 mb-4">
              Use API keys to run scans from CI/CD. Send them as <code className="bg-slate-100 px-1 rounded">X-API-Key</code> (or
              <code className="bg-slate-100 px-1 ml-1 rounded">Authorization: Bearer</code>).
            </p>
            <form onSubmit={createKey} className="flex flex-wrap gap-2">
              <input
                placeholder="Key name (e.g. GitHub Actions)"
                value={keyName}
                onChange={(e) => setKeyName(e.target.value)}
                className="flex-1 min-w-[240px] border border-slate-300 rounded-lg px-3 py-2 text-sm"
              />
              <button type="submit" className="btn-primary px-4 py-2 rounded-lg text-sm font-medium">Create key</button>
            </form>
            {newKey && (
              <div className="mt-4 bg-amber-50 border border-amber-200 rounded-lg p-3">
                <p className="text-xs text-amber-800 flex items-center gap-1 mb-1">
                  <AlertTriangle size={14} /> Copy this key now — it will not be shown again.
                </p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-xs break-all text-amber-900">{newKey}</code>
                  <button onClick={() => copy(newKey)} className="p-1.5 text-amber-700 hover:text-amber-900" title="Copy key">
                    <Copy size={16} />
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <table className="w-full">
              <thead className="bg-slate-50 border-b border-slate-200">
                <tr>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Name</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Key</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Scopes</th>
                  <th className="px-5 py-3 text-left text-xs font-semibold text-slate-500 uppercase tracking-wider">Last used</th>
                  <th className="px-5 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200">
                {keys.length === 0 ? (
                  <tr><td colSpan={5} className="px-5 py-10 text-center text-sm text-slate-500">No API keys yet.</td></tr>
                ) : (
                  keys.map((key) => (
                    <tr key={key.id} className="hover:bg-slate-50">
                      <td className="px-5 py-3 text-sm font-medium text-slate-900">{key.name}</td>
                      <td className="px-5 py-3 text-sm font-mono text-slate-600">{key.prefix}…</td>
                      <td className="px-5 py-3 text-xs text-slate-600">{key.scopes.join(', ') || '—'}</td>
                      <td className="px-5 py-3 text-sm text-slate-600">{key.last_used ? new Date(key.last_used).toLocaleString() : 'Never'}</td>
                      <td className="px-5 py-3 text-right pr-5">
                        <button onClick={() => void revokeKey(key.id)} className="text-slate-400 hover:text-red-600" title="Revoke key">
                          <Trash2 size={16} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
          <p className="text-xs text-slate-400 flex items-center gap-1">
            <Check size={12} /> Keys inherit your workspace role and can only access workspaces you belong to.
          </p>
        </>
      )}
    </div>
  )
}
