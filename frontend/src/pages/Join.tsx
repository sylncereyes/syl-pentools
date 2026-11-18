import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { UserPlus, CheckCircle2 } from 'lucide-react'
import { teamApi } from '../lib/api'
import { useAppStore } from '../store/useAppStore'

export function Join() {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const bootstrap = useAppStore((s) => s.bootstrap)
  const [token, setToken] = useState(params.get('token') || '')
  const [status, setStatus] = useState<'idle' | 'working' | 'done' | 'error'>('idle')
  const [message, setMessage] = useState<string | null>(null)

  useEffect(() => {
    setToken(params.get('token') || '')
  }, [params])

  const accept = async (e: React.FormEvent) => {
    e.preventDefault()
    setStatus('working')
    setMessage(null)
    try {
      const result = await teamApi.acceptInvite(token.trim())
      localStorage.setItem('workspace_id', result.workspace_id)
      await bootstrap()
      setStatus('done')
      setMessage('You have joined the workspace.')
      setTimeout(() => navigate('/dashboard'), 900)
    } catch (err) {
      setStatus('error')
      setMessage(err instanceof Error ? err.message : 'Could not accept invite')
    }
  }

  return (
    <div className="max-w-lg mx-auto mt-10 bg-white rounded-xl border border-slate-200 p-6 space-y-4">
      <h1 className="text-xl font-bold text-slate-900 flex items-center gap-2">
        <UserPlus size={20} /> Accept workspace invite
      </h1>
      {status === 'done' ? (
        <p className="flex items-center gap-2 text-emerald-700 text-sm">
          <CheckCircle2 size={18} /> {message} Redirecting…
        </p>
      ) : (
        <form onSubmit={accept} className="space-y-3">
          <p className="text-sm text-slate-500">
            Paste the invite token from your invite link or email to join this workspace.
          </p>
          <input
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="Invite token"
            required
            className="w-full border border-slate-300 rounded-lg px-3 py-2 text-sm font-mono"
          />
          {message && <p className="text-sm text-red-600">{message}</p>}
          <button
            type="submit"
            disabled={status === 'working' || !token.trim()}
            className="btn-primary px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50"
          >
            {status === 'working' ? 'Joining…' : 'Join workspace'}
          </button>
        </form>
      )}
    </div>
  )
}
