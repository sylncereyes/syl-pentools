import { useEffect, useMemo, useState } from 'react'
import { Bot, Play, Trash2, Plus, ChevronDown, ChevronRight, RefreshCw, Clock3, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { robotsApi, type Robot, type RobotRun, type RobotStep, type RobotStepState } from '../lib/api'
import { useAppStore } from '../store/useAppStore'

const TOOLS: { value: string; label: string }[] = [
  { value: 'subdomain', label: 'Subdomain discovery' },
  { value: 'domain_finder', label: 'Domain finder' },
  { value: 'vhost', label: 'Virtual hosts' },
  { value: 'recon', label: 'Reconnaissance' },
  { value: 'port', label: 'Port scan' },
  { value: 'network', label: 'Network scan' },
  { value: 'website', label: 'Website scan' },
  { value: 'cms', label: 'CMS scan' },
  { value: 'api', label: 'API scan' },
  { value: 'cloud', label: 'Cloud scan' },
  { value: 'full', label: 'Full scan' },
  { value: 'http_logger', label: 'HTTP logger' },
]

const INTENSITIES = ['light', 'normal', 'deep']

const STATUS_STYLES: Record<string, string> = {
  completed: 'bg-green-100 text-green-700',
  running: 'bg-blue-100 text-blue-700',
  queued: 'bg-gray-100 text-gray-600',
  failed: 'bg-red-100 text-red-700',
  cancelled: 'bg-amber-100 text-amber-700',
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${STATUS_STYLES[status] || 'bg-gray-100 text-gray-600'}`}>
      {status === 'running' && <Loader2 className="h-3 w-3 animate-spin" />}
      {status}
    </span>
  )
}

function StepTimeline({ steps }: { steps: RobotStepState[] }) {
  return (
    <ol className="space-y-2">
      {steps.map((step) => (
        <li key={step.index} className="flex items-start gap-3 text-sm">
          <span className="mt-0.5 w-5 h-5 rounded-full bg-gray-100 text-gray-600 flex items-center justify-center text-xs font-semibold">
            {step.index + 1}
          </span>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <span className="font-medium text-gray-900">{step.tool}</span>
              <span className="text-xs text-gray-500">{step.intensity}</span>
              <StatusBadge status={step.status} />
              <span className="text-xs text-gray-500">{step.findings} findings</span>
            </div>
            <div className="text-xs text-gray-500 mt-0.5">
              targets: {step.targets.slice(0, 3).join(', ') || '—'}
              {step.targets.length > 3 ? ` +${step.targets.length - 3}` : ''}
            </div>
            {step.discovered.length > 0 && (
              <div className="text-xs text-indigo-600">
                discovered: {step.discovered.slice(0, 4).join(', ')}
                {step.discovered.length > 4 ? ` +${step.discovered.length - 4}` : ''}
              </div>
            )}
            {step.error && <div className="text-xs text-red-600">{step.error}</div>}
          </div>
        </li>
      ))}
    </ol>
  )
}

export function Robots() {
  const { workspaceId } = useAppStore()
  const [robots, setRobots] = useState<Robot[]>([])
  const [runs, setRuns] = useState<RobotRun[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)
  const [targets, setTargets] = useState<Record<string, string>>({})
  const [runningId, setRunningId] = useState<string | null>(null)

  const [formOpen, setFormOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [maxTargets, setMaxTargets] = useState(10)
  const [steps, setSteps] = useState<RobotStep[]>([{ tool: 'subdomain', intensity: 'light' }, { tool: 'website', intensity: 'normal' }])

  const activeRuns = useMemo(() => runs.filter((r) => r.status === 'queued' || r.status === 'running'), [runs])

  const load = async () => {
    setError(null)
    try {
      const [list, allRuns] = await Promise.all([robotsApi.list(), robotsApi.runs()])
      setRobots(list)
      setRuns(allRuns)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load robots')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    setLoading(true)
    void load()
  }, [workspaceId])

  useEffect(() => {
    if (activeRuns.length === 0) return
    const timer = setInterval(() => void load(), 3000)
    return () => clearInterval(timer)
  }, [activeRuns.length])

  const updateStep = (index: number, patch: Partial<RobotStep>) => {
    setSteps((prev) => prev.map((step, i) => (i === index ? { ...step, ...patch } : step)))
  }

  const createRobot = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!name.trim()) {
      setError('Name is required')
      return
    }
    if (steps.length === 0) {
      setError('Add at least one step')
      return
    }
    try {
      await robotsApi.create({ name: name.trim(), description: description.trim() || undefined, steps, max_targets: maxTargets })
      setName('')
      setDescription('')
      setSteps([{ tool: 'subdomain', intensity: 'light' }, { tool: 'website', intensity: 'normal' }])
      setFormOpen(false)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create robot')
    }
  }

  const runRobot = async (robot: Robot) => {
    const target = (targets[robot.id] || '').trim()
    if (!target) {
      setError('Enter a target first')
      return
    }
    setError(null)
    setRunningId(robot.id)
    try {
      await robotsApi.run(robot.id, target)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start robot')
    } finally {
      setRunningId(null)
    }
  }

  const removeRobot = async (robot: Robot) => {
    if (!confirm(`Delete robot "${robot.name}"? Its run history is removed too.`)) return
    try {
      await robotsApi.remove(robot.id)
      await load()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete robot')
    }
  }

  const runsFor = (robotId: string) => runs.filter((run) => run.robot_id === robotId).slice(0, 10)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Bot className="h-6 w-6 text-indigo-600" /> Robots
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Chain scans together: results from a discovery step become the targets of the next one.
          </p>
        </div>
        <button onClick={() => setFormOpen((v) => !v)} className="btn-primary flex items-center gap-2">
          <Plus className="h-4 w-4" /> New robot
        </button>
      </div>

      {error && <div className="rounded-lg bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">{error}</div>}

      {formOpen && (
        <form onSubmit={createRobot} className="card p-5 space-y-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label className="label">Name</label>
              <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Subdomain sweep to website scan" />
            </div>
            <div>
              <label className="label">Max targets per step</label>
              <input type="number" min={1} max={50} className="input" value={maxTargets} onChange={(e) => setMaxTargets(Number(e.target.value) || 1)} />
            </div>
          </div>
          <div>
            <label className="label">Description</label>
            <input className="input" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" />
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="label mb-0">Steps</label>
              <button type="button" className="text-sm text-indigo-600 hover:text-indigo-700 flex items-center gap-1" onClick={() => setSteps((prev) => [...prev, { tool: 'website', intensity: 'normal' }])}>
                <Plus className="h-3.5 w-3.5" /> Add step
              </button>
            </div>
            {steps.map((step, index) => (
              <div key={index} className="flex items-center gap-2">
                <span className="w-6 text-sm text-gray-500">{index + 1}.</span>
                <select className="input flex-1" value={step.tool} onChange={(e) => updateStep(index, { tool: e.target.value })}>
                  {TOOLS.map((tool) => (
                    <option key={tool.value} value={tool.value}>{tool.label}</option>
                  ))}
                </select>
                <select className="input w-32" value={step.intensity || 'normal'} onChange={(e) => updateStep(index, { intensity: e.target.value })}>
                  {INTENSITIES.map((level) => (
                    <option key={level} value={level}>{level}</option>
                  ))}
                </select>
                <button type="button" className="p-2 text-gray-400 hover:text-red-600" onClick={() => setSteps((prev) => prev.filter((_, i) => i !== index))} disabled={steps.length === 1}>
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
          </div>
          <div className="flex justify-end gap-2">
            <button type="button" className="btn-secondary" onClick={() => setFormOpen(false)}>Cancel</button>
            <button type="submit" className="btn-primary">Create robot</button>
          </div>
        </form>
      )}

      {loading ? (
        <div className="text-sm text-gray-500">Loading robots…</div>
      ) : robots.length === 0 ? (
        <div className="card p-10 text-center">
          <Bot className="h-10 w-10 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-700 font-medium">No robots yet</p>
          <p className="text-sm text-gray-500 mt-1">Create one to chain discovery and scanning automatically.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {robots.map((robot) => {
            const history = runsFor(robot.id)
            const last = robot.last_run || history[0]
            const isOpen = expanded === robot.id
            return (
              <div key={robot.id} className="card">
                <div className="p-5 flex flex-wrap items-start gap-4">
                  <div className="flex-1 min-w-[240px]">
                    <div className="flex items-center gap-2">
                      <h2 className="font-semibold text-gray-900">{robot.name}</h2>
                      {last && <StatusBadge status={last.status} />}
                      {!robot.is_active && <span className="text-xs text-gray-500">disabled</span>}
                    </div>
                    {robot.description && <p className="text-sm text-gray-500 mt-0.5">{robot.description}</p>}
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {robot.steps.map((step, i) => (
                        <span key={i} className="inline-flex items-center gap-1 text-xs bg-gray-100 text-gray-700 px-2 py-0.5 rounded">
                          <span className="font-semibold">{i + 1}</span> {step.tool}
                          <span className="text-gray-400">{step.intensity || 'normal'}</span>
                        </span>
                      ))}
                    </div>
                    {last && (
                      <div className="text-xs text-gray-500 mt-2 flex items-center gap-1">
                        <Clock3 className="h-3 w-3" />
                        last run {last.created_at ? new Date(last.created_at).toLocaleString() : '—'} · step {last.current_step}/{last.total_steps} · {last.scan_ids.length} scans
                      </div>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <input
                      className="input w-56"
                      placeholder="target, e.g. example.com"
                      value={targets[robot.id] || ''}
                      onChange={(e) => setTargets((prev) => ({ ...prev, [robot.id]: e.target.value }))}
                      onKeyDown={(e) => { if (e.key === 'Enter') void runRobot(robot) }}
                    />
                    <button
                      className="btn-primary flex items-center gap-1.5"
                      onClick={() => void runRobot(robot)}
                      disabled={runningId === robot.id || !robot.is_active}
                    >
                      {runningId === robot.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                      Run
                    </button>
                    <button className="p-2 text-gray-400 hover:text-red-600" onClick={() => void removeRobot(robot)} title="Delete robot">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                </div>

                <div className="px-5 pb-3">
                  <button className="text-sm text-indigo-600 hover:text-indigo-700 flex items-center gap-1" onClick={() => setExpanded(isOpen ? null : robot.id)}>
                    {isOpen ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                    Run history ({history.length})
                    <RefreshCw className="h-3.5 w-3.5 ml-1" onClick={(e) => { e.stopPropagation(); void load() }} />
                  </button>
                </div>

                {isOpen && (
                  <div className="border-t border-gray-100 px-5 py-4 space-y-4">
                    {history.length === 0 && <p className="text-sm text-gray-500">No runs yet.</p>}
                    {history.map((run) => (
                      <div key={run.id} className="rounded-lg border border-gray-100 p-3">
                        <div className="flex flex-wrap items-center gap-2 text-sm">
                          <StatusBadge status={run.status} />
                          <span className="font-medium text-gray-900">{run.target}</span>
                          <span className="text-xs text-gray-500">{run.created_at ? new Date(run.created_at).toLocaleString() : ''}</span>
                          {run.error_message && <span className="text-xs text-red-600 flex items-center gap-1"><XCircle className="h-3.5 w-3.5" />{run.error_message}</span>}
                          {run.status === 'completed' && <CheckCircle2 className="h-4 w-4 text-green-600" />}
                        </div>
                        <div className="mt-3">
                          <StepTimeline steps={run.steps_state || []} />
                        </div>
                        {run.scan_ids.length > 0 && (
                          <div className="mt-2 text-xs text-gray-500">
                            scans: {run.scan_ids.map((id) => id.slice(0, 8)).join(', ')}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
