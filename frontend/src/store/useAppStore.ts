import { create } from 'zustand'
import { api, mapAsset, mapFinding, mapScan, workspaceApi, type WorkspaceSummary } from '../lib/api'

export interface Asset { id: string; target: string; type: 'hostname' | 'ip'; description?: string; riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical'; scans: number; createdAt: string }
export interface Scan { id: string; type: string; target: string; status: 'pending' | 'running' | 'completed' | 'failed'; progress: number; startedAt: string; completedAt?: string; findings?: number }
export interface Finding { id: string; title: string; target: string; riskLevel: 'low' | 'medium' | 'high' | 'critical'; status: 'open' | 'verified' | 'false_positive' | 'fixed'; source: string; scanDate: string }
export interface Integration { id: string; name: string; type: 'slack' | 'teams' | 'jira' | 'webhook' | 'github' | 'discord' | 'aws' | 'vanta'; configured: boolean; enabled: boolean }

export interface CreateScanInput {
  type: string
  target: string
  intensity?: string
  asset_type?: string
  is_authenticated?: boolean
}

interface AppState {
  workspaceId: string | null
  bootstrapped: boolean
  loading: boolean
  error: string | null
  assets: Asset[]
  scans: Scan[]
  findings: Finding[]
  integrations: Integration[]
  workspace: { name: string; assetLimit: number; scanLimit: number }
  workspaces: WorkspaceSummary[]
  bootstrap: () => Promise<void>
  loadWorkspaces: () => Promise<void>
  switchWorkspace: (id: string) => Promise<void>
  addAsset: (asset: Asset) => void
  addScan: (scan: Scan) => void
  updateScan: (id: string, patch: Partial<Scan>) => void
  addFinding: (finding: Finding) => void
  updateFindingStatus: (id: string, status: Finding['status']) => Promise<void>
  removeFinding: (id: string) => void
  setAssets: (assets: Asset[]) => void
  setScans: (scans: Scan[]) => void
  setFindings: (findings: Finding[]) => void
  setIntegrations: (i: Integration[]) => void
  createScan: (input: CreateScanInput) => Promise<Scan>
  createAsset: (input: { target: string; type?: string; description?: string }) => Promise<Asset>
  deleteAsset: (id: string) => Promise<void>
  toggleIntegration: (id: string) => Promise<void>
}

const emptyWorkspace = { name: 'My Workspace', assetLimit: 100, scanLimit: 5 }

export const useAppStore = create<AppState>((set, get) => ({
  workspaceId: typeof localStorage !== 'undefined' ? localStorage.getItem('workspace_id') : null,
  bootstrapped: false,
  loading: false,
  error: null,
  assets: [],
  scans: [],
  findings: [],
  integrations: [],
  workspace: emptyWorkspace,
  workspaces: [],

  loadWorkspaces: async () => {
    try {
      const workspaces = await workspaceApi.list()
      set({ workspaces })
      const current = typeof localStorage !== 'undefined' ? localStorage.getItem('workspace_id') : null
      if (workspaces.length > 0 && !workspaces.some((w) => w.id === current)) {
        const fallback = workspaces[0].id
        if (typeof localStorage !== 'undefined') localStorage.setItem('workspace_id', fallback)
        set({ workspaceId: fallback })
      }
    } catch {
      /* workspaces are optional for the UI shell */
    }
  },

  switchWorkspace: async (id) => {
    if (typeof localStorage !== 'undefined') localStorage.setItem('workspace_id', id)
    set({ workspaceId: id, bootstrapped: false })
    await get().bootstrap()
  },

  bootstrap: async () => {
    set({ loading: true, error: null })
    try {
      const storedWorkspace = typeof localStorage !== 'undefined' ? localStorage.getItem('workspace_id') : null
      const data = await api.bootstrap(storedWorkspace)
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('workspace_id', data.workspace.id)
      }
      set({
        workspaceId: data.workspace.id,
        workspace: {
          name: data.workspace.name,
          assetLimit: data.workspace.asset_limit,
          scanLimit: data.workspace.scan_limit,
        },
        assets: data.assets.map(mapAsset),
        scans: data.scans.map(mapScan),
        findings: data.findings.map(mapFinding),
        integrations: data.integrations,
        bootstrapped: true,
        loading: false,
      })
    } catch (err) {
      set({ loading: false, error: err instanceof Error ? err.message : 'Could not load workspace' })
    }
  },

  addAsset: (a) => set((s) => ({ assets: [a, ...s.assets] })),
  addScan: (sc) => set((s) => ({ scans: [sc, ...s.scans] })),
  updateScan: (id, patch) => set((s) => ({ scans: s.scans.map((sc) => (sc.id === id ? { ...sc, ...patch } : sc)) })),
  addFinding: (f) => set((s) => (s.findings.some((x) => x.id === f.id) ? s : { findings: [f, ...s.findings] })),
  removeFinding: (id) => set((s) => ({ findings: s.findings.filter((f) => f.id !== id) })),
  setAssets: (assets) => set({ assets }),
  setScans: (scans) => set({ scans }),
  setFindings: (findings) => set({ findings }),
  setIntegrations: (i) => set({ integrations: i }),

  updateFindingStatus: async (id, status) => {
    const previous = get().findings
    set({ findings: previous.map((f) => (f.id === id ? { ...f, status } : f)) })
    try {
      await api.updateFinding(id, { status })
      await get().bootstrap()
    } catch (err) {
      set({ findings: previous, error: err instanceof Error ? err.message : 'Could not update finding' })
    }
  },

  createScan: async (input) => {
    set({ error: null })
    try {
      const raw = await api.createScan(input)
      const scan = mapScan(raw)
      set((s) => ({ scans: [scan, ...s.scans.filter((x) => x.id !== scan.id)] }))
      return scan
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not start scan'
      set({ error: message })
      throw err
    }
  },

  createAsset: async (input) => {
    set({ error: null })
    try {
      const raw = await api.createAsset(input)
      const asset = mapAsset(raw)
      set((s) => ({ assets: [asset, ...s.assets.filter((x) => x.id !== asset.id)] }))
      return asset
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Could not create asset'
      set({ error: message })
      throw err
    }
  },

  deleteAsset: async (id) => {
    await api.deleteAsset(id)
    set((s) => ({ assets: s.assets.filter((a) => a.id !== id) }))
  },

  toggleIntegration: async (id) => {
    const previous = get().integrations
    set({ integrations: previous.map((i) => (i.id === id ? { ...i, enabled: !i.enabled, configured: true } : i)) })
    try {
      await api.toggleIntegration(id)
    } catch (err) {
      set({ integrations: previous, error: err instanceof Error ? err.message : 'Could not update integration' })
    }
  },
}))
