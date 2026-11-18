import { createContext, useContext, useEffect, useRef, useState, ReactNode } from 'react'
import { io, Socket } from 'socket.io-client'
import { useAppStore } from '../store/useAppStore'
import { mapAsset, mapFinding } from '../lib/api'

interface RealtimeEvent {
  event_type: string
  workspace_id: string
  data: any
  timestamp: string
  user_id?: string
}

interface ScanProgressData {
  scan_id: string
  progress: number
  step: string
  metadata?: any
}

interface FindingData {
  id: string
  title: string
  severity: string
  status: string
  target_url?: string
  asset_id?: string
}

interface ScanEventData {
  scan_id: string
  type?: string
  target?: string
  status?: string
  progress?: number
  step?: string
  findings_count?: number
  critical_count?: number
  high_count?: number
  medium_count?: number
  low_count?: number
  error?: string
  metadata?: any
  log?: {
    level: string
    message: string
    step: string
  }
  report_id?: string
}

interface SocketContextType {
  socket: Socket | null
  isConnected: boolean
  connectionError: string | null
  subscribeToScan: (scanId: string) => void
  unsubscribeFromScan: (scanId: string) => void
  subscribeToAsset: (assetId: string) => void
  unsubscribeFromAsset: (assetId: string) => void
  onScanProgress: (callback: (data: ScanProgressData) => void) => () => void
  onScanEvent: (callback: (data: ScanEventData) => void) => () => void
  onFindingCreated: (callback: (data: FindingData) => void) => () => void
  onFindingUpdated: (callback: (data: FindingData) => void) => () => void
  onAssetCreated: (callback: (data: any) => void) => () => void
  onAssetUpdated: (callback: (data: any) => void) => () => void
  onNotification: (callback: (data: any) => void) => () => void
}

const SocketContext = createContext<SocketContextType | null>(null)

const SOCKET_URL = (import.meta as any).env?.VITE_SOCKET_URL || 'http://localhost:8000'

export function SocketProvider({ children }: { children: ReactNode }) {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const [connectionError, setConnectionError] = useState<string | null>(null)
  
  // Event handlers storage using refs to avoid re-renders
  const scanProgressHandlers = useRef<Set<(data: ScanProgressData) => void>>(new Set())
  const scanEventHandlers = useRef<Set<(data: ScanEventData) => void>>(new Set())
  const findingCreatedHandlers = useRef<Set<(data: FindingData) => void>>(new Set())
  const findingUpdatedHandlers = useRef<Set<(data: FindingData) => void>>(new Set())
  const assetCreatedHandlers = useRef<Set<(data: any) => void>>(new Set())
  const assetUpdatedHandlers = useRef<Set<(data: any) => void>>(new Set())
  const notificationHandlers = useRef<Set<(data: any) => void>>(new Set())

  useEffect(() => {
    // Get auth token from localStorage
    const token = localStorage.getItem('auth_token') || ''
    const workspaceId = localStorage.getItem('workspace_id') || ''
    const userId = localStorage.getItem('user_id') || ''

    const newSocket = io(SOCKET_URL, {
      auth: { token, workspace_id: workspaceId, user_id: userId },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      timeout: 10000,
    })

    newSocket.on('connect', () => {
      console.log('Socket connected:', newSocket.id)
      setIsConnected(true)
      setConnectionError(null)
    })

    newSocket.on('disconnect', (reason) => {
      console.log('Socket disconnected:', reason)
      setIsConnected(false)
    })

    newSocket.on('connect_error', (error) => {
      console.error('Socket connection error:', error)
      setConnectionError(error.message)
      setIsConnected(false)
    })

    newSocket.on('connected', (data) => {
      console.log('Socket authenticated:', data)
      if (data?.workspace_id && typeof localStorage !== 'undefined') {
        localStorage.setItem('workspace_id', data.workspace_id)
      }
    })

    // Keep the global store in sync with server broadcasts.
    newSocket.on('scan_started', (event: RealtimeEvent) => {
      const store = useAppStore.getState()
      store.updateScan(event.data.scan_id, { status: 'pending', progress: event.data.progress ?? 0 })
    })

    newSocket.on('scan_progress', (event: RealtimeEvent) => {
      const store = useAppStore.getState()
      store.updateScan(event.data.scan_id, {
        status: 'running',
        progress: event.data.progress ?? 0,
        findings: event.data.findings_count,
      })
    })

    newSocket.on('scan_completed', (event: RealtimeEvent) => {
      const store = useAppStore.getState()
      store.updateScan(event.data.scan_id, {
        status: 'completed',
        progress: 100,
        findings: event.data.findings_count,
      })
    })

    newSocket.on('scan_failed', (event: RealtimeEvent) => {
      const store = useAppStore.getState()
      store.updateScan(event.data.scan_id, { status: 'failed' })
      void store.bootstrap()
    })

    newSocket.on('finding_created', (event: RealtimeEvent) => {
      useAppStore.getState().addFinding(mapFinding(event.data))
    })

    newSocket.on('asset_created', (event: RealtimeEvent) => {
      const store = useAppStore.getState()
      const asset = mapAsset(event.data)
      store.setAssets([asset, ...store.assets.filter((a) => a.id !== asset.id)])
    })

    newSocket.on('asset_updated', (event: RealtimeEvent) => {
      const store = useAppStore.getState()
      const asset = mapAsset(event.data)
      store.setAssets(store.assets.map((a) => (a.id === asset.id ? asset : a)))
    })

    // Scan events
    newSocket.on('scan_started', (event: RealtimeEvent) => {
      scanEventHandlers.current.forEach(handler => handler({
        scan_id: event.data.scan_id,
        type: event.data.type,
        target: event.data.target,
        status: 'started',
      }))
    })

    newSocket.on('scan_progress', (event: RealtimeEvent) => {
      const data: ScanProgressData = {
        scan_id: event.data.scan_id,
        progress: event.data.progress,
        step: event.data.step,
        metadata: event.data.metadata,
      }
      scanProgressHandlers.current.forEach(handler => handler(data))
      scanEventHandlers.current.forEach(handler => handler({
        scan_id: event.data.scan_id,
        progress: event.data.progress,
        step: event.data.step,
        metadata: event.data.metadata,
      }))
    })

    newSocket.on('scan_completed', (event: RealtimeEvent) => {
      scanEventHandlers.current.forEach(handler => handler({
        scan_id: event.data.scan_id,
        status: 'completed',
        findings_count: event.data.findings_count,
        critical_count: event.data.critical_count,
        high_count: event.data.high_count,
        medium_count: event.data.medium_count,
        low_count: event.data.low_count,
      }))
    })

    newSocket.on('scan_failed', (event: RealtimeEvent) => {
      scanEventHandlers.current.forEach(handler => handler({
        scan_id: event.data.scan_id,
        status: 'failed',
        error: event.data.error,
      }))
    })

    newSocket.on('scan_log', (event: RealtimeEvent) => {
      scanEventHandlers.current.forEach(handler => handler({
        scan_id: event.data.scan_id,
        log: event.data.log,
      }))
    })

    // Finding events
    newSocket.on('finding_created', (event: RealtimeEvent) => {
      const finding: FindingData = {
        id: event.data.id,
        title: event.data.title,
        severity: event.data.severity,
        status: event.data.status,
        target_url: event.data.target_url,
        asset_id: event.data.asset_id,
      }
      findingCreatedHandlers.current.forEach(handler => handler(finding))
    })

    newSocket.on('finding_updated', (event: RealtimeEvent) => {
      const finding: FindingData = {
        id: event.data.finding_id,
        title: event.data.title,
        severity: event.data.severity,
        status: event.data.status,
      }
      findingUpdatedHandlers.current.forEach(handler => handler(finding))
    })

    // Asset events
    newSocket.on('asset_created', (event: RealtimeEvent) => {
      assetCreatedHandlers.current.forEach(handler => handler(event.data))
    })

    newSocket.on('asset_updated', (event: RealtimeEvent) => {
      assetUpdatedHandlers.current.forEach(handler => handler({
        asset_id: event.data.asset_id,
        ...event.data,
      }))
    })

    // Notification events
    newSocket.on('notification', (event: RealtimeEvent) => {
      notificationHandlers.current.forEach(handler => handler(event.data))
    })

    // Scheduled scan triggered
    newSocket.on('scheduled_scan_triggered', (event: RealtimeEvent) => {
      scanEventHandlers.current.forEach(handler => handler({
        scan_id: event.data.scan_id,
        status: 'scheduled_triggered',
        type: event.data.type,
        target: event.data.target,
      }))
    })

    // Report generated
    newSocket.on('report_generated', (event: RealtimeEvent) => {
      scanEventHandlers.current.forEach(handler => handler({
        scan_id: event.data.scan_id || '',
        report_id: event.data.report_id,
        status: 'generated',
      }))
    })

    // Notification
    newSocket.on('notification', (event: RealtimeEvent) => {
      notificationHandlers.current.forEach(handler => handler(event.data))
    })

    setSocket(newSocket)

    return () => {
      newSocket.disconnect()
      setIsConnected(false)
    }
  }, [])

  // Handler registration functions
  const onScanProgress = (callback: (data: ScanProgressData) => void) => {
    scanProgressHandlers.current.add(callback)
    return () => scanProgressHandlers.current.delete(callback)
  }

  const onScanEvent = (callback: (data: ScanEventData) => void) => {
    scanEventHandlers.current.add(callback)
    return () => scanEventHandlers.current.delete(callback)
  }

  const onFindingCreated = (callback: (data: FindingData) => void) => {
    findingCreatedHandlers.current.add(callback)
    return () => findingCreatedHandlers.current.delete(callback)
  }

  const onFindingUpdated = (callback: (data: FindingData) => void) => {
    findingUpdatedHandlers.current.add(callback)
    return () => findingUpdatedHandlers.current.delete(callback)
  }

  const onAssetCreated = (callback: (data: any) => void) => {
    assetCreatedHandlers.current.add(callback)
    return () => assetCreatedHandlers.current.delete(callback)
  }

  const onAssetUpdated = (callback: (data: any) => void) => {
    assetUpdatedHandlers.current.add(callback)
    return () => assetUpdatedHandlers.current.delete(callback)
  }

  const onNotification = (callback: (data: any) => void) => {
    notificationHandlers.current.add(callback)
    return () => notificationHandlers.current.delete(callback)
  }

  const subscribeToScan = (scanId: string) => {
    socket?.emit('subscribe', { scan_id: scanId })
  }

  const unsubscribeFromScan = (scanId: string) => {
    socket?.emit('unsubscribe', { scan_id: scanId })
  }

  const subscribeToAsset = (assetId: string) => {
    socket?.emit('subscribe', { asset_id: assetId })
  }

  const unsubscribeFromAsset = (assetId: string) => {
    socket?.emit('unsubscribe', { asset_id: assetId })
  }

  return (
    <SocketContext.Provider value={{
      socket,
      isConnected,
      connectionError,
      subscribeToScan,
      unsubscribeFromScan,
      subscribeToAsset,
      unsubscribeFromAsset,
      onScanProgress,
      onScanEvent,
      onFindingCreated,
      onFindingUpdated,
      onAssetCreated,
      onAssetUpdated,
      onNotification,
    }}>
      {children}
    </SocketContext.Provider>
  )
}

export function useSocket() {
  const context = useContext(SocketContext)
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider')
  }
  return context
}