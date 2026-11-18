import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Assets } from './pages/Assets'
import { AttackSurface } from './pages/AttackSurface'
import { Scans } from './pages/Scans'
import { Findings } from './pages/Findings'
import { Reports } from './pages/Reports'
import { Robots } from './pages/Robots'
import { AiPentests } from './pages/AiPentests'
import { Integrations } from './pages/Integrations'
import { Settings } from './pages/Settings'
import { Team } from './pages/Team'
import { Join } from './pages/Join'
import { NewScan } from './pages/NewScan'
import { Login } from './pages/Login'
import { Register } from './pages/Register'
import { useAppStore } from './store/useAppStore'
import { getAuthToken } from './lib/api'
import { AuthProvider, useAuth } from './context/AuthContext'
import { ProtectedRoute } from './components/ProtectedRoute'

function AppRoutes() {
  const bootstrap = useAppStore((s) => s.bootstrap)
  const { loading } = useAuth()

  useEffect(() => {
    if (!loading && getAuthToken()) void bootstrap()
  }, [bootstrap, loading])

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600"></div>
      </div>
    )
  }

  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route path="/register" element={<Register />} />
      <Route element={<ProtectedRoute />}>
        <Route element={<Layout />}>
          <Route index element={<Navigate to="/dashboard" replace />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="assets" element={<Assets />} />
          <Route path="attack-surface" element={<AttackSurface />} />
          <Route path="scans" element={<Scans />} />
          <Route path="scans/new" element={<NewScan />} />
          <Route path="findings" element={<Findings />} />
          <Route path="reports" element={<Reports />} />
          <Route path="ai-pentests" element={<AiPentests />} />
          <Route path="robots" element={<Robots />} />
          <Route path="integrations" element={<Integrations />} />
          <Route path="settings" element={<Settings />} />
          <Route path="team" element={<Team />} />
          <Route path="join" element={<Join />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Routes>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <AppRoutes />
    </AuthProvider>
  )
}