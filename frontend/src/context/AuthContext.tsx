import { createContext, useContext, useState, useEffect, type ReactNode } from 'react'
import { authApi, setAuthToken, getAuthToken, type UserInfo } from '../lib/api'

interface AuthContextType {
  user: UserInfo | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string, fullName?: string) => Promise<void>
  logout: () => Promise<void>
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<UserInfo | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const initAuth = async () => {
      const token = getAuthToken()
      if (token) {
        try {
          const userData = await authApi.me()
          setUser(userData)
        } catch {
          setAuthToken(null)
        }
      }
      setLoading(false)
    }
    initAuth()
  }, [])

  const login = async (email: string, password: string) => {
    const { access_token, user: userData } = await authApi.login({ email, password })
    setAuthToken(access_token)
    setUser(userData)
  }

  const register = async (email: string, password: string, fullName?: string) => {
    const { access_token, user: userData } = await authApi.register({ email, password, full_name: fullName })
    setAuthToken(access_token)
    setUser(userData)
  }

  const logout = async () => {
    await authApi.logout()
    setAuthToken(null)
    setUser(null)
  }

  const refreshUser = async () => {
    const token = getAuthToken()
    if (!token) return
    try {
      const userData = await authApi.me()
      setUser(userData)
    } catch {
      setAuthToken(null)
      setUser(null)
    }
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, refreshUser }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}