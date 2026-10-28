'use client'

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from 'react'
import axios from 'axios'
import { authApi, type AdminUser } from '@/lib/auth'
import api from '@/lib/api'

type AuthStatus =
  | 'loading'
  | 'authenticated'
  | 'unauthenticated'
  | 'error'

interface AuthContextValue {
  status: AuthStatus
  admin: AdminUser | null
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('loading')
  const [admin, setAdmin] = useState<AdminUser | null>(null)

  const refresh = useCallback(async () => {
    setStatus('loading')
    setAdmin(null)

    try {
      const session = await authApi.me()
      setAdmin(session.admin)
      setStatus('authenticated')
    } catch (error) {
      setAdmin(null)

      if (axios.isAxiosError(error) && error.response?.status === 401) {
        setStatus('unauthenticated')
      } else {
        setStatus('error')
      }
    }
  }, [])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => {
    const interceptor = api.interceptors.response.use(
      response => response,
      error => {
        if (
          axios.isAxiosError(error) &&
          error.response?.status === 401 &&
          !error.config?.url?.includes('/api/auth/login') &&
          !error.config?.url?.includes('/api/auth/me')
        ) {
          setAdmin(null)
          setStatus('unauthenticated')
        }

        return Promise.reject(error)
      }
    )

    return () => {
      api.interceptors.response.eject(interceptor)
    }
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    await authApi.login(username, password)

    setStatus('loading')
    setAdmin(null)

    try {
      const session = await authApi.me()

      if (!session.authenticated || !session.admin) {
        throw new Error('Session verification failed')
      }

      setAdmin(session.admin)
      setStatus('authenticated')
    } catch (error) {
      setAdmin(null)

      if (axios.isAxiosError(error) && error.response?.status === 401) {
        setStatus('unauthenticated')
      } else {
        setStatus('error')
      }

      throw error
    }
  }, [])

  const logout = useCallback(async () => {
    await authApi.logout()
    setAdmin(null)
    setStatus('unauthenticated')
  }, [])

  return (
    <AuthContext.Provider
      value={{
        status,
        admin,
        login,
        logout,
        refresh,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)

  if (!context) {
    throw new Error('useAuth must be used inside AuthProvider')
  }

  return context
}
