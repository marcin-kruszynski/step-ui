'use client'

import { type ReactNode } from 'react'
import { useAuth } from '@/contexts/AuthContext'
import { LoginScreen } from './LoginScreen'

export function AuthGate({ children }: { children: ReactNode }) {
  const { status, refresh } = useAuth()

  if (status === 'loading') {
    return (
      <main
        role="status"
        className="flex min-h-screen items-center justify-center bg-slate-950 text-slate-300"
      >
        <div className="text-center">
          <div className="mb-3 text-sm font-semibold text-sky-400">
            Step UI
          </div>
          <p>Checking administrator session…</p>
        </div>
      </main>
    )
  }

  if (status === 'error') {
    return (
      <main className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
        <div className="w-full max-w-md rounded-xl border border-slate-800 bg-slate-900 p-8 text-center">
          <h1 className="text-xl font-semibold text-white">
            Unable to verify session
          </h1>

          <p className="mt-3 text-sm text-slate-400">
            Step UI could not contact the authentication service.
            Check the connection and try again.
          </p>

          <button
            type="button"
            onClick={() => void refresh()}
            className="mt-6 rounded-lg bg-sky-600 px-6 py-3 font-semibold text-white transition hover:bg-sky-500"
          >
            Retry connection
          </button>
        </div>
      </main>
    )
  }

  if (status === 'unauthenticated') {
    return <LoginScreen />
  }

  if (status !== 'authenticated') {
    return null
  }

  return <>{children}</>
}
