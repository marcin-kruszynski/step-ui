'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Shield, FileText, List, Settings, Home, Archive, LogOut } from 'lucide-react'
import { cn } from '@/lib/utils'
import { useAuth } from '@/contexts/AuthContext'
import { useState } from 'react'

const navigation = [
  { name: 'Dashboard', href: '/', icon: Home },
  { name: 'Issue Certificate', href: '/issue', icon: Shield },
  { name: 'Sign CSR', href: '/sign-csr', icon: FileText },
  { name: 'Inventory', href: '/inventory', icon: List },
  // 2026-10-24: Dedicated certificate archive.
  { name: 'Archive', href: '/archive', icon: Archive },
  { name: 'Settings', href: '/settings', icon: Settings },
]

export default function Navigation() {
  const pathname = usePathname()
  const { admin, logout } = useAuth()
  const [signingOut, setSigningOut] = useState(false)
  const [logoutError, setLogoutError] = useState(false)

  const handleLogout = async () => {
    if (signingOut) return

    setSigningOut(true)
    setLogoutError(false)

    try {
      await logout()
    } catch {
      setLogoutError(true)
    } finally {
      setSigningOut(false)
    }
  }

  return (
    <nav className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between h-16">
          <div className="flex">
            <div className="flex-shrink-0 flex items-center">
              <Shield className="h-8 w-8 text-blue-600" />
              <span className="ml-2 text-xl font-bold text-gray-900">Step-CA Web UI</span>
            </div>
            <div className="hidden sm:ml-6 sm:flex sm:space-x-8">
              {navigation.map((item) => {
                const Icon = item.icon
                return (
                  <Link
                    key={item.name}
                    href={item.href}
                    className={cn(
                      pathname === item.href
                        ? 'border-blue-500 text-blue-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300',
                      'inline-flex items-center px-1 pt-1 border-b-2 text-sm font-medium'
                    )}
                  >
                    <Icon className="h-4 w-4 mr-2" />
                    {item.name}
                  </Link>
                )
              })}
            </div>
          </div>

          <div className="flex items-center gap-3 pl-4">
            {admin && (
              <span className="hidden lg:inline text-sm text-gray-500">
                {admin.username}
              </span>
            )}

            <button
              type="button"
              onClick={() => void handleLogout()}
              disabled={signingOut}
              className="inline-flex items-center gap-2 rounded-md px-3 py-2 text-sm font-medium text-gray-600 hover:bg-gray-100 hover:text-gray-900 disabled:opacity-50"
              aria-label="Sign out"
            >
              <LogOut className="h-4 w-4" />
              <span>{signingOut ? 'Signing out…' : 'Sign out'}</span>
            </button>

            {logoutError && (
              <span role="alert" className="text-xs text-red-600">
                Sign out failed
              </span>
            )}
          </div>
        </div>
      </div>
    </nav>
  )
}
