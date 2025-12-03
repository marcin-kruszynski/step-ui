'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'

interface Config {
  apiUrl: string
}

interface ConfigContextType {
  config: Config | null
  loading: boolean
  error: Error | null
}

const ConfigContext = createContext<ConfigContextType>({
  config: null,
  loading: true,
  error: null,
})

export function ConfigProvider({ children }: { children: ReactNode }) {
  const [config, setConfig] = useState<Config | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)

  useEffect(() => {
    fetch('/config')
      .then(res => {
        if (!res.ok) {
          throw new Error(`Failed to fetch config: ${res.status}`)
        }
        return res.json()
      })
      .then(data => {
        // Use ENV value if set, otherwise fallback to current origin
        const apiUrl = data.apiUrl || window.location.origin
        setConfig({ apiUrl })
        setLoading(false)
      })
      .catch(err => {
        console.error('Error loading configuration:', err)
        setError(err)
        setLoading(false)
      })
  }, [])

  return (
    <ConfigContext.Provider value={{ config, loading, error }}>
      {children}
    </ConfigContext.Provider>
  )
}

export const useConfig = () => useContext(ConfigContext)