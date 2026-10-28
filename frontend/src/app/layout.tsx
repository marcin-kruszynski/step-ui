import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { Toaster } from 'react-hot-toast'
import Navigation from './navigation'
import { AuthProvider } from '@/contexts/AuthContext'
import { AuthGate } from '@/components/auth/AuthGate'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Step-CA Web UI',
  description: 'Web interface for Step-CA certificate management',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={inter.className}>
        <AuthProvider>
          <AuthGate>
            <Navigation />
            {children}
            <Toaster position="top-right" />
          </AuthGate>
        </AuthProvider>
      </body>
    </html>
  )
}
