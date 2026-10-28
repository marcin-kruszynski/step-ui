'use client'

// 2026-10-24: Certificate archive.
// Archived certificates remain in the database and retain their CA status.

import { useEffect, useState } from 'react'
import { certificateApi, Certificate } from '@/lib/api'
import { formatDate } from '@/lib/utils'
import { Archive, RotateCcw, Search } from 'lucide-react'
import { toast } from 'react-hot-toast'
import Link from 'next/link'

export default function CertificateArchive() {
  const [certificates, setCertificates] = useState<Certificate[]>([])
  const [loading, setLoading] = useState(true)
  const [restoringId, setRestoringId] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState('')

  useEffect(() => {
    loadCertificates()
  }, [])

  const loadCertificates = async () => {
    try {
      const response = await certificateApi.listArchivedCertificates({
        limit: 500,
      })

      setCertificates(response.certificates || [])
    } catch (error) {
      console.error('Failed to load archive:', error)
      toast.error('Failed to load certificate archive')
    } finally {
      setLoading(false)
    }
  }

  const handleRestore = async (cert: Certificate) => {
    if (
      !confirm(
        `Restore ${cert.cn} to the certificate inventory?\n\n` +
        'This will NOT renew the certificate or reverse its revocation.'
      )
    ) {
      return
    }

    setRestoringId(cert.id)

    try {
      await certificateApi.restoreCertificate(cert.id)
      toast.success('Certificate restored to inventory')
      await loadCertificates()
    } catch (error: any) {
      console.error('Failed to restore certificate:', error)
      toast.error(
        error.response?.data?.error ||
        'Failed to restore certificate'
      )
    } finally {
      setRestoringId(null)
    }
  }

  const filteredCertificates = certificates.filter((cert) => {
    const search = searchTerm.toLowerCase()

    return (
      cert.cn.toLowerCase().includes(search) ||
      (cert.serial || '').toLowerCase().includes(search)
    )
  })

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500" />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">

        <div className="mb-8">
          <Link
            href="/inventory"
            className="text-blue-600 hover:text-blue-500 text-sm font-medium"
          >
            ← Back to Inventory
          </Link>

          <div className="flex items-center gap-3 mt-4">
            <Archive className="h-8 w-8 text-gray-700" />

            <h1 className="text-3xl font-bold text-gray-900">
              Certificate Archive
            </h1>
          </div>

          <p className="mt-2 text-gray-600">
            Historical certificates manually removed from the active inventory.
          </p>

          <p className="mt-1 text-sm text-gray-500">
            Archiving and restoring certificates never changes their
            validity or revocation status.
          </p>
        </div>

        <div className="bg-white rounded-lg shadow mb-6 p-6">
          <div className="flex items-center justify-between gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-3 h-5 w-5 text-gray-400" />

              <input
                type="text"
                placeholder="Search certificates or serial numbers..."
                value={searchTerm}
                onChange={(event) => setSearchTerm(event.target.value)}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-md text-gray-900"
              />
            </div>

            <div className="text-sm text-gray-600">
              {certificates.length} archived
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow overflow-hidden">
          {filteredCertificates.length === 0 ? (
            <div className="p-12 text-center">
              <Archive className="mx-auto h-12 w-12 text-gray-400" />

              <h2 className="mt-4 text-lg font-medium text-gray-900">
                {searchTerm
                  ? 'No matching certificates'
                  : 'No archived certificates'}
              </h2>

              <p className="mt-2 text-gray-500">
                {searchTerm
                  ? 'Try another search term.'
                  : 'Expired and revoked certificates can be archived from Inventory.'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    {[
                      'Certificate',
                      'Status',
                      'Expiration',
                      'Archived',
                      'Actions',
                    ].map((heading) => (
                      <th
                        key={heading}
                        className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider"
                      >
                        {heading}
                      </th>
                    ))}
                  </tr>
                </thead>

                <tbody className="bg-white divide-y divide-gray-200">
                  {filteredCertificates.map((cert) => (
                    <tr key={cert.id}>
                      <td className="px-6 py-4">
                        <div className="text-sm font-medium text-gray-900">
                          {cert.cn}
                        </div>

                        <div className="text-xs text-gray-500 font-mono break-all mt-1">
                          Serial: {cert.serial || 'Unavailable'}
                        </div>
                      </td>

                      <td className="px-6 py-4 text-sm">
                        <span className="capitalize">
                          {cert.status}
                        </span>
                      </td>

                      <td className="px-6 py-4 text-sm text-gray-600">
                        {formatDate(cert.not_after)}
                      </td>

                      <td className="px-6 py-4 text-sm text-gray-600">
                        {cert.archived_at
                          ? formatDate(cert.archived_at)
                          : 'Unknown'}
                      </td>

                      <td className="px-6 py-4">
                        <button
                          type="button"
                          onClick={() => handleRestore(cert)}
                          disabled={restoringId !== null}
                          className="inline-flex items-center gap-2 text-blue-600 hover:text-blue-800 disabled:opacity-50 text-sm font-medium"
                        >
                          <RotateCcw className="h-4 w-4" />

                          {restoringId === cert.id
                            ? 'Restoring...'
                            : 'Restore'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
