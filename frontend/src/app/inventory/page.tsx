'use client'

import { useEffect, useState } from 'react'
import { certificateApi, Certificate } from '@/lib/api'
import { formatDate, getDaysUntilExpiry, getExpiryStatus } from '@/lib/utils'
import { Archive, Shield, AlertTriangle, CheckCircle, Clock, Search, Filter, Download, RotateCcw, X } from 'lucide-react'
import { toast } from 'react-hot-toast'
import Link from 'next/link'

export default function Inventory() {
  const [certificates, setCertificates] = useState<Certificate[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null)

  useEffect(() => {
    loadCertificates()
  }, [])

  const loadCertificates = async () => {
    try {
      const response = await certificateApi.listCertificates({ limit: 1000 })
      setCertificates(response.certificates || [])
    } catch (error) {
      console.error('Failed to load certificates:', error)
      toast.error('Failed to load certificates')
    } finally {
      setLoading(false)
    }
  }

  const handleRenew = async (cert: Certificate) => {
    try {
      await certificateApi.renewCertificate(cert.id)
      toast.success('Certificate renewed successfully!')
      loadCertificates()
    } catch (error: any) {
      console.error('Failed to renew certificate:', error)
      toast.error(error.response?.data?.error || 'Failed to renew certificate')
    }
  }

  const handleRevoke = async (cert: Certificate) => {
    if (!confirm(`Are you sure you want to revoke certificate for ${cert.cn}?`)) {
      return
    }

    try {
      await certificateApi.revokeCertificate(cert.id)
      toast.success('Certificate revoked successfully!')
      loadCertificates()
    } catch (error: any) {
      console.error('Failed to revoke certificate:', error)
      toast.error(error.response?.data?.error || 'Failed to revoke certificate')
    }
  }


  // 2026-10-24: Manually archive revoked or expired certificates.
  const handleArchive = async (cert: Certificate) => {
    if (
      !confirm(
        `Archive certificate for ${cert.cn}?\n\n` +
        'This removes it from Inventory but preserves its history. ' +
        'You can restore it later.'
      )
    ) {
      return
    }

    try {
      await certificateApi.archiveCertificate(cert.id)
      toast.success('Certificate archived successfully!')
      await loadCertificates()
    } catch (error: any) {
      console.error('Failed to archive certificate:', error)
      toast.error(
        error.response?.data?.error ||
        'Failed to archive certificate'
      )
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'revoked':
        return <X className="h-4 w-4 text-red-500" />
      case 'expired':
        return <Clock className="h-4 w-4 text-gray-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getExpiryColor = (notAfter: string) => {
    const status = getExpiryStatus(notAfter)
    switch (status) {
      case 'critical':
        return 'text-red-600 bg-red-50'
      case 'warning':
        return 'text-yellow-600 bg-yellow-50'
      case 'expired':
        return 'text-gray-500 bg-gray-50'
      default:
        return 'text-green-600 bg-green-50'
    }
  }

  const filteredCertificates = certificates.filter((cert: Certificate) => {
    const matchesSearch = cert.cn.toLowerCase().includes(searchTerm.toLowerCase()) ||
      cert.sans.some((san: string) => san.toLowerCase().includes(searchTerm.toLowerCase()))
    const matchesStatus = !statusFilter || cert.status === statusFilter
    return matchesSearch && matchesStatus
  })

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center">
            <Link
              href="/"
              className="text-blue-600 hover:text-blue-500 text-sm font-medium"
            >
              ← Back to Dashboard
            </Link>
          </div>
          <h1 className="mt-4 text-3xl font-bold text-gray-900">Certificate Inventory</h1>
          <p className="mt-2 text-gray-600">Manage all your certificates</p>
        </div>

        {/* Filters */}
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div>
                <label htmlFor="search" className="block text-sm font-medium text-gray-700">
                  Search
                </label>
                <div className="mt-1 relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
                  <input
                    type="text"
                    id="search"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                    placeholder="Search by CN or SANs..."
                  />
                </div>
              </div>
              <div>
                <label htmlFor="status" className="block text-sm font-medium text-gray-700">
                  Status
                </label>
                <select
                  id="status"
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                >
                  <option value="">All Statuses</option>
                  <option value="active">Active</option>
                  <option value="revoked">Revoked</option>
                  <option value="expired">Expired</option>
                </select>
              </div>
              <div className="flex items-end">
                <button
                  onClick={() => {
                    setSearchTerm('')
                    setStatusFilter('')
                  }}
                  className="w-full inline-flex items-center justify-center px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                >
                  <Filter className="h-4 w-4 mr-2" />
                  Clear Filters
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Certificates Table */}
        <div className="bg-white rounded-lg shadow">
          <div className="px-6 py-4 border-b border-gray-200">
            <h2 className="text-lg font-medium text-gray-900">
              Certificates ({filteredCertificates.length})
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Certificate
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Expires
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Days Left
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Key Strategy
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {filteredCertificates.map((cert: Certificate) => (
                  <tr key={cert.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{cert.cn}</div>
                        {cert.sans && cert.sans.length > 0 && (
                          <div className="text-sm text-gray-500">
                            {cert.sans.slice(0, 2).join(', ')}
                            {cert.sans.length > 2 && ` +${cert.sans.length - 2} more`}
                          </div>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        {getStatusIcon(cert.status)}
                        <span className="ml-2 text-sm text-gray-900 capitalize">{cert.status}</span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                      {formatDate(cert.not_after)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getExpiryColor(cert.not_after)}`}>
                        {getDaysUntilExpiry(cert.not_after)} days
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {cert.key_strategy}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <div className="flex space-x-2">
                        {cert.status === 'active' && (
                          <>
                            <button
                              onClick={() => handleRenew(cert)}
                              className="text-blue-600 hover:text-blue-900"
                              title="Renew Certificate"
                            >
                              <RotateCcw className="h-4 w-4" />
                            </button>
                            <button
                              onClick={() => handleRevoke(cert)}
                              className="text-red-600 hover:text-red-900"
                              title="Revoke Certificate"
                            >
                              <X className="h-4 w-4" />
                            </button>
                          </>
                        )}
                        {/* 2026-10-24: Archive only revoked or expired certificates. */}
                        {(cert.status === 'revoked' ||
                          new Date(cert.not_after).getTime() <= Date.now()) && (
                          <button
                            type="button"
                            onClick={() => handleArchive(cert)}
                            className="text-amber-600 hover:text-amber-800"
                            title="Archive Certificate"
                            aria-label={`Archive certificate ${cert.cn}`}
                          >
                            <Archive className="h-4 w-4" />
                          </button>
                        )}
                        <button
                          onClick={() => setSelectedCert(cert)}
                          className="text-gray-600 hover:text-gray-900"
                          title="View Details"
                        >
                          <Shield className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Certificate Details Modal */}
        {selectedCert && (
          <div className="fixed inset-0 bg-gray-600 bg-opacity-50 overflow-y-auto h-full w-full z-50">
            <div className="relative top-20 mx-auto p-5 border w-96 shadow-lg rounded-md bg-white">
              <div className="mt-3">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-medium text-gray-900">Certificate Details</h3>
                  <button
                    onClick={() => setSelectedCert(null)}
                    className="text-gray-400 hover:text-gray-600"
                  >
                    <X className="h-6 w-6" />
                  </button>
                </div>
                <div className="space-y-3">
                  <div>
                    <label className="text-sm font-medium text-gray-500">Common Name</label>
                    <p className="text-sm text-gray-900">{selectedCert.cn}</p>
                  </div>
                  {selectedCert.sans && selectedCert.sans.length > 0 && (
                    <div>
                      <label className="text-sm font-medium text-gray-500">Subject Alternative Names</label>
                      <ul className="text-sm text-gray-900">
                        {selectedCert.sans.map((san, index) => (
                          <li key={index}>• {san}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <div>
                    <label className="text-sm font-medium text-gray-500">Status</label>
                    <p className="text-sm text-gray-900 capitalize">{selectedCert.status}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Expires</label>
                    <p className="text-sm text-gray-900">{formatDate(selectedCert.not_after)}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Key Strategy</label>
                    <p className="text-sm text-gray-900">{selectedCert.key_strategy}</p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-500">Created</label>
                    <p className="text-sm text-gray-900">{formatDate(selectedCert.created_at)}</p>
                  </div>
                </div>
                <div className="mt-6 flex justify-end space-x-3">
                  <button
                    onClick={() => setSelectedCert(null)}
                    className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
