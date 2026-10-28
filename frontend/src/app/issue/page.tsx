'use client'

import { useEffect, useState } from 'react'
import { useForm } from 'react-hook-form'
import { certificateApi, IssueRequest } from '@/lib/api'
import { Shield, Download, AlertCircle } from 'lucide-react'
import { toast } from 'react-hot-toast'
import { downloadBase64File } from '@/lib/utils'
import Link from 'next/link'

interface FormData {
  cn: string
  sans: string
  not_after_days: number
  key_type: 'rsa-2048' | 'ec-p256'
  format: 'pem' | 'pfx'
  pfx_password?: string
}

export default function IssueCertificate() {
  const [loading, setLoading] = useState(false)
  const [defaultDNSSuffix, setDefaultDNSSuffix] = useState('')
  const [appendDNSSuffix, setAppendDNSSuffix] = useState(false)
  const [downloadData, setDownloadData] = useState<{
    data: string
    filename: string
    mime_type: string
  } | null>(null)

  const {
    register,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<FormData>({
    defaultValues: {
      cn: '',
      sans: '',
      not_after_days: 365,
      key_type: 'rsa-2048',
      format: 'pem',
    },
  })

  const format = watch('format')

  useEffect(() => {
    const loadIssuanceDefaults = async () => {
      try {
        const settings = await certificateApi.getCASettings()
        setDefaultDNSSuffix(settings.default_dns_suffix || '')
        setAppendDNSSuffix(settings.append_dns_suffix || false)
      } catch (error) {
        console.error('Failed to load certificate issuance defaults:', error)
      }
    }

    loadIssuanceDefaults()
  }, [])

  const onSubmit = async (data: FormData) => {
    setLoading(true)
    try {
      // Parse SANs from comma-separated string
      const sans = data.sans
        .split(',')
        .map(san => san.trim())
        .filter(san => san.length > 0)

      const cn = appendDNSSuffix && defaultDNSSuffix
        ? `${data.cn.replace(/\.+$/, '')}.${defaultDNSSuffix}`
        : data.cn

      const request: IssueRequest = {
        cn,
        sans,
        not_after_days: data.not_after_days,
        key_type: data.key_type,
        format: data.format,
        pfx_password: data.pfx_password,
      }

      const response = await certificateApi.issueCertificate(request)
      setDownloadData(response.download)
      toast.success('Certificate issued successfully!')
    } catch (error: any) {
      console.error('Failed to issue certificate:', error)
      toast.error(error.response?.data?.error || 'Failed to issue certificate')
    } finally {
      setLoading(false)
    }
  }

  const handleDownload = () => {
    if (downloadData) {
      downloadBase64File(downloadData.data, downloadData.filename, downloadData.mime_type)
    }
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
          <h1 className="mt-4 text-3xl font-bold text-gray-900">Issue New Certificate</h1>
          <p className="mt-2 text-gray-600">Create a new certificate with server-generated keypair</p>
        </div>

        <div className="bg-white rounded-lg shadow">
          <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-6">
            {/* Common Name */}
            <div>
              <label htmlFor="cn" className="block text-sm font-medium text-gray-700">
                Common Name (CN) *
              </label>
              {appendDNSSuffix && defaultDNSSuffix ? (
                <div className="mt-1 flex rounded-md shadow-sm">
                  <input
                    {...register('cn', { required: 'Common Name is required' })}
                    type="text"
                    className="flex-1 min-w-0 block w-full border-gray-300 rounded-l-md focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                    placeholder="server01"
                  />
                  <span className="inline-flex items-center px-3 border border-l-0 border-gray-300 bg-gray-50 text-gray-500 rounded-r-md sm:text-sm font-mono">
                    .{defaultDNSSuffix}
                  </span>
                </div>
              ) : (
                <input
                  {...register('cn', { required: 'Common Name is required' })}
                  type="text"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="example.com"
                />
              )}
              {errors.cn && (
                <p className="mt-1 text-sm text-red-600">{errors.cn.message}</p>
              )}
            </div>

            {/* Subject Alternative Names */}
            <div>
              <label htmlFor="sans" className="block text-sm font-medium text-gray-700">
                Subject Alternative Names (SANs)
              </label>
              <input
                {...register('sans')}
                type="text"
                className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                placeholder="www.example.com, api.example.com, *.example.com"
              />
              <p className="mt-1 text-sm text-gray-500">
                Comma-separated list of additional domain names
              </p>
            </div>

            {/* Key Type */}
            <div>
              <label htmlFor="key_type" className="block text-sm font-medium text-gray-700">
                Key Type
              </label>
              <select
                {...register('key_type')}
                className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
              >
                <option value="rsa-2048">RSA 2048-bit (recommended for infrastructure)</option>
                <option value="ec-p256">EC P-256</option>
              </select>
              <p className="mt-1 text-sm text-gray-500">
                RSA 2048 provides broad compatibility with appliances and management interfaces.
              </p>
            </div>

            {/* Validity Period */}
            <div>
              <label htmlFor="not_after_days" className="block text-sm font-medium text-gray-700">
                Validity Period (Days)
              </label>
              <select
                {...register('not_after_days', { valueAsNumber: true })}
                className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
              >
                <option value={30}>30 days</option>
                <option value={90}>90 days</option>
                <option value={180}>180 days</option>
                <option value={365}>1 year</option>
              </select>
            </div>

            {/* Output Format */}
            <div>
              <label className="block text-sm font-medium text-gray-700">
                Output Format
              </label>
              <div className="mt-2 space-y-2">
                <label className="flex items-center">
                  <input
                    {...register('format')}
                    type="radio"
                    value="pem"
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                  />
                  <span className="ml-2 text-sm text-gray-700">PEM Bundle (cert.pem, chain.pem, privkey.pem)</span>
                </label>
                <label className="flex items-center">
                  <input
                    {...register('format')}
                    type="radio"
                    value="pfx"
                    className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300"
                  />
                  <span className="ml-2 text-sm text-gray-700">PFX/PKCS#12 Bundle</span>
                </label>
              </div>
            </div>

            {/* PFX Password */}
            {format === 'pfx' && (
              <div>
                <label htmlFor="pfx_password" className="block text-sm font-medium text-gray-700">
                  PFX Password
                </label>
                <input
                  {...register('pfx_password', {
                    required: format === 'pfx' ? 'PFX password is required' : false,
                  })}
                  type="password"
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="Enter password for PFX file"
                />
                {errors.pfx_password && (
                  <p className="mt-1 text-sm text-red-600">{errors.pfx_password.message}</p>
                )}
              </div>
            )}

            {/* Submit Button */}
            <div className="flex justify-end space-x-3">
              <Link
                href="/"
                className="px-4 py-2 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50"
              >
                Cancel
              </Link>
              <button
                type="submit"
                disabled={loading}
                className="px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? 'Issuing...' : 'Issue Certificate'}
              </button>
            </div>
          </form>
        </div>

        {/* Download Section */}
        {downloadData && (
          <div className="mt-8 bg-green-50 border border-green-200 rounded-lg p-6">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-green-500" />
              <div className="ml-4">
                <h3 className="text-lg font-medium text-green-800">Certificate Issued Successfully!</h3>
                <p className="text-sm text-green-600">
                  Your certificate has been generated and is ready for download.
                </p>
              </div>
            </div>
            <div className="mt-4">
              <button
                onClick={handleDownload}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-green-600 hover:bg-green-700"
              >
                <Download className="h-4 w-4 mr-2" />
                Download Certificate Bundle
              </button>
            </div>
            <div className="mt-4 p-4 bg-green-100 rounded-md">
              <h4 className="text-sm font-medium text-green-800 mb-2">Installation Instructions:</h4>
              <ul className="text-sm text-green-700 space-y-1">
                <li>• Extract the downloaded ZIP file</li>
                <li>• Use <code className="bg-green-200 px-1 rounded">fullchain.pem</code> as your certificate</li>
                <li>• Use <code className="bg-green-200 px-1 rounded">privkey.pem</code> as your private key</li>
                <li>• See README.txt for detailed installation instructions</li>
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
