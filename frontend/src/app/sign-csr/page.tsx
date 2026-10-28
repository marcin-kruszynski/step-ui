'use client'

import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { certificateApi, SignCSRRequest } from '@/lib/api'
import { FileText, Upload, AlertCircle } from 'lucide-react'
import { toast } from 'react-hot-toast'
import Link from 'next/link'

interface FormData {
  csr_pem: string
  not_after_days: number
}

export default function SignCSR() {
  const [loading, setLoading] = useState(false)
  const [certData, setCertData] = useState<{
    cert_pem: string
    chain_pem: string
  } | null>(null)

  const {
    register,
    handleSubmit,
    setValue,
    formState: { errors },
  } = useForm<FormData>({
    defaultValues: {
      csr_pem: '',
      not_after_days: 365,
    },
  })

  const onSubmit = async (data: FormData) => {
    setLoading(true)
    try {
      const request: SignCSRRequest = {
        csr_pem: data.csr_pem,
        not_after_days: data.not_after_days,
      }

      const response = await certificateApi.signCSR(request)
      setCertData({
        cert_pem: response.cert_pem,
        chain_pem: response.chain_pem,
      })
      toast.success('CSR signed successfully!')
    } catch (error: any) {
      console.error('Failed to sign CSR:', error)
      toast.error(error.response?.data?.error || 'Failed to sign CSR')
    } finally {
      setLoading(false)
    }
  }

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (e) => {
        const content = e.target?.result
        if (typeof content === 'string') {
          setValue('csr_pem', content, {
            shouldValidate: true,
            shouldDirty: true,
            shouldTouch: true,
          })
        }
      }
      reader.readAsText(file)
    }
  }

  const downloadCert = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)
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
          <h1 className="mt-4 text-3xl font-bold text-gray-900">Sign Certificate Signing Request</h1>
          <p className="mt-2 text-gray-600">Upload a CSR to get it signed by your CA</p>
        </div>

        <div className="bg-white rounded-lg shadow">
          <form onSubmit={handleSubmit(onSubmit)} className="p-6 space-y-6">
            {/* CSR Input */}
            <div>
              <label htmlFor="csr_pem" className="block text-sm font-medium text-gray-700">
                Certificate Signing Request (CSR) *
              </label>
              <div className="mt-1">
                <textarea
                  {...register('csr_pem', { required: 'CSR is required' })}
                  rows={10}
                  className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm font-mono"
                  placeholder="-----BEGIN CERTIFICATE REQUEST-----
MIIB...
-----END CERTIFICATE REQUEST-----"
                />
              </div>
              <div className="mt-2 flex items-center space-x-4">
                <label className="inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 cursor-pointer">
                  <Upload className="h-4 w-4 mr-2" />
                  Upload CSR File
                  <input
                    type="file"
                    accept=".pem,.csr,.txt"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
                <span className="text-sm text-gray-500">
                  Or paste the CSR content directly
                </span>
              </div>
              {errors.csr_pem && (
                <p className="mt-1 text-sm text-red-600">{errors.csr_pem.message}</p>
              )}
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
                {loading ? 'Signing...' : 'Sign CSR'}
              </button>
            </div>
          </form>
        </div>

        {/* Certificate Output */}
        {certData && (
          <div className="mt-8 bg-green-50 border border-green-200 rounded-lg p-6">
            <div className="flex items-center">
              <FileText className="h-8 w-8 text-green-500" />
              <div className="ml-4">
                <h3 className="text-lg font-medium text-green-800">CSR Signed Successfully!</h3>
                <p className="text-sm text-green-600">
                  Your certificate has been generated and is ready for download.
                </p>
              </div>
            </div>
            <div className="mt-4 space-y-4">
              <div>
                <h4 className="text-sm font-medium text-green-800 mb-2">Certificate:</h4>
                <div className="bg-white border border-green-200 rounded-md p-3">
                  <pre className="text-xs text-gray-700 whitespace-pre-wrap break-all">
                    {certData.cert_pem}
                  </pre>
                </div>
                <button
                  onClick={() => downloadCert(certData.cert_pem, 'certificate.pem')}
                  className="mt-2 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded text-green-700 bg-green-100 hover:bg-green-200"
                >
                  Download Certificate
                </button>
              </div>
              <div>
                <h4 className="text-sm font-medium text-green-800 mb-2">Certificate Chain:</h4>
                <div className="bg-white border border-green-200 rounded-md p-3">
                  <pre className="text-xs text-gray-700 whitespace-pre-wrap break-all">
                    {certData.chain_pem}
                  </pre>
                </div>
                <button
                  onClick={() => downloadCert(certData.chain_pem, 'chain.pem')}
                  className="mt-2 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded text-green-700 bg-green-100 hover:bg-green-200"
                >
                  Download Chain
                </button>
              </div>
            </div>
            <div className="mt-4 p-4 bg-green-100 rounded-md">
              <h4 className="text-sm font-medium text-green-800 mb-2">Installation Instructions:</h4>
              <ul className="text-sm text-green-700 space-y-1">
                <li>• Save the certificate and chain to your server</li>
                <li>• Configure your web server to use the certificate</li>
                <li>• The private key should remain on the system that generated the CSR</li>
                <li>• Test the certificate with: <code className="bg-green-200 px-1 rounded">openssl x509 -in certificate.pem -text -noout</code></li>
              </ul>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
