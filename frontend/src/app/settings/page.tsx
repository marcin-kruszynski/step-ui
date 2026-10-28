'use client'

import { useEffect, useState } from 'react'
import { certificateApi, CASettings } from '@/lib/api'
import { Copy, AlertCircle } from 'lucide-react'
import { toast } from 'react-hot-toast'
import Link from 'next/link'

export default function Settings() {
  const [settings, setSettings] = useState<CASettings | null>(null)
  const [loading, setLoading] = useState(true)
  const [testHost, setTestHost] = useState('')
  const [defaultDNSSuffix, setDefaultDNSSuffix] = useState('')
  const [appendDNSSuffix, setAppendDNSSuffix] = useState(false)
  const [savingIssuanceDefaults, setSavingIssuanceDefaults] = useState(false)

  useEffect(() => {
    loadSettings()
  }, [])

  const loadSettings = async () => {
    try {
      const response = await certificateApi.getCASettings()
      setSettings(response)
      setDefaultDNSSuffix(response.default_dns_suffix || '')
      setAppendDNSSuffix(response.append_dns_suffix || false)
      setTestHost('')
    } catch (error) {
      console.error('Failed to load CA settings:', error)
      toast.error('Failed to load CA settings')
    } finally {
      setLoading(false)
    }
  }

  const saveIssuanceDefaults = async () => {
    setSavingIssuanceDefaults(true)
    try {
      const response = await certificateApi.updateCASettings({
        default_dns_suffix: defaultDNSSuffix,
        append_dns_suffix: appendDNSSuffix,
      })

      setDefaultDNSSuffix(response.default_dns_suffix)
      setAppendDNSSuffix(response.append_dns_suffix)
      setSettings(current => current ? {
        ...current,
        default_dns_suffix: response.default_dns_suffix,
        append_dns_suffix: response.append_dns_suffix,
      } : current)

      toast.success('Certificate issuance defaults saved!')
    } catch (error: any) {
      console.error('Failed to save certificate issuance defaults:', error)
      toast.error(error.response?.data?.error || 'Failed to save certificate issuance defaults')
    } finally {
      setSavingIssuanceDefaults(false)
    }
  }

  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text)
      } else {
        throw new Error('Clipboard API unavailable')
      }
      toast.success('Copied to clipboard!')
    } catch {
      const textarea = document.createElement('textarea')
      textarea.value = text
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      textarea.focus()
      textarea.select()

      try {
        const copied = document.execCommand('copy')
        if (!copied) {
          throw new Error('Fallback copy failed')
        }
        toast.success('Copied to clipboard!')
      } catch (error) {
        console.error('Failed to copy to clipboard:', error)
        toast.error('Failed to copy to clipboard')
      } finally {
        document.body.removeChild(textarea)
      }
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
          <h1 className="mt-4 text-3xl font-bold text-gray-900">CA Settings</h1>
          <p className="mt-2 text-gray-600">Certificate Authority configuration and trust instructions</p>
        </div>

        <div className="space-y-8">
          {/* CA Information */}
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-medium text-gray-900">Certificate Authority Information</h2>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">CA URL</label>
                <div className="mt-1 flex items-center">
                  <input
                    type="text"
                    value={settings?.ca_url || ''}
                    readOnly
                    className="flex-1 block w-full border-gray-300 rounded-md shadow-sm bg-gray-50 sm:text-sm"
                  />
                  <button
                    onClick={() => copyToClipboard(settings?.ca_url || '')}
                    className="ml-2 inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                  >
                    <Copy className="h-4 w-4" />
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">Root Fingerprint</label>
                <div className="mt-1 flex items-center">
                  <input
                    type="text"
                    value={settings?.root_fingerprint || 'Not available'}
                    readOnly
                    className="flex-1 block w-full border-gray-300 rounded-md shadow-sm bg-gray-50 sm:text-sm font-mono"
                  />
                  <button
                    onClick={() => copyToClipboard(settings?.root_fingerprint || '')}
                    className="ml-2 inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                  >
                    <Copy className="h-4 w-4" />
                  </button>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700">ACME Directories</label>
                <div className="mt-1">
                  {settings?.acme_directories?.map((dir, index) => (
                    <div key={index} className="flex items-center mb-2">
                      <input
                        type="text"
                        value={dir}
                        readOnly
                        className="flex-1 block w-full border-gray-300 rounded-md shadow-sm bg-gray-50 sm:text-sm"
                      />
                      <button
                        onClick={() => copyToClipboard(dir)}
                        className="ml-2 inline-flex items-center px-3 py-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                      >
                        <Copy className="h-4 w-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Certificate Issuance Defaults */}
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-medium text-gray-900">Certificate Issuance Defaults</h2>
              <p className="mt-1 text-sm text-gray-500">
                Optional conveniences for issuing certificates. These settings do not change the CA itself.
              </p>
            </div>
            <div className="p-6 space-y-4">
              <div>
                <label htmlFor="default_dns_suffix" className="block text-sm font-medium text-gray-700">
                  Default DNS Suffix
                </label>
                <input
                  id="default_dns_suffix"
                  type="text"
                  value={defaultDNSSuffix}
                  onChange={(event) => setDefaultDNSSuffix(event.target.value)}
                  className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                  placeholder="example.com"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Example: entering <span className="font-mono">server01</span> when the suffix is <span className="font-mono">example.com</span> will issue for <span className="font-mono">server01.example.com</span>.
                </p>
              </div>

              <div className="flex items-start">
                <input
                  id="append_dns_suffix"
                  type="checkbox"
                  checked={appendDNSSuffix}
                  onChange={(event) => setAppendDNSSuffix(event.target.checked)}
                  className="mt-1 h-4 w-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <div className="ml-3">
                  <label htmlFor="append_dns_suffix" className="text-sm font-medium text-gray-700">
                    Append default DNS suffix when issuing certificates
                  </label>
                  <p className="text-sm text-gray-500">
                    When disabled, the Common Name field remains unchanged and accepts a complete hostname as usual.
                  </p>
                </div>
              </div>

              <div>
                <button
                  type="button"
                  onClick={saveIssuanceDefaults}
                  disabled={savingIssuanceDefaults}
                  className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 disabled:opacity-50"
                >
                  {savingIssuanceDefaults ? 'Saving...' : 'Save Issuance Defaults'}
                </button>
              </div>
            </div>
          </div>

          {/* Trust Installation */}
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-medium text-gray-900">Trust Installation</h2>
            </div>
            <div className="p-6 space-y-6">
              <div className="bg-blue-50 border border-blue-200 rounded-md p-4">
                <div className="flex">
                  <AlertCircle className="h-5 w-5 text-blue-400" />
                  <div className="ml-3">
                    <h3 className="text-sm font-medium text-blue-800">Important</h3>
                    <p className="mt-1 text-sm text-blue-700">
                      To trust certificates issued by this CA, you need to install the root CA certificate
                      on client systems. This allows browsers and applications to verify the certificate chain.
                    </p>
                  </div>
                </div>
              </div>

              {/* Linux/Ubuntu Instructions */}
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-3">Linux/Ubuntu</h3>
                <div className="bg-gray-50 rounded-md p-4">
                  <pre className="text-sm text-gray-800 whitespace-pre-wrap">
{`# Download the root CA certificate
curl -O ${settings?.ca_url}/roots.pem

# Install the certificate
sudo cp roots.pem /usr/local/share/ca-certificates/my-ca.crt
sudo update-ca-certificates

# Verify installation
openssl verify -CAfile /etc/ssl/certs/my-ca.pem /path/to/your/certificate.pem`}
                  </pre>
                  <button
                    onClick={() => copyToClipboard(`curl -O ${settings?.ca_url}/roots.pem\nsudo cp roots.pem /usr/local/share/ca-certificates/my-ca.crt\nsudo update-ca-certificates`)}
                    className="mt-2 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200"
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    Copy Commands
                  </button>
                </div>
              </div>

              {/* Windows Instructions */}
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-3">Windows</h3>
                <div className="bg-gray-50 rounded-md p-4">
                  <pre className="text-sm text-gray-800 whitespace-pre-wrap">
{`# PowerShell (Run as Administrator)
# Download the root CA certificate
Invoke-WebRequest -Uri "${settings?.ca_url}/roots.pem" -OutFile "roots.pem"

# Import the certificate
Import-Certificate -FilePath "roots.pem" -CertStoreLocation Cert:\LocalMachine\Root

# Verify installation
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Subject -like "*Your CA Name*"}`}
                  </pre>
                  <button
                    onClick={() => copyToClipboard(`Invoke-WebRequest -Uri "${settings?.ca_url}/roots.pem" -OutFile "roots.pem"\nImport-Certificate -FilePath "roots.pem" -CertStoreLocation Cert:\LocalMachine\Root`)}
                    className="mt-2 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200"
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    Copy Commands
                  </button>
                </div>
              </div>

              {/* macOS Instructions */}
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-3">macOS</h3>
                <div className="bg-gray-50 rounded-md p-4">
                  <pre className="text-sm text-gray-800 whitespace-pre-wrap">
{`# Download the root CA certificate
curl -O ${settings?.ca_url}/roots.pem

# Add to Keychain (double-click the .pem file)
open roots.pem

# Or via command line
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain roots.pem

# Verify installation
security find-certificate -a -c "Your CA Name" /Library/Keychains/System.keychain`}
                  </pre>
                  <button
                    onClick={() => copyToClipboard(`curl -O ${settings?.ca_url}/roots.pem\nsudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain roots.pem`)}
                    className="mt-2 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200"
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    Copy Commands
                  </button>
                </div>
              </div>

              {/* iOS/iPadOS Instructions */}
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-3">iOS / iPadOS</h3>
                <div className="bg-gray-50 rounded-md p-4">
                  <ol className="text-sm text-gray-800 space-y-2">
                    <li>1. Download the root CA certificate from <span className="font-mono">{settings?.ca_url}/roots.pem</span></li>
                    <li>2. Open Settings and install the downloaded certificate profile when prompted</li>
                    <li>3. Go to Settings → General → About → Certificate Trust Settings</li>
                    <li>4. Under "Enable Full Trust for Root Certificates", enable trust for the installed root CA</li>
                    <li>5. Confirm the warning to enable full trust</li>
                    <li>6. Return to Safari or the application using the CA-issued certificate and verify that it is trusted</li>
                  </ol>
                  <p className="mt-3 text-xs text-gray-600">
                    On managed devices, profile installation or trust settings may be controlled by your administrator or MDM.
                  </p>
                </div>
              </div>

              {/* Android Instructions */}
              <div>
                <h3 className="text-lg font-medium text-gray-900 mb-3">Android</h3>
                <div className="bg-gray-50 rounded-md p-4">
                  <ol className="text-sm text-gray-800 space-y-2">
                    <li>1. Download the root CA certificate to your device</li>
                    <li>2. Go to Settings → Security → Encryption & credentials</li>
                    <li>3. Tap "Install a certificate" → "CA certificate"</li>
                    <li>4. Select the downloaded .pem file</li>
                    <li>5. Give the certificate a name and tap "OK"</li>
                    <li>6. The certificate is now trusted for all apps</li>
                  </ol>
                </div>
              </div>
            </div>
          </div>

          {/* Verification */}
          <div className="bg-white rounded-lg shadow">
            <div className="px-6 py-4 border-b border-gray-200">
              <h2 className="text-lg font-medium text-gray-900">Verification</h2>
            </div>
            <div className="p-6">
              <div className="bg-gray-50 rounded-md p-4">
                <h3 className="text-sm font-medium text-gray-900 mb-3">Test Certificate Trust</h3>

                <label htmlFor="tls_test_host" className="block text-sm font-medium text-gray-700">
                  TLS Host to Test
                </label>
                <input
                  id="tls_test_host"
                  type="text"
                  value={testHost}
                  onChange={(event) => setTestHost(event.target.value)}
                  placeholder="service.example.com"
                  className="mt-1 block w-full bg-white border-2 border-gray-400 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                />
                <p className="mt-1 text-sm text-gray-500">
                  Enter a hostname serving HTTPS on port 443 with a certificate issued by this CA. The command below updates automatically.
                </p>

                <div className="mt-5">
                  <h4 className="text-sm font-medium text-gray-900">Live TLS Endpoint</h4>
                  <p className="mt-1 text-sm text-gray-500">
                    Shows the certificate chain presented by the server. Trust verification also depends on whether your local OpenSSL trusts the issuing root CA.
                  </p>
                  <pre className="mt-2 text-sm text-gray-800 whitespace-pre-wrap">
{`openssl s_client -connect ${testHost || 'service.example.com'}:443 -servername ${testHost || 'service.example.com'} -showcerts`}
                  </pre>
                  <button
                    onClick={() => copyToClipboard(`openssl s_client -connect ${testHost || 'service.example.com'}:443 -servername ${testHost || 'service.example.com'} -showcerts`)}
                    className="mt-2 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200"
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    Copy Command
                  </button>
                </div>

                <div className="mt-6">
                  <h4 className="text-sm font-medium text-gray-900">Downloaded PEM Bundle</h4>
                  <p className="mt-1 text-sm text-gray-500">
                    Run these commands from the directory containing the extracted certificate bundle and roots.pem.
                  </p>
                  <pre className="mt-2 text-sm text-gray-800 whitespace-pre-wrap">
{`# Verify the downloaded leaf certificate and intermediate chain
openssl verify -CAfile roots.pem -untrusted chain.pem cert.pem

# Inspect the downloaded leaf certificate
openssl x509 -in cert.pem -text -noout`}
                  </pre>
                  <button
                    onClick={() => copyToClipboard(`openssl verify -CAfile roots.pem -untrusted chain.pem cert.pem\nopenssl x509 -in cert.pem -text -noout`)}
                    className="mt-2 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded text-blue-700 bg-blue-100 hover:bg-blue-200"
                  >
                    <Copy className="h-4 w-4 mr-1" />
                    Copy Commands
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
