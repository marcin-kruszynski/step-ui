import axios, { AxiosInstance } from 'axios'

// Create a function to get API client with dynamic baseURL
let cachedApiUrl: string | null = null

async function getApiUrl(): Promise<string> {
  if (cachedApiUrl) {
    return cachedApiUrl
  }

  const response = await fetch('/config')
  if (!response.ok) {
    throw new Error(`Failed to fetch config: ${response.status}`)
  }
  const data = await response.json()
  cachedApiUrl = data.apiUrl
  return cachedApiUrl as string
}

export async function createApiClient(): Promise<AxiosInstance> {
  const apiUrl = await getApiUrl()
  return axios.create({
    baseURL: apiUrl,
    headers: {
      'Content-Type': 'application/json',
    },
  })
}

// Legacy export for backward compatibility (will be deprecated)
const api = axios.create({
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add interceptor to set baseURL dynamically
api.interceptors.request.use(async (config: any) => {
  if (!config.baseURL) {
    config.baseURL = await getApiUrl()
  }
  return config
})

export interface Certificate {
  id: string
  cn: string
  sans: string[]
  not_after: string
  status: string
  key_strategy: string
  created_at: string
  updated_at: string
}

export interface IssueRequest {
  cn: string
  sans: string[]
  not_after_days: number
  format: 'pem' | 'pfx'
  pfx_password?: string
}

export interface SignCSRRequest {
  csr_pem: string
  not_after_days: number
}

export interface CertBundle {
  data: string
  filename: string
  mime_type: string
}

export interface CASettings {
  ca_url: string
  root_fingerprint: string
  acme_directories: string[]
}

export const certificateApi = {
  // Issue a new certificate
  issueCertificate: async (data: IssueRequest) => {
    const client = await createApiClient()
    const response = await client.post('/api/certs/issue', data)
    return response.data
  },

  // Sign a CSR
  signCSR: async (data: SignCSRRequest) => {
    const client = await createApiClient()
    const response = await client.post('/api/certs/sign-csr', data)
    return response.data
  },

  // List certificates
  listCertificates: async (params?: {
    limit?: number
    offset?: number
    status?: string
  }) => {
    const client = await createApiClient()
    const response = await client.get('/api/certs', { params })
    return response.data
  },

  // Get a specific certificate
  getCertificate: async (id: string) => {
    const client = await createApiClient()
    const response = await client.get(`/api/certs/${id}`)
    return response.data
  },

  // Renew a certificate
  renewCertificate: async (id: string) => {
    const client = await createApiClient()
    const response = await client.post(`/api/certs/${id}/renew`)
    return response.data
  },

  // Revoke a certificate
  revokeCertificate: async (id: string) => {
    const client = await createApiClient()
    const response = await client.post(`/api/certs/${id}/revoke`)
    return response.data
  },

  // Get CA settings
  getCASettings: async () => {
    const client = await createApiClient()
    const response = await client.get('/api/settings/ca')
    return response.data
  },

  // Health check
  health: async () => {
    const client = await createApiClient()
    const response = await client.get('/health')
    return response.data
  },
}

export default api
