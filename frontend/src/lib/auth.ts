import api from './api'

export interface AdminUser {
  id: number
  username: string
}

export interface AuthSession {
  authenticated: boolean
  admin: AdminUser
}

export const authApi = {
  login: async (
    username: string,
    password: string,
  ): Promise<{ authenticated: boolean }> => {
    const response = await api.post('/api/auth/login', {
      username,
      password,
    })

    return response.data
  },

  me: async (): Promise<AuthSession> => {
    const response = await api.get('/api/auth/me')
    return response.data
  },

  logout: async (): Promise<void> => {
    await api.post('/api/auth/logout')
  },
}
