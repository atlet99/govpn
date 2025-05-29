// API client for GoVPN backend
const API_BASE_URL = (import.meta as any).env?.VITE_API_URL || 'http://localhost:8080/api/v1'

interface ApiResponse<T = any> {
  success: boolean
  message?: string
  data?: T
  error?: string
}

interface User {
  id: string
  username: string
  email: string
  role: 'admin' | 'user' | 'viewer'
  status: 'active' | 'inactive' | 'suspended'
  lastLogin: string
  createdAt: string
  updatedAt: string
}

interface CreateUserRequest {
  username: string
  email: string
  password: string
  role: 'admin' | 'user' | 'viewer'
  status: 'active' | 'inactive' | 'suspended'
}

interface UpdateUserRequest {
  username?: string
  email?: string
  password?: string
  role?: 'admin' | 'user' | 'viewer'
  status?: 'active' | 'inactive' | 'suspended'
}

interface ConnectionInfo {
  id: string
  username: string
  realIP: string
  virtualIP: string
  protocol: string
  connectedAt: string
  bytesIn: number
  bytesOut: number
  status: 'connected' | 'disconnected'
  location?: string
  obfuscationMethod?: string
}

interface ServerStatus {
  running: boolean
  clientCount: number
  bytesIn: number
  bytesOut: number
  activeRoutes: string[]
  startTime: string
  uptime: number
}

interface Certificate {
  id: string
  name: string
  type: 'ca' | 'server' | 'client'
  subject: string
  issuer: string
  validFrom: string
  validTo: string
  serialNumber: string
  algorithm: string
  status: 'valid' | 'expired' | 'revoked' | 'expiring'
}

interface CreateCertificateRequest {
  name: string
  type: 'ca' | 'server' | 'client'
  commonName: string
  organization?: string
  country?: string
  keySize: number
  validityDays: number
  email?: string
}

class ApiClient {
  private baseURL: string
  private token: string | null = null

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL
    this.token = localStorage.getItem('auth_token')
  }

  setToken(token: string) {
    this.token = token
    localStorage.setItem('auth_token', token)
  }

  clearToken() {
    this.token = null
    localStorage.removeItem('auth_token')
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    const url = `${this.baseURL}${endpoint}`
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    }

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers,
      })

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }

      const data = await response.json()
      return data
    } catch (error) {
      console.error('API request failed:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error',
      }
    }
  }

  // Authentication
  async login(username: string, password: string): Promise<ApiResponse<{ token: string; user: User }>> {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    })
  }

  async logout(): Promise<ApiResponse> {
    const result = await this.request('/auth/logout', {
      method: 'POST',
    })
    this.clearToken()
    return result
  }

  // Server status
  async getStatus(): Promise<ApiResponse<ServerStatus>> {
    return this.request('/status')
  }

  // User management
  async getUsers(): Promise<ApiResponse<User[]>> {
    return this.request('/users')
  }

  async getUser(id: string): Promise<ApiResponse<User>> {
    return this.request(`/users/${id}`)
  }

  async createUser(userData: CreateUserRequest): Promise<ApiResponse<User>> {
    return this.request('/users', {
      method: 'POST',
      body: JSON.stringify(userData),
    })
  }

  async updateUser(id: string, userData: UpdateUserRequest): Promise<ApiResponse<User>> {
    return this.request(`/users/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(userData),
    })
  }

  async deleteUser(id: string): Promise<ApiResponse> {
    return this.request(`/users/${id}`, {
      method: 'DELETE',
    })
  }

  // Client connections
  async getConnections(): Promise<ApiResponse<ConnectionInfo[]>> {
    return this.request('/clients')
  }

  async disconnectClient(id: string): Promise<ApiResponse> {
    return this.request(`/clients/${id}/disconnect`, {
      method: 'POST',
    })
  }

  // Certificate management
  async getCertificates(): Promise<ApiResponse<Certificate[]>> {
    return this.request('/certificates')
  }

  async getCertificate(id: string): Promise<ApiResponse<Certificate>> {
    return this.request(`/certificates/${id}`)
  }

  async createCertificate(certData: CreateCertificateRequest): Promise<ApiResponse<Certificate>> {
    return this.request('/certificates', {
      method: 'POST',
      body: JSON.stringify(certData),
    })
  }

  async revokeCertificate(id: string): Promise<ApiResponse> {
    return this.request(`/certificates/${id}/revoke`, {
      method: 'POST',
    })
  }

  async deleteCertificate(id: string): Promise<ApiResponse> {
    return this.request(`/certificates/${id}`, {
      method: 'DELETE',
    })
  }

  // Configuration
  async getConfig(): Promise<ApiResponse<any>> {
    return this.request('/config')
  }

  async updateConfig(config: any): Promise<ApiResponse> {
    return this.request('/config/update', {
      method: 'POST',
      body: JSON.stringify(config),
    })
  }

  // Logs
  async getLogs(params?: {
    level?: string
    component?: string
    dateFrom?: string
    dateTo?: string
    limit?: number
  }): Promise<ApiResponse<any[]>> {
    const searchParams = new URLSearchParams()
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.append(key, value.toString())
        }
      })
    }
    
    const endpoint = searchParams.toString() 
      ? `/logs?${searchParams.toString()}`
      : '/logs'
    
    return this.request(endpoint)
  }
}

// Create singleton instance
export const apiClient = new ApiClient()

// Export types for use in components
export type {
  ApiResponse,
  User,
  CreateUserRequest,
  UpdateUserRequest,
  ConnectionInfo,
  ServerStatus,
  Certificate,
  CreateCertificateRequest,
}

export default ApiClient 