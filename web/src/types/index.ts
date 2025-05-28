export interface User {
  id: string
  username: string
  email: string
  role: 'admin' | 'user'
  status: 'active' | 'inactive'
  lastLogin: string
  createdAt: string
  updatedAt: string
}

export interface SystemStats {
  activeUsers: number
  securityScore: number
  averageSpeed: number
  storageUsed: number
}

export interface SystemSettings {
  serverName: string
  maxConnections: number
  enableLogging: boolean
  logRetentionDays: number
  enableObfuscation: boolean
  obfuscationLevel: 'low' | 'medium' | 'high'
  enableSteganography: boolean
  steganographyMethod: 'lsb' | 'dct' | 'both'
}

export interface LoginCredentials {
  username: string
  password: string
}

export interface ApiResponse<T> {
  data: T
  error?: string
  message?: string
} 