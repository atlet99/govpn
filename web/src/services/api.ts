import axios from 'axios'
import { ApiResponse, LoginCredentials, SystemSettings, SystemStats, User } from '../types'

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Add request interceptor for authentication
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Add response interceptor for error handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

export const authService = {
  login: async (credentials: LoginCredentials): Promise<ApiResponse<{ token: string }>> => {
    const response = await api.post<ApiResponse<{ token: string }>>('/auth/login', credentials)
    return response.data
  },

  logout: () => {
    localStorage.removeItem('token')
    window.location.href = '/login'
  },
}

export const userService = {
  getUsers: async (): Promise<ApiResponse<User[]>> => {
    const response = await api.get<ApiResponse<User[]>>('/users')
    return response.data
  },

  createUser: async (user: Omit<User, 'id' | 'createdAt' | 'updatedAt'>): Promise<ApiResponse<User>> => {
    const response = await api.post<ApiResponse<User>>('/users', user)
    return response.data
  },

  updateUser: async (id: string, user: Partial<User>): Promise<ApiResponse<User>> => {
    const response = await api.put<ApiResponse<User>>(`/users/${id}`, user)
    return response.data
  },

  deleteUser: async (id: string): Promise<ApiResponse<void>> => {
    const response = await api.delete<ApiResponse<void>>(`/users/${id}`)
    return response.data
  },
}

export const systemService = {
  getStats: async (): Promise<ApiResponse<SystemStats>> => {
    const response = await api.get<ApiResponse<SystemStats>>('/system/stats')
    return response.data
  },

  getSettings: async (): Promise<ApiResponse<SystemSettings>> => {
    const response = await api.get<ApiResponse<SystemSettings>>('/system/settings')
    return response.data
  },

  updateSettings: async (settings: Partial<SystemSettings>): Promise<ApiResponse<SystemSettings>> => {
    const response = await api.put<ApiResponse<SystemSettings>>('/system/settings', settings)
    return response.data
  },
} 