import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import type { LoginCredentials, User } from '@/types'
import { apiClient } from '@/services/api'

interface AuthContextType {
  user: User | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (credentials: LoginCredentials | User) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextType | null>(null)

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const navigate = useNavigate()
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const isAuthenticated = !!user

  useEffect(() => {
    const initAuth = async () => {
      try {
        const token = localStorage.getItem('token')
        if (token) {
          apiClient.setToken(token)
          // TODO: Verify token with real API call when implemented
          // const userData = await apiClient.getProfile()
          // setUser(userData.data)
          
          // Temporarily keep mock user for now
          setUser({
            id: '1',
            username: 'admin',
            email: 'admin@govpn.com',
            role: 'admin',
            status: 'active',
            lastLogin: new Date().toISOString(),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          })
        }
      } catch (error) {
        console.error('Auth initialization failed:', error)
        localStorage.removeItem('token')
      } finally {
        setIsLoading(false)
      }
    }

    initAuth()
  }, [])

  const login = async (data: LoginCredentials | User) => {
    try {
      setIsLoading(true)
      
      // If user object is passed directly (for simplification)
      if ('id' in data) {
        const mockToken = 'mock-jwt-token-' + Date.now()
        localStorage.setItem('token', mockToken)
        apiClient.setToken(mockToken)
        setUser(data)
        navigate('/dashboard')
        return
      }
      
      // Normal authentication via API
      const credentials = data as LoginCredentials
      const response = await apiClient.login(credentials.username, credentials.password)
      
      if (response.success && response.data) {
        localStorage.setItem('token', response.data.token)
        apiClient.setToken(response.data.token)
        setUser(response.data.user)
        navigate('/dashboard')
      } else {
        throw new Error(response.error || 'Login failed')
      }
    } catch (error) {
      console.error('Login failed:', error)
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const logout = () => {
    localStorage.removeItem('token')
    apiClient.clearToken()
    setUser(null)
    navigate('/login')
  }

  const value: AuthContextType = {
    user,
    isAuthenticated,
    isLoading,
    login,
    logout,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
} 