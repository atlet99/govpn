import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { useNavigate } from 'react-router-dom'
import type { LoginCredentials, User } from '@/types'

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
          // In a real application, there would be a request to verify the token
          // const userData = await authService.getProfile()
          // setUser(userData.data)
          
          // Temporarily set mock user
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
        setUser(data)
        navigate('/dashboard')
        return
      }
      
      // Normal authentication by username/password
      const credentials = data as LoginCredentials
      if (credentials.username === 'admin' && credentials.password === 'admin123') {
        const mockToken = 'mock-jwt-token-' + Date.now()
        localStorage.setItem('token', mockToken)
        
        const mockUser: User = {
          id: '1',
          username: credentials.username,
          email: 'admin@govpn.com',
          role: 'admin',
          status: 'active',
          lastLogin: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        }
        
        setUser(mockUser)
        navigate('/dashboard')
      } else {
        throw new Error('Invalid credentials')
      }
      
      // In a real application:
      // const response = await authService.login(credentials)
      // localStorage.setItem('token', response.data.token)
      // const userData = await authService.getProfile()
      // setUser(userData.data)
      // navigate('/dashboard')
    } catch (error) {
      console.error('Login failed:', error)
      throw error
    } finally {
      setIsLoading(false)
    }
  }

  const logout = () => {
    localStorage.removeItem('token')
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