import { Routes, Route, Navigate } from 'react-router-dom'
import { ThemeProvider } from '@mui/material/styles'
import { CssBaseline } from '@mui/material'
import { AuthProvider } from '@/contexts/AuthContext'
import { AppThemeProvider, useTheme } from '@/contexts/ThemeContext'
import { SettingsProvider } from '@/contexts/SettingsContext'
import Login from '@/pages/Login'
import Dashboard from '@/pages/Dashboard'
import Users from '@/pages/Users'
import Settings from '@/pages/Settings'
import Obfuscation from '@/pages/Obfuscation'
import Authentication from '@/pages/Authentication'
import Certificates from '@/pages/Certificates'
import Logs from '@/pages/Logs'
import Network from '@/pages/Network'
import MainLayout from '@/layouts/MainLayout'
import ProtectedRoute from '@/components/ProtectedRoute'

function AppContent() {
  const { theme } = useTheme()
  
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route
            path="/"
            element={
              <ProtectedRoute>
                <MainLayout />
              </ProtectedRoute>
            }
          >
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="users" element={<Users />} />
            <Route path="obfuscation" element={<Obfuscation />} />
            <Route path="authentication" element={<Authentication />} />
            <Route path="settings" element={<Settings />} />
            <Route path="certificates" element={<Certificates />} />
            <Route path="logs" element={<Logs />} />
            <Route path="network" element={<Network />} />
          </Route>
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthProvider>
    </ThemeProvider>
  )
}

export default function App() {
  return (
    <SettingsProvider>
      <AppThemeProvider>
        <AppContent />
      </AppThemeProvider>
    </SettingsProvider>
  )
} 