import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

export interface AppSettings {
  // Network settings
  ipRange: string
  dnsServers: string
  maxConnections: number
  
  // Security settings
  encryptionAlgorithm: string
  keyExchangeMethod: string
  sessionTimeout: number
  
  // System parameters
  logLevel: string
  logRetentionDays: number
  backupEnabled: boolean
  
  // Interface settings
  language: string
  theme: 'light' | 'dark' | 'auto' | 'soft-light'
  notifications: boolean
}

interface SettingsContextType {
  settings: AppSettings
  updateSetting: <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => void
  saveSettings: () => Promise<boolean>
  resetSettings: () => void
  exportSettings: () => void
  importSettings: (settingsData: Partial<AppSettings>) => void
  isLoading: boolean
  lastSaved: Date | null
}

const defaultSettings: AppSettings = {
  ipRange: '10.8.0.0/24',
  dnsServers: '8.8.8.8, 1.1.1.1',
  maxConnections: 100,
  encryptionAlgorithm: 'AES-256-GCM',
  keyExchangeMethod: 'ECDH',
  sessionTimeout: 24,
  logLevel: 'info',
  logRetentionDays: 30,
  backupEnabled: true,
  language: 'en',
  theme: 'auto',
  notifications: true,
}

const SettingsContext = createContext<SettingsContextType | undefined>(undefined)

interface SettingsProviderProps {
  children: ReactNode
}

export function SettingsProvider({ children }: SettingsProviderProps) {
  const { i18n } = useTranslation()
  const [settings, setSettings] = useState<AppSettings>(() => {
    try {
      const savedSettings = localStorage.getItem('govpn-settings')
      if (savedSettings) {
        const parsed = JSON.parse(savedSettings)
        return { ...defaultSettings, ...parsed }
      }
    } catch (error) {
      console.error('Failed to load settings from localStorage:', error)
    }
    return defaultSettings
  })
  
  const [isLoading, setIsLoading] = useState(false)
  const [lastSaved, setLastSaved] = useState<Date | null>(() => {
    const timestamp = localStorage.getItem('govpn-settings-timestamp')
    return timestamp ? new Date(timestamp) : null
  })

  // Update i18n language when settings change
  useEffect(() => {
    if (settings.language !== i18n.language) {
      i18n.changeLanguage(settings.language)
    }
  }, [settings.language, i18n])

  const updateSetting = <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }))
  }

  const saveSettings = async (): Promise<boolean> => {
    setIsLoading(true)
    try {
      // Save to localStorage
      localStorage.setItem('govpn-settings', JSON.stringify(settings))
      localStorage.setItem('govpn-settings-timestamp', new Date().toISOString())
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 800))
      
      // TODO: Replace with actual API call
      // const response = await fetch('/api/settings', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(settings)
      // })
      // if (!response.ok) throw new Error('Failed to save settings')
      
      setLastSaved(new Date())
      return true
    } catch (error) {
      console.error('Failed to save settings:', error)
      return false
    } finally {
      setIsLoading(false)
    }
  }

  const resetSettings = () => {
    setSettings(defaultSettings)
    localStorage.removeItem('govpn-settings')
    localStorage.removeItem('govpn-settings-timestamp')
    setLastSaved(null)
  }

  const exportSettings = () => {
    const dataStr = JSON.stringify(settings, null, 2)
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr)
    
    const exportFileDefaultName = `govpn-settings-${new Date().toISOString().split('T')[0]}.json`
    
    const linkElement = document.createElement('a')
    linkElement.setAttribute('href', dataUri)
    linkElement.setAttribute('download', exportFileDefaultName)
    linkElement.click()
  }

  const importSettings = (settingsData: Partial<AppSettings>) => {
    setSettings(prev => ({
      ...prev,
      ...settingsData
    }))
  }

  const contextValue: SettingsContextType = {
    settings,
    updateSetting,
    saveSettings,
    resetSettings,
    exportSettings,
    importSettings,
    isLoading,
    lastSaved,
  }

  return (
    <SettingsContext.Provider value={contextValue}>
      {children}
    </SettingsContext.Provider>
  )
}

export function useSettings() {
  const context = useContext(SettingsContext)
  if (!context) {
    throw new Error('useSettings must be used within SettingsProvider')
  }
  return context
} 