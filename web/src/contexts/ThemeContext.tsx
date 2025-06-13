import { createContext, useContext, useState, useEffect, ReactNode } from 'react'
import { createTheme, Theme } from '@mui/material/styles'
import { useMediaQuery } from '@mui/material'

type ThemeMode = 'light' | 'dark' | 'auto' | 'soft-light'

interface ThemeContextType {
  mode: ThemeMode
  setMode: (mode: ThemeMode) => void
  theme: Theme
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

const createAppTheme = (mode: 'light' | 'dark' | 'soft-light'): Theme => {
  const isDark = mode === 'dark'
  const isSoftLight = mode === 'soft-light'
  
  return createTheme({
    palette: {
      mode: isDark ? 'dark' : 'light',
      primary: {
        main: isDark ? '#2196f3' : isSoftLight ? '#5c7cfa' : '#1976d2',
      },
      secondary: {
        main: isDark ? '#f50057' : isSoftLight ? '#e91e63' : '#d32f2f',
      },
      background: {
        default: isDark ? '#121212' : isSoftLight ? '#f8fafb' : '#f8f9fa',
        paper: isDark ? '#1e1e1e' : '#ffffff',
      },
      text: {
        primary: isDark ? '#ffffff' : isSoftLight ? '#3c4858' : '#2c3e50',
        secondary: isDark ? '#b0b0b0' : isSoftLight ? '#607d8b' : '#546e7a',
      },
      divider: isDark ? '#333333' : isSoftLight ? '#eceff1' : '#e1e8ed',
      action: {
        hover: isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(0, 0, 0, 0.04)',
        selected: isDark ? 'rgba(255, 255, 255, 0.12)' : 'rgba(0, 0, 0, 0.08)',
      },
    },
    typography: {
      fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
      h1: {
        fontSize: '2.5rem',
        fontWeight: 500,
        color: isDark ? '#ffffff' : '#2c3e50',
      },
      h2: {
        fontSize: '2rem',
        fontWeight: 500,
        color: isDark ? '#ffffff' : '#2c3e50',
      },
      h3: {
        fontSize: '1.75rem',
        fontWeight: 500,
        color: isDark ? '#ffffff' : '#2c3e50',
      },
      h4: {
        fontSize: '1.5rem',
        fontWeight: 500,
        color: isDark ? '#ffffff' : '#34495e',
      },
      h5: {
        fontSize: '1.25rem',
        fontWeight: 500,
        color: isDark ? '#ffffff' : '#34495e',
      },
      h6: {
        fontSize: '1rem',
        fontWeight: 500,
        color: isDark ? '#ffffff' : '#34495e',
      },
    },
    components: {
      MuiButton: {
        styleOverrides: {
          root: {
            textTransform: 'none',
            borderRadius: 8,
            boxShadow: isDark ? 'none' : '0 2px 4px rgba(0,0,0,0.1)',
            '&:hover': {
              boxShadow: isDark ? 'none' : '0 4px 8px rgba(0,0,0,0.15)',
            },
          },
        },
      },
      MuiCard: {
        styleOverrides: {
          root: {
            backgroundImage: 'none',
            borderRadius: 12,
            border: isDark ? '1px solid #333333' : '1px solid #e1e8ed',
            boxShadow: isDark 
              ? '0 4px 6px rgba(0, 0, 0, 0.3)' 
              : '0 2px 8px rgba(0, 0, 0, 0.08)',
          },
        },
      },
      MuiAppBar: {
        styleOverrides: {
          root: {
            backgroundColor: isDark ? '#1e1e1e' : '#ffffff',
            color: isDark ? '#ffffff' : '#2c3e50',
            boxShadow: isDark 
              ? '0 2px 4px rgba(0, 0, 0, 0.3)' 
              : '0 2px 4px rgba(0, 0, 0, 0.08)',
          },
        },
      },
      MuiDrawer: {
        styleOverrides: {
          paper: {
            backgroundColor: isDark ? '#1a1a1a' : '#f8f9fa',
            borderRight: isDark ? '1px solid #333333' : '1px solid #e1e8ed',
          },
        },
      },
      MuiListItemButton: {
        styleOverrides: {
          root: {
            borderRadius: 8,
            margin: '2px 8px',
            '&.Mui-selected': {
              backgroundColor: isDark ? 'rgba(33, 150, 243, 0.12)' : 'rgba(25, 118, 210, 0.08)',
              '&:hover': {
                backgroundColor: isDark ? 'rgba(33, 150, 243, 0.16)' : 'rgba(25, 118, 210, 0.12)',
              },
            },
            '&:hover': {
              backgroundColor: isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.04)',
            },
          },
        },
      },
      MuiTextField: {
        styleOverrides: {
          root: {
            '& .MuiOutlinedInput-root': {
              backgroundColor: isDark ? 'rgba(255, 255, 255, 0.05)' : '#ffffff',
              '& fieldset': {
                borderColor: isDark ? '#333333' : '#d1d9e0',
              },
              '&:hover fieldset': {
                borderColor: isDark ? '#555555' : '#b0bec5',
              },
            },
          },
        },
      },
      MuiTableHead: {
        styleOverrides: {
          root: {
            backgroundColor: isDark ? '#2a2a2a' : '#f5f7fa',
          },
        },
      },
      MuiTableRow: {
        styleOverrides: {
          root: {
            '&:nth-of-type(even)': {
              backgroundColor: isDark ? 'rgba(255, 255, 255, 0.02)' : 'rgba(0, 0, 0, 0.02)',
            },
            '&:hover': {
              backgroundColor: isDark ? 'rgba(255, 255, 255, 0.05)' : 'rgba(0, 0, 0, 0.04)',
            },
          },
        },
      },
    },
  })
}

interface ThemeProviderProps {
  children: ReactNode
}

export function AppThemeProvider({ children }: ThemeProviderProps) {
  const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)')
  const [mode, setMode] = useState<ThemeMode>(() => {
    // Load user's personal theme preference from localStorage
    const savedTheme = localStorage.getItem('govpn-theme-preference') as ThemeMode
    return savedTheme || 'auto' // Default to auto theme
  })

  // Determine effective theme mode (resolve 'auto')
  const effectiveMode = mode === 'auto' ? (prefersDarkMode ? 'dark' : 'light') : mode
  const theme = createAppTheme(effectiveMode as 'light' | 'dark' | 'soft-light')

  // Save theme preference to localStorage whenever it changes
  useEffect(() => {
    localStorage.setItem('govpn-theme-preference', mode)
  }, [mode])

  const contextValue: ThemeContextType = {
    mode,
    setMode,
    theme,
  }

  return (
    <ThemeContext.Provider value={contextValue}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within AppThemeProvider')
  }
  return context
} 