import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  IconButton,
  Menu,
  MenuItem,
  ListItemIcon,
  ListItemText,
  Tooltip,
} from '@mui/material'
import {
  LightMode as LightModeIcon,
  DarkMode as DarkModeIcon,
  SettingsBrightness as AutoModeIcon,
  Brightness6 as Brightness6Icon,
} from '@mui/icons-material'
import { useTheme } from '@/contexts/ThemeContext'

const themeOptions = [
  { 
    value: 'light', 
    icon: <LightModeIcon />, 
    labelKey: 'light' 
  },
  { 
    value: 'dark', 
    icon: <DarkModeIcon />, 
    labelKey: 'dark' 
  },
  { 
    value: 'soft-light', 
    icon: <Brightness6Icon />, 
    labelKey: 'soft-light' 
  },
  { 
    value: 'auto', 
    icon: <AutoModeIcon />, 
    labelKey: 'auto' 
  },
] as const

export default function ThemeSwitcher() {
  const { t } = useTranslation()
  const { mode, setMode } = useTheme()
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null)

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget)
  }

  const handleClose = () => {
    setAnchorEl(null)
  }

  const handleThemeChange = (themeMode: typeof mode) => {
    setMode(themeMode)
    handleClose()
  }

  const currentTheme = themeOptions.find(theme => theme.value === mode) ?? themeOptions[1]

  return (
    <>
      <Tooltip title={t('common.changeTheme')}>
        <IconButton
          color="inherit"
          onClick={handleClick}
          sx={{ 
            display: 'flex', 
            alignItems: 'center', 
            gap: 1,
            '& .MuiSvgIcon-root': {
              fontSize: '1.2rem'
            }
          }}
        >
          {currentTheme.icon}
        </IconButton>
      </Tooltip>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
      >
        {themeOptions.map((theme) => (
          <MenuItem
            key={theme.value}
            onClick={() => handleThemeChange(theme.value)}
            selected={theme.value === mode}
          >
            <ListItemIcon>
              {theme.icon}
            </ListItemIcon>
            <ListItemText primary={t(`settings.themes.${theme.labelKey}`)} />
          </MenuItem>
        ))}
      </Menu>
    </>
  )
} 