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
  Language as LanguageIcon,
} from '@mui/icons-material'

const languages = [
  { code: 'en', nameKey: 'en', flag: '🇺🇸' },
  { code: 'ru', nameKey: 'ru', flag: '🇷🇺' },
] as const

type Language = typeof languages[number]

export default function LanguageSwitcher() {
  const { i18n, t } = useTranslation()
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null)

  const handleClick = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget)
  }

  const handleClose = () => {
    setAnchorEl(null)
  }

  const handleLanguageChange = (languageCode: string) => {
    i18n.changeLanguage(languageCode)
    handleClose()
  }

  const currentLanguage: Language = languages.find(lang => lang.code === i18n.language) ?? languages[0]

  return (
    <>
      <Tooltip title={t('common.changeLanguage')}>
        <IconButton
          color="inherit"
          onClick={handleClick}
          sx={{ display: 'flex', alignItems: 'center', gap: 1 }}
        >
          <span style={{ fontSize: '1.2em' }}>{currentLanguage.flag}</span>
          <LanguageIcon />
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
        {languages.map((language) => (
          <MenuItem
            key={language.code}
            onClick={() => handleLanguageChange(language.code)}
            selected={language.code === i18n.language}
          >
            <ListItemIcon>
              <span style={{ fontSize: '1.2em' }}>{language.flag}</span>
            </ListItemIcon>
            <ListItemText primary={t(`settings.languages.${language.nameKey}`)} />
          </MenuItem>
        ))}
      </Menu>
    </>
  )
} 