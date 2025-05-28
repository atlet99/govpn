import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  TextField,
  Button,
  Switch,
  FormControlLabel,
  Tabs,
  Tab,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Divider,
  Alert,
  Snackbar,
  CircularProgress,
} from '@mui/material'
import {
  Settings as SettingsIcon,
  NetworkCheck as NetworkIcon,
  Security as SecurityIcon,
  Extension as IntegrationIcon,
  Backup as BackupIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  CheckCircle as CheckCircleIcon,
} from '@mui/icons-material'
import { useTheme } from '@/contexts/ThemeContext'
import { useSettings } from '@/contexts/SettingsContext'

interface TabPanelProps {
  children?: React.ReactNode
  index: number
  value: number
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`settings-tabpanel-${index}`}
      aria-labelledby={`settings-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  )
}

export default function Settings() {
  const { t } = useTranslation()
  const { mode, setMode } = useTheme()
  const { 
    settings, 
    updateSetting, 
    saveSettings, 
    exportSettings, 
    importSettings, 
    isLoading, 
    lastSaved 
  } = useSettings()
  
  const [tabValue, setTabValue] = useState(0)
  const [saveSuccess, setSaveSuccess] = useState(false)
  const [saveError, setSaveError] = useState(false)

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleThemeChange = (newTheme: string) => {
    setMode(newTheme as 'light' | 'dark' | 'auto' | 'soft-light')
    updateSetting('theme', newTheme as 'light' | 'dark' | 'auto' | 'soft-light')
  }

  const handleSaveSettings = async () => {
    const success = await saveSettings()
    if (success) {
      setSaveSuccess(true)
    } else {
      setSaveError(true)
    }
  }

  const handleImportSettings = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (e) => {
        try {
          const importedSettings = JSON.parse(e.target?.result as string)
          importSettings(importedSettings)
          // Update theme immediately if imported
          if (importedSettings.theme) {
            setMode(importedSettings.theme)
          }
        } catch (error) {
          console.error('Error importing settings:', error)
          setSaveError(true)
        }
      }
      reader.readAsText(file)
    }
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('settings.title')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => window.location.reload()}
          >
            {t('common.refresh')}
          </Button>
          <Button
            variant="contained"
            startIcon={isLoading ? <CircularProgress size={20} /> : <SaveIcon />}
            onClick={handleSaveSettings}
            disabled={isLoading}
          >
            {t('common.save')}
          </Button>
        </Box>
      </Box>

      {lastSaved && (
        <Alert severity="info" sx={{ mb: 2 }}>
          {t('common.lastSaved')}: {lastSaved.toLocaleString()}
        </Alert>
      )}

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label={t('settings.networkSettings')} icon={<NetworkIcon />} />
          <Tab label={t('settings.securitySettings')} icon={<SecurityIcon />} />
          <Tab label={t('settings.systemParameters')} icon={<SettingsIcon />} />
          <Tab label={t('settings.integrations')} icon={<IntegrationIcon />} />
          <Tab label={t('settings.backup')} icon={<BackupIcon />} />
        </Tabs>
      </Box>

      {/* Network settings */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {t('settings.networkSettings')}
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField
                    label={t('settings.ipRange')}
                    value={settings.ipRange}
                    onChange={(e) => updateSetting('ipRange', e.target.value)}
                    fullWidth
                  />
                  <TextField
                    label={t('settings.dnsServers')}
                    value={settings.dnsServers}
                    onChange={(e) => updateSetting('dnsServers', e.target.value)}
                    fullWidth
                    helperText={t('settings.dnsServersHelper')}
                  />
                  <TextField
                    label={t('settings.maxConnections')}
                    type="number"
                    value={settings.maxConnections}
                    onChange={(e) => updateSetting('maxConnections', parseInt(e.target.value))}
                    fullWidth
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {t('settings.language')} & {t('settings.theme')}
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <FormControl fullWidth>
                    <InputLabel>{t('settings.language')}</InputLabel>
                    <Select
                      value={settings.language}
                      label={t('settings.language')}
                      onChange={(e) => updateSetting('language', e.target.value)}
                    >
                      <MenuItem value="en">🇺🇸 {t('settings.languages.en')}</MenuItem>
                      <MenuItem value="ru">🇷🇺 {t('settings.languages.ru')}</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl fullWidth>
                    <InputLabel>{t('settings.theme')}</InputLabel>
                    <Select
                      value={mode}
                      label={t('settings.theme')}
                      onChange={(e) => handleThemeChange(e.target.value as string)}
                    >
                      <MenuItem value="light">{t('settings.themes.light')}</MenuItem>
                      <MenuItem value="dark">{t('settings.themes.dark')}</MenuItem>
                      <MenuItem value="auto">{t('settings.themes.auto')}</MenuItem>
                      <MenuItem value="soft-light">{t('settings.themes.soft-light')}</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.notifications}
                        onChange={(e) => updateSetting('notifications', e.target.checked)}
                      />
                    }
                    label={t('settings.notifications')}
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Security settings */}
      <TabPanel value={tabValue} index={1}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {t('settings.encryptionAlgorithm')}
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <FormControl fullWidth>
                    <InputLabel>{t('settings.encryptionAlgorithm')}</InputLabel>
                    <Select
                      value={settings.encryptionAlgorithm}
                      label={t('settings.encryptionAlgorithm')}
                      onChange={(e) => updateSetting('encryptionAlgorithm', e.target.value)}
                    >
                      <MenuItem value="AES-256-GCM">{t('settings.encryptionAlgorithms.aes256gcm')}</MenuItem>
                      <MenuItem value="AES-128-GCM">{t('settings.encryptionAlgorithms.aes128gcm')}</MenuItem>
                      <MenuItem value="ChaCha20-Poly1305">{t('settings.encryptionAlgorithms.chacha20poly1305')}</MenuItem>
                    </Select>
                  </FormControl>
                  <FormControl fullWidth>
                    <InputLabel>{t('settings.keyExchangeMethod')}</InputLabel>
                    <Select
                      value={settings.keyExchangeMethod}
                      label={t('settings.keyExchangeMethod')}
                      onChange={(e) => updateSetting('keyExchangeMethod', e.target.value)}
                    >
                      <MenuItem value="ECDH">{t('settings.keyExchangeMethods.ecdh')}</MenuItem>
                      <MenuItem value="RSA">{t('settings.keyExchangeMethods.rsa')}</MenuItem>
                      <MenuItem value="DH">{t('settings.keyExchangeMethods.dh')}</MenuItem>
                    </Select>
                  </FormControl>
                  <TextField
                    label={t('settings.sessionTimeoutHours')}
                    type="number"
                    value={settings.sessionTimeout}
                    onChange={(e) => updateSetting('sessionTimeout', parseInt(e.target.value))}
                    fullWidth
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* System parameters */}
      <TabPanel value={tabValue} index={2}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {t('settings.logging')}
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <FormControl fullWidth>
                    <InputLabel>{t('settings.logLevel')}</InputLabel>
                    <Select
                      value={settings.logLevel}
                      label={t('settings.logLevel')}
                      onChange={(e) => updateSetting('logLevel', e.target.value)}
                    >
                      <MenuItem value="debug">{t('settings.logLevels.debug')}</MenuItem>
                      <MenuItem value="info">{t('settings.logLevels.info')}</MenuItem>
                      <MenuItem value="warning">{t('settings.logLevels.warning')}</MenuItem>
                      <MenuItem value="error">{t('settings.logLevels.error')}</MenuItem>
                    </Select>
                  </FormControl>
                  <TextField
                    label={t('settings.logRetentionDays')}
                    type="number"
                    value={settings.logRetentionDays}
                    onChange={(e) => updateSetting('logRetentionDays', parseInt(e.target.value))}
                    fullWidth
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Integrations */}
      <TabPanel value={tabValue} index={3}>
        <Alert severity="info" sx={{ mb: 3 }}>
          {t('settings.integrationsNotice')}
        </Alert>
      </TabPanel>

      {/* Backup and restore */}
      <TabPanel value={tabValue} index={4}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {t('settings.backupConfiguration')}
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={settings.backupEnabled}
                        onChange={(e) => updateSetting('backupEnabled', e.target.checked)}
                      />
                    }
                    label={t('settings.automaticBackup')}
                  />
                  <Divider />
                  <Button
                    variant="outlined"
                    onClick={exportSettings}
                    fullWidth
                  >
                    {t('settings.exportSettings')}
                  </Button>
                  <Button
                    variant="outlined"
                    component="label"
                    fullWidth
                  >
                    {t('settings.importSettings')}
                    <input
                      type="file"
                      hidden
                      accept=".json"
                      onChange={handleImportSettings}
                    />
                  </Button>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* Success/Error snackbars */}
      <Snackbar
        open={saveSuccess}
        autoHideDuration={3000}
        onClose={() => setSaveSuccess(false)}
      >
        <Alert severity="success" sx={{ width: '100%' }} icon={<CheckCircleIcon />}>
          {t('common.saveSuccess', 'Settings saved successfully!')}
        </Alert>
      </Snackbar>

      <Snackbar
        open={saveError}
        autoHideDuration={5000}
        onClose={() => setSaveError(false)}
      >
        <Alert severity="error" sx={{ width: '100%' }}>
          {t('common.saveError', 'Failed to save settings. Please try again.')}
        </Alert>
      </Snackbar>
    </Box>
  )
} 