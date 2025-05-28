import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Switch,
  FormControlLabel,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Button,
  Alert,
  LinearProgress,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  Slider,
  TextField,
  Tooltip,
  IconButton,
  Snackbar,
  CircularProgress,
} from '@mui/material'
import {
  ExpandMore as ExpandMoreIcon,
  Security as SecurityIcon,
  NetworkCheck as NetworkIcon,
  Settings as SettingsIcon,
  CheckCircle as CheckCircleIcon,
  Warning as WarningIcon,
  Info as InfoIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material'

interface ObfuscationMethod {
  id: string
  nameKey: string
  descriptionKey: string
  enabled: boolean
  effectiveness: number
  performance: number
  region: string[]
  status: 'active' | 'standby' | 'disabled'
}

interface RegionProfile {
  id: string
  nameKey: string
  country: string
  methods: string[]
  dpiLevel: 'low' | 'medium' | 'high' | 'extreme'
  autoSwitch: boolean
}

export default function Obfuscation() {
  const { t } = useTranslation()
  const [globalEnabled, setGlobalEnabled] = useState(true)
  const [autoDetection, setAutoDetection] = useState(true)
  const [selectedProfile, setSelectedProfile] = useState('auto')
  const [isLoading, setIsLoading] = useState(false)
  const [saveSuccess, setSaveSuccess] = useState(false)
  const [saveError, setSaveError] = useState(false)
  
  const [methods, setMethods] = useState<ObfuscationMethod[]>([
    {
      id: 'tls_tunnel',
      nameKey: 'tlsTunnel',
      descriptionKey: 'tlsTunnel',
      enabled: true,
      effectiveness: 95,
      performance: 85,
      region: ['CN', 'IR', 'RU'],
      status: 'active',
    },
    {
      id: 'http_mimicry',
      nameKey: 'httpMimicry',
      descriptionKey: 'httpMimicry',
      enabled: true,
      effectiveness: 88,
      performance: 92,
      region: ['CN', 'IR'],
      status: 'standby',
    },
    {
      id: 'dns_tunnel',
      nameKey: 'dnsTunnel',
      descriptionKey: 'dnsTunnel',
      enabled: false,
      effectiveness: 75,
      performance: 45,
      region: ['CN', 'IR', 'RU', 'TR'],
      status: 'disabled',
    },
    {
      id: 'xor_cipher',
      nameKey: 'xorCipher',
      descriptionKey: 'xorCipher',
      enabled: true,
      effectiveness: 70,
      performance: 98,
      region: ['ALL'],
      status: 'active',
    },
    {
      id: 'packet_padding',
      nameKey: 'packetPadding',
      descriptionKey: 'packetPadding',
      enabled: false,
      effectiveness: 70,
      performance: 85,
      region: ['China', 'Iran'],
      status: 'disabled',
    },
    {
      id: 'timing_obfs',
      nameKey: 'timingObfs',
      descriptionKey: 'timingObfs',
      enabled: false,
      effectiveness: 78,
      performance: 75,
      region: ['ALL'],
      status: 'disabled',
    },
  ])

  const [profiles, _setProfiles] = useState<RegionProfile[]>([
    {
      id: 'china',
      nameKey: 'china',
      country: 'CN',
      methods: ['tls_tunnel', 'http_mimicry', 'packet_padding'],
      dpiLevel: 'extreme',
      autoSwitch: true,
    },
    {
      id: 'iran',
      nameKey: 'iran',
      country: 'IR',
      methods: ['tls_tunnel', 'dns_tunnel', 'xor_cipher'],
      dpiLevel: 'high',
      autoSwitch: true,
    },
    {
      id: 'russia',
      nameKey: 'russia',
      country: 'RU',
      methods: ['tls_tunnel', 'packet_padding'],
      dpiLevel: 'medium',
      autoSwitch: false,
    },
  ])

  const [advancedSettings, setAdvancedSettings] = useState({
    packetPaddingSize: 128,
    timingVariation: 50,
    tlsHandshakeDelay: 100,
    httpUserAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    dnsServer: '8.8.8.8',
    autoSwitchThreshold: 3,
  })

  const handleMethodToggle = (methodId: string) => {
    setMethods(methods.map(method => 
      method.id === methodId 
        ? { ...method, enabled: !method.enabled, status: !method.enabled ? 'active' : 'disabled' }
        : method
    ))
  }

  const handleSaveSettings = async () => {
    setIsLoading(true)
    try {
      // Save obfuscation settings to localStorage
      const obfuscationSettings = {
        globalEnabled,
        autoDetection,
        selectedProfile,
        methods,
        profiles,
        advancedSettings,
        lastUpdated: new Date().toISOString()
      }
      
      localStorage.setItem('govpn-obfuscation-settings', JSON.stringify(obfuscationSettings))
      
      // Simulate API call delay
      await new Promise(resolve => setTimeout(resolve, 1000))
      
      // TODO: Replace with actual API call
      // const response = await fetch('/api/obfuscation/settings', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(obfuscationSettings)
      // })
      // if (!response.ok) throw new Error('Failed to save obfuscation settings')
      
      setSaveSuccess(true)
    } catch (error) {
      console.error('Failed to save obfuscation settings:', error)
      setSaveError(true)
    } finally {
      setIsLoading(false)
    }
  }

  const getDpiLevelColor = (level: string) => {
    switch (level) {
      case 'low': return 'success'
      case 'medium': return 'warning'
      case 'high': return 'error'
      case 'extreme': return 'error'
      default: return 'default'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircleIcon color="success" />
      case 'standby': return <WarningIcon color="warning" />
      case 'disabled': return <WarningIcon color="disabled" />
      default: return <InfoIcon />
    }
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('obfuscation.title')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => console.log('Refreshing...')}
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

      {/* Global settings */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SettingsIcon />
            {t('obfuscation.globalSettings')}
          </Typography>
          <Grid container spacing={3}>
            <Grid item xs={12} md={4}>
              <FormControlLabel
                control={
                  <Switch
                    checked={globalEnabled}
                    onChange={(e) => setGlobalEnabled(e.target.checked)}
                    color="primary"
                  />
                }
                label={t('obfuscation.enableObfuscation')}
              />
            </Grid>
            <Grid item xs={12} md={4}>
              <FormControlLabel
                control={
                  <Switch
                    checked={autoDetection}
                    onChange={(e) => setAutoDetection(e.target.checked)}
                    color="primary"
                  />
                }
                label={t('obfuscation.autoDetectDPI')}
              />
            </Grid>
            <Grid item xs={12} md={4}>
              <FormControl fullWidth>
                <InputLabel>{t('obfuscation.regionalProfile')}</InputLabel>
                <Select
                  value={selectedProfile}
                  label={t('obfuscation.regionalProfile')}
                  onChange={(e) => setSelectedProfile(e.target.value)}
                >
                  <MenuItem value="auto">{t('obfuscation.autoSelect')}</MenuItem>
                  {profiles.map((profile) => (
                    <MenuItem key={profile.id} value={profile.id}>
                      {t(`obfuscation.regions.${profile.nameKey}`)} ({profile.country})
                    </MenuItem>
                  ))}
                </Select>
              </FormControl>
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      {/* Obfuscation status */}
      {!globalEnabled && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          {t('obfuscation.disabledWarning')}
        </Alert>
      )}

      {/* Obfuscation methods */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <SecurityIcon />
            {t('obfuscation.methodsColumn')}
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('obfuscation.method')}</TableCell>
                  <TableCell>{t('obfuscation.description')}</TableCell>
                  <TableCell>{t('obfuscation.effectiveness')}</TableCell>
                  <TableCell>{t('obfuscation.performance')}</TableCell>
                  <TableCell>{t('obfuscation.regionsColumn')}</TableCell>
                  <TableCell>{t('common.status')}</TableCell>
                  <TableCell>{t('obfuscation.enabled')}</TableCell>
                  <TableCell>{t('common.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {methods.map((method) => (
                  <TableRow key={method.id}>
                    <TableCell>
                      <Typography variant="subtitle2">{t(`obfuscation.methodNames.${method.nameKey}`)}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" color="text.secondary">
                        {t(`obfuscation.methodDescriptions.${method.descriptionKey}`)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LinearProgress
                          variant="determinate"
                          value={method.effectiveness}
                          sx={{ width: 60, height: 8, borderRadius: 4 }}
                          color={method.effectiveness > 80 ? 'success' : method.effectiveness > 60 ? 'warning' : 'error'}
                        />
                        <Typography variant="body2">{method.effectiveness}%</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <LinearProgress
                          variant="determinate"
                          value={method.performance}
                          sx={{ width: 60, height: 8, borderRadius: 4 }}
                          color={method.performance > 80 ? 'success' : method.performance > 60 ? 'warning' : 'error'}
                        />
                        <Typography variant="body2">{method.performance}%</Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {method.region.map((region) => (
                          <Chip
                            key={region}
                            label={region}
                            size="small"
                            variant="outlined"
                          />
                        ))}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {getStatusIcon(method.status)}
                        <Typography variant="body2" textTransform="capitalize">
                          {t(`obfuscation.status.${method.status}`)}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Switch
                        checked={method.enabled}
                        onChange={() => handleMethodToggle(method.id)}
                        disabled={!globalEnabled}
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={t('obfuscation.methodSettings')}>
                        <IconButton size="small" color="primary">
                          <SettingsIcon />
                        </IconButton>
                      </Tooltip>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        </CardContent>
      </Card>

      {/* Regional profiles */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <NetworkIcon />
            {t('obfuscation.regionalProfiles')}
          </Typography>
          <Grid container spacing={2}>
            {profiles.map((profile) => (
              <Grid item xs={12} md={4} key={profile.id}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Typography variant="h6" gutterBottom>
                      {t(`obfuscation.regions.${profile.nameKey}`)}
                    </Typography>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        {t('obfuscation.dpiLevel')}:
                      </Typography>
                      <Chip
                        label={t(`obfuscation.dpiLevels.${profile.dpiLevel}`)}
                        color={getDpiLevelColor(profile.dpiLevel) as any}
                        size="small"
                      />
                    </Box>
                    <Box sx={{ mb: 2 }}>
                      <Typography variant="body2" color="text.secondary" gutterBottom>
                        {t('obfuscation.methodsColumn')}:
                      </Typography>
                      <Box sx={{ display: 'flex', gap: 0.5, flexWrap: 'wrap' }}>
                        {profile.methods.map((methodId) => {
                          const method = methods.find(m => m.id === methodId)
                          return (
                            <Chip
                              key={methodId}
                              label={method ? t(`obfuscation.methodNames.${method.nameKey}`) : methodId}
                              size="small"
                              variant="outlined"
                              color="primary"
                            />
                          )
                        })}
                      </Box>
                    </Box>
                    <FormControlLabel
                      control={
                        <Switch
                          checked={profile.autoSwitch}
                          size="small"
                        />
                      }
                      label={t('obfuscation.autoSwitch')}
                    />
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </CardContent>
      </Card>

      {/* Advanced settings */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography variant="h6">{t('obfuscation.advancedSettings')}</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={3}>
            <Grid item xs={12} md={6}>
              <Typography gutterBottom>{t('obfuscation.packetPaddingSize')}</Typography>
              <Slider
                value={advancedSettings.packetPaddingSize}
                onChange={(_, value) => setAdvancedSettings({
                  ...advancedSettings,
                  packetPaddingSize: value as number
                })}
                min={64}
                max={512}
                step={64}
                marks
                valueLabelDisplay="auto"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <Typography gutterBottom>{t('obfuscation.timingVariation')}</Typography>
              <Slider
                value={advancedSettings.timingVariation}
                onChange={(_, value) => setAdvancedSettings({
                  ...advancedSettings,
                  timingVariation: value as number
                })}
                min={0}
                max={100}
                step={10}
                marks
                valueLabelDisplay="auto"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('obfuscation.httpUserAgent')}
                value={advancedSettings.httpUserAgent}
                onChange={(e) => setAdvancedSettings({
                  ...advancedSettings,
                  httpUserAgent: e.target.value
                })}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('obfuscation.dnsServer')}
                value={advancedSettings.dnsServer}
                onChange={(e) => setAdvancedSettings({
                  ...advancedSettings,
                  dnsServer: e.target.value
                })}
              />
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Success/Error snackbars */}
      <Snackbar
        open={saveSuccess}
        autoHideDuration={3000}
        onClose={() => setSaveSuccess(false)}
      >
        <Alert severity="success" sx={{ width: '100%' }} icon={<CheckCircleIcon />}>
          {t('common.saveSuccess', 'Obfuscation settings saved successfully!')}
        </Alert>
      </Snackbar>

      <Snackbar
        open={saveError}
        autoHideDuration={5000}
        onClose={() => setSaveError(false)}
      >
        <Alert severity="error" sx={{ width: '100%' }}>
          {t('common.saveError', 'Failed to save obfuscation settings. Please try again.')}
        </Alert>
      </Snackbar>
    </Box>
  )
} 