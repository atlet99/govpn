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
  TextField,
  Button,
  Tabs,
  Tab,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  IconButton,
  Tooltip,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material'
import {
  Security as SecurityIcon,
  VpnKey as VpnKeyIcon,
  Group as GroupIcon,
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  Save as SaveIcon,
  Refresh as RefreshIcon,
  QrCode as QrCodeIcon,
  Key as KeyIcon,
  Shield as ShieldIcon,
} from '@mui/icons-material'

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
      id={`auth-tabpanel-${index}`}
      aria-labelledby={`auth-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  )
}

interface OIDCProvider {
  id: string
  name: string
  type: 'keycloak' | 'google' | 'azure' | 'auth0' | 'okta' | 'gitlab'
  enabled: boolean
  clientId: string
  issuerUrl: string
  status: 'active' | 'error' | 'disabled'
}

interface LDAPConfig {
  id: string
  name: string
  type: 'active_directory' | 'openldap' | 'freeipa' | '389ds' | 'oracle'
  enabled: boolean
  server: string
  port: number
  baseDN: string
  bindDN: string
  status: 'connected' | 'error' | 'disabled'
}

interface MFAUser {
  id: string
  username: string
  email: string
  mfaEnabled: boolean
  mfaMethod: 'totp' | 'hotp' | 'backup'
  backupCodes: number
  lastUsed: string
}

export default function Authentication() {
  const { t } = useTranslation()
  const [tabValue, setTabValue] = useState(0)
  const [oidcDialogOpen, setOidcDialogOpen] = useState(false)
  const [ldapDialogOpen, setLdapDialogOpen] = useState(false)
  const [qrDialogOpen, setQrDialogOpen] = useState(false)
  const [selectedUser, setSelectedUser] = useState<MFAUser | null>(null)

  const [oidcProviders, setOidcProviders] = useState<OIDCProvider[]>([
    {
      id: '1',
      name: 'Keycloak Corporate',
      type: 'keycloak',
      enabled: true,
      clientId: 'govpn-client',
      issuerUrl: 'https://auth.company.com/realms/main',
      status: 'active',
    },
    {
      id: '2',
      name: 'Google Workspace',
      type: 'google',
      enabled: false,
      clientId: 'google-client-id',
      issuerUrl: 'https://accounts.google.com',
      status: 'disabled',
    },
  ])

  const [ldapConfigs, setLdapConfigs] = useState<LDAPConfig[]>([
    {
      id: '1',
      name: 'Corporate AD',
      type: 'active_directory',
      enabled: true,
      server: 'ldap.company.com',
      port: 636,
      baseDN: 'dc=company,dc=com',
      bindDN: 'cn=govpn,ou=service,dc=company,dc=com',
      status: 'connected',
    },
  ])

  const [mfaUsers, _setMfaUsers] = useState<MFAUser[]>([
    {
      id: '1',
      username: 'john.doe',
      email: 'john.doe@company.com',
      mfaEnabled: true,
      mfaMethod: 'totp',
      backupCodes: 8,
      lastUsed: '2024-03-15 14:30',
    },
    {
      id: '2',
      username: 'jane.smith',
      email: 'jane.smith@company.com',
      mfaEnabled: false,
      mfaMethod: 'totp',
      backupCodes: 0,
      lastUsed: 'Never',
    },
  ])

  const [authSettings, setAuthSettings] = useState({
    basicAuthEnabled: true,
    oidcEnabled: true,
    ldapEnabled: true,
    mfaRequired: false,
    sessionTimeout: 24,
    maxFailedAttempts: 5,
    lockoutDuration: 30,
  })

  const [newOidcProvider, setNewOidcProvider] = useState({
    name: '',
    type: 'keycloak' as const,
    clientId: '',
    clientSecret: '',
    issuerUrl: '',
    scopes: 'openid profile email',
  })

  const [newLdapConfig, setNewLdapConfig] = useState({
    name: '',
    type: 'active_directory' as const,
    server: '',
    port: 636,
    baseDN: '',
    bindDN: '',
    bindPassword: '',
    userFilter: '(sAMAccountName={username})',
    groupFilter: '(member={userdn})',
  })

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleSaveSettings = () => {
    console.log('Saving authentication settings...')
    // TODO: Implement API call
  }

  const handleAddOidcProvider = () => {
    const newProvider: OIDCProvider = {
      id: Date.now().toString(),
      name: newOidcProvider.name,
      type: newOidcProvider.type,
      enabled: false,
      clientId: newOidcProvider.clientId,
      issuerUrl: newOidcProvider.issuerUrl,
      status: 'disabled',
    }
    setOidcProviders([...oidcProviders, newProvider])
    setOidcDialogOpen(false)
    setNewOidcProvider({
      name: '',
      type: 'keycloak',
      clientId: '',
      clientSecret: '',
      issuerUrl: '',
      scopes: 'openid profile email',
    })
  }

  const handleAddLdapConfig = () => {
    const newConfig: LDAPConfig = {
      id: Date.now().toString(),
      name: newLdapConfig.name,
      type: newLdapConfig.type,
      enabled: false,
      server: newLdapConfig.server,
      port: newLdapConfig.port,
      baseDN: newLdapConfig.baseDN,
      bindDN: newLdapConfig.bindDN,
      status: 'disabled',
    }
    setLdapConfigs([...ldapConfigs, newConfig])
    setLdapDialogOpen(false)
    setNewLdapConfig({
      name: '',
      type: 'active_directory',
      server: '',
      port: 636,
      baseDN: '',
      bindDN: '',
      bindPassword: '',
      userFilter: '(sAMAccountName={username})',
      groupFilter: '(member={userdn})',
    })
  }

  const getProviderIcon = (type: string) => {
    switch (type) {
      case 'keycloak': return '🔐'
      case 'google': return '🔍'
      case 'azure': return '☁️'
      case 'auth0': return '🔒'
      case 'okta': return '🛡️'
      case 'gitlab': return '🦊'
      default: return '🔑'
    }
  }

  const getLdapIcon = (type: string) => {
    switch (type) {
      case 'active_directory': return '🏢'
      case 'openldap': return '🐧'
      case 'freeipa': return '🔴'
      case '389ds': return '📁'
      case 'oracle': return '🔶'
      default: return '📋'
    }
  }

  const generateQRCode = (username: string) => {
    // Generate TOTP secret for QR code
    const secret = 'JBSWY3DPEHPK3PXP' // In reality this should be randomly generated
    const issuer = 'GoVPN'
    const otpauth = `otpauth://totp/${issuer}:${username}?secret=${secret}&issuer=${issuer}`
    return otpauth
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('authentication.title')}
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
            startIcon={<SaveIcon />}
            onClick={handleSaveSettings}
          >
            {t('common.save')}
          </Button>
        </Box>
      </Box>

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label={t('authentication.generalSettings')} icon={<SecurityIcon />} />
          <Tab label={t('authentication.oidcProviders')} icon={<VpnKeyIcon />} />
          <Tab label={t('authentication.ldapConfiguration')} icon={<GroupIcon />} />
          <Tab label={t('authentication.mfa')} icon={<ShieldIcon />} />
        </Tabs>
      </Box>

      {/* General settings */}
      <TabPanel value={tabValue} index={0}>
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {t('authentication.methods')}
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <FormControlLabel
                    control={
                      <Switch
                        checked={authSettings.basicAuthEnabled}
                        onChange={(e) => setAuthSettings({
                          ...authSettings,
                          basicAuthEnabled: e.target.checked
                        })}
                      />
                    }
                    label={t('authentication.basicAuth')}
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={authSettings.oidcEnabled}
                        onChange={(e) => setAuthSettings({
                          ...authSettings,
                          oidcEnabled: e.target.checked
                        })}
                      />
                    }
                    label={t('authentication.oidcAuth')}
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={authSettings.ldapEnabled}
                        onChange={(e) => setAuthSettings({
                          ...authSettings,
                          ldapEnabled: e.target.checked
                        })}
                      />
                    }
                    label={t('authentication.ldapAuth')}
                  />
                  <FormControlLabel
                    control={
                      <Switch
                        checked={authSettings.mfaRequired}
                        onChange={(e) => setAuthSettings({
                          ...authSettings,
                          mfaRequired: e.target.checked
                        })}
                      />
                    }
                    label={t('authentication.mfaRequired')}
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  {t('authentication.securitySettings')}
                </Typography>
                <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                  <TextField
                    label={t('authentication.sessionTimeout')}
                    type="number"
                    value={authSettings.sessionTimeout}
                    onChange={(e) => setAuthSettings({
                      ...authSettings,
                      sessionTimeout: parseInt(e.target.value)
                    })}
                    fullWidth
                  />
                  <TextField
                    label={t('authentication.maxFailedAttempts')}
                    type="number"
                    value={authSettings.maxFailedAttempts}
                    onChange={(e) => setAuthSettings({
                      ...authSettings,
                      maxFailedAttempts: parseInt(e.target.value)
                    })}
                    fullWidth
                  />
                  <TextField
                    label={t('authentication.lockoutDuration')}
                    type="number"
                    value={authSettings.lockoutDuration}
                    onChange={(e) => setAuthSettings({
                      ...authSettings,
                      lockoutDuration: parseInt(e.target.value)
                    })}
                    fullWidth
                  />
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      </TabPanel>

      {/* OIDC providers */}
      <TabPanel value={tabValue} index={1}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">{t('authentication.oidcProviders')}</Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setOidcDialogOpen(true)}
          >
            {t('authentication.addProvider')}
          </Button>
        </Box>

        <TableContainer component={Card}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('authentication.provider')}</TableCell>
                <TableCell>{t('common.type')}</TableCell>
                <TableCell>{t('authentication.clientId')}</TableCell>
                <TableCell>{t('authentication.issuerUrl')}</TableCell>
                <TableCell>{t('common.status')}</TableCell>
                <TableCell>{t('common.enabled')}</TableCell>
                <TableCell>{t('common.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {oidcProviders.map((provider) => (
                <TableRow key={provider.id}>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <span>{getProviderIcon(provider.type)}</span>
                      <Typography>{provider.name}</Typography>
                    </Box>
                  </TableCell>
                  <TableCell>{provider.type}</TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {provider.clientId}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {provider.issuerUrl}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={provider.status}
                      color={
                        provider.status === 'active' ? 'success' :
                        provider.status === 'error' ? 'error' : 'default'
                      }
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={provider.enabled}
                      onChange={() => {
                        setOidcProviders(oidcProviders.map(p =>
                          p.id === provider.id ? { ...p, enabled: !p.enabled } : p
                        ))
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Tooltip title={t('common.edit')}>
                        <IconButton size="small" color="primary">
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('common.delete')}>
                        <IconButton size="small" color="error">
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* LDAP configuration */}
      <TabPanel value={tabValue} index={2}>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">{t('authentication.ldapConfiguration')}</Typography>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setLdapDialogOpen(true)}
          >
            {t('authentication.addLdap')}
          </Button>
        </Box>

        <TableContainer component={Card}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('common.name')}</TableCell>
                <TableCell>{t('common.type')}</TableCell>
                <TableCell>{t('authentication.server')}</TableCell>
                <TableCell>{t('authentication.baseDn')}</TableCell>
                <TableCell>{t('common.status')}</TableCell>
                <TableCell>{t('common.enabled')}</TableCell>
                <TableCell>{t('common.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {ldapConfigs.map((config) => (
                <TableRow key={config.id}>
                  <TableCell>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                      <span>{getLdapIcon(config.type)}</span>
                      <Typography>{config.name}</Typography>
                    </Box>
                  </TableCell>
                  <TableCell>{config.type}</TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {config.server}:{config.port}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" fontFamily="monospace">
                      {config.baseDN}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={config.status}
                      color={
                        config.status === 'connected' ? 'success' :
                        config.status === 'error' ? 'error' : 'default'
                      }
                      size="small"
                    />
                  </TableCell>
                  <TableCell>
                    <Switch
                      checked={config.enabled}
                      onChange={() => {
                        setLdapConfigs(ldapConfigs.map(c =>
                          c.id === config.id ? { ...c, enabled: !c.enabled } : c
                        ))
                      }}
                    />
                  </TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Tooltip title={t('authentication.testConnection')}>
                        <IconButton size="small" color="info">
                          <VisibilityIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('common.edit')}>
                        <IconButton size="small" color="primary">
                          <EditIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('common.delete')}>
                        <IconButton size="small" color="error">
                          <DeleteIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* MFA */}
      <TabPanel value={tabValue} index={3}>
        <Typography variant="h6" gutterBottom>
          {t('authentication.mfaUsers')}
        </Typography>

        <TableContainer component={Card}>
          <Table>
            <TableHead>
              <TableRow>
                <TableCell>{t('authentication.user')}</TableCell>
                <TableCell>{t('authentication.email')}</TableCell>
                <TableCell>{t('authentication.mfaEnabled')}</TableCell>
                <TableCell>{t('authentication.method')}</TableCell>
                <TableCell>{t('authentication.backupCodes')}</TableCell>
                <TableCell>{t('authentication.lastUsed')}</TableCell>
                <TableCell>{t('common.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {mfaUsers.map((user) => (
                <TableRow key={user.id}>
                  <TableCell>{user.username}</TableCell>
                  <TableCell>{user.email}</TableCell>
                  <TableCell>
                    <Chip
                      label={user.mfaEnabled ? t('common.enabled') : t('common.disabled')}
                      color={user.mfaEnabled ? 'success' : 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell>{user.mfaMethod.toUpperCase()}</TableCell>
                  <TableCell>{user.backupCodes}</TableCell>
                  <TableCell>{user.lastUsed === 'Never' ? t('authentication.never') : user.lastUsed}</TableCell>
                  <TableCell>
                    <Box sx={{ display: 'flex', gap: 1 }}>
                      <Tooltip title={t('authentication.showQrCode')}>
                        <IconButton
                          size="small"
                          color="primary"
                          onClick={() => {
                            setSelectedUser(user)
                            setQrDialogOpen(true)
                          }}
                        >
                          <QrCodeIcon />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title={t('authentication.resetMfa')}>
                        <IconButton size="small" color="warning">
                          <KeyIcon />
                        </IconButton>
                      </Tooltip>
                    </Box>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </TabPanel>

      {/* Add OIDC provider dialog */}
      <Dialog open={oidcDialogOpen} onClose={() => setOidcDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{t('authentication.addOidcProvider')}</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('common.name')}
                value={newOidcProvider.name}
                onChange={(e) => setNewOidcProvider({ ...newOidcProvider, name: e.target.value })}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>{t('authentication.providerType')}</InputLabel>
                <Select
                  value={newOidcProvider.type}
                  label={t('authentication.providerType')}
                  onChange={(e) => setNewOidcProvider({ ...newOidcProvider, type: e.target.value as any })}
                >
                  <MenuItem value="keycloak">{t('authentication.providerTypes.keycloak')}</MenuItem>
                  <MenuItem value="google">{t('authentication.providerTypes.google')}</MenuItem>
                  <MenuItem value="azure">{t('authentication.providerTypes.azure')}</MenuItem>
                  <MenuItem value="auth0">{t('authentication.providerTypes.auth0')}</MenuItem>
                  <MenuItem value="okta">{t('authentication.providerTypes.okta')}</MenuItem>
                  <MenuItem value="gitlab">{t('authentication.providerTypes.gitlab')}</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label={t('authentication.issuerUrl')}
                value={newOidcProvider.issuerUrl}
                onChange={(e) => setNewOidcProvider({ ...newOidcProvider, issuerUrl: e.target.value })}
                placeholder="https://auth.example.com/realms/main"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('authentication.clientId')}
                value={newOidcProvider.clientId}
                onChange={(e) => setNewOidcProvider({ ...newOidcProvider, clientId: e.target.value })}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('authentication.clientSecret')}
                type="password"
                value={newOidcProvider.clientSecret}
                onChange={(e) => setNewOidcProvider({ ...newOidcProvider, clientSecret: e.target.value })}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label={t('authentication.scopes')}
                value={newOidcProvider.scopes}
                onChange={(e) => setNewOidcProvider({ ...newOidcProvider, scopes: e.target.value })}
                helperText={t('authentication.scopesHelp')}
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOidcDialogOpen(false)}>{t('common.cancel')}</Button>
          <Button onClick={handleAddOidcProvider} variant="contained">{t('common.add')}</Button>
        </DialogActions>
      </Dialog>

      {/* Add LDAP dialog */}
      <Dialog open={ldapDialogOpen} onClose={() => setLdapDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{t('authentication.addLdapConfig')}</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('common.name')}
                value={newLdapConfig.name}
                onChange={(e) => setNewLdapConfig({ ...newLdapConfig, name: e.target.value })}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>{t('authentication.ldapType')}</InputLabel>
                <Select
                  value={newLdapConfig.type}
                  label={t('authentication.ldapType')}
                  onChange={(e) => setNewLdapConfig({ ...newLdapConfig, type: e.target.value as any })}
                >
                  <MenuItem value="active_directory">{t('authentication.ldapTypes.activeDirectory')}</MenuItem>
                  <MenuItem value="openldap">{t('authentication.ldapTypes.openldap')}</MenuItem>
                  <MenuItem value="freeipa">{t('authentication.ldapTypes.freeipa')}</MenuItem>
                  <MenuItem value="389ds">{t('authentication.ldapTypes.389ds')}</MenuItem>
                  <MenuItem value="oracle">{t('authentication.ldapTypes.oracle')}</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={8}>
              <TextField
                fullWidth
                label={t('authentication.ldapServer')}
                value={newLdapConfig.server}
                onChange={(e) => setNewLdapConfig({ ...newLdapConfig, server: e.target.value })}
                placeholder="ldap.example.com"
              />
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                label={t('authentication.port')}
                type="number"
                value={newLdapConfig.port}
                onChange={(e) => setNewLdapConfig({ ...newLdapConfig, port: parseInt(e.target.value) })}
              />
            </Grid>
            <Grid item xs={12}>
              <TextField
                fullWidth
                label={t('authentication.baseDn')}
                value={newLdapConfig.baseDN}
                onChange={(e) => setNewLdapConfig({ ...newLdapConfig, baseDN: e.target.value })}
                placeholder="dc=example,dc=com"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('authentication.bindDn')}
                value={newLdapConfig.bindDN}
                onChange={(e) => setNewLdapConfig({ ...newLdapConfig, bindDN: e.target.value })}
                placeholder="cn=admin,dc=example,dc=com"
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('authentication.bindPassword')}
                type="password"
                value={newLdapConfig.bindPassword}
                onChange={(e) => setNewLdapConfig({ ...newLdapConfig, bindPassword: e.target.value })}
              />
            </Grid>
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setLdapDialogOpen(false)}>{t('common.cancel')}</Button>
          <Button onClick={handleAddLdapConfig} variant="contained">{t('common.add')}</Button>
        </DialogActions>
      </Dialog>

      {/* QR code dialog */}
      <Dialog open={qrDialogOpen} onClose={() => setQrDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{t('authentication.qrCodeTitle')}</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, p: 2 }}>
            <Typography variant="body1">
              {t('authentication.user')}: <strong>{selectedUser?.username}</strong>
            </Typography>
            {selectedUser && (
              <Box sx={{ p: 2, bgcolor: 'white', borderRadius: 1 }}>
                <img 
                  src={`https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(generateQRCode(selectedUser.username))}`}
                  alt="QR Code"
                  style={{ width: 200, height: 200 }}
                />
              </Box>
            )}
            <Typography variant="body2" color="text.secondary" textAlign="center">
              {t('authentication.qrCodeInstructions')}
            </Typography>
            <Alert severity="info">
              {t('authentication.secretKey')}: JBSWY3DPEHPK3PXP
            </Alert>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setQrDialogOpen(false)}>{t('common.close')}</Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
} 