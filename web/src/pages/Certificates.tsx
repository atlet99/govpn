import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Button,
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
  TextField,
  IconButton,
  Tooltip,
  Alert,
  Tabs,
  Tab,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from '@mui/material'
import {
  Security as SecurityIcon,
  Add as AddIcon,
  Download as DownloadIcon,
  Delete as DeleteIcon,
  Visibility as VisibilityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Upload as UploadIcon,
} from '@mui/icons-material'

interface Certificate {
  id: string
  name: string
  type: 'ca' | 'server' | 'client'
  subject: string
  issuer: string
  validFrom: string
  validTo: string
  status: 'valid' | 'expired' | 'revoked' | 'expiring'
  serialNumber: string
  keySize: number
  algorithm: string
}

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
      id={`cert-tabpanel-${index}`}
      aria-labelledby={`cert-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  )
}

export default function Certificates() {
  const { t } = useTranslation()
  const [tabValue, setTabValue] = useState(0)
  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [viewDialogOpen, setViewDialogOpen] = useState(false)
  const [selectedCert, setSelectedCert] = useState<Certificate | null>(null)

  const [certificates, setCertificates] = useState<Certificate[]>([
    {
      id: '1',
      name: 'GoVPN Root CA',
      type: 'ca',
      subject: 'CN=GoVPN Root CA, O=GoVPN, C=US',
      issuer: 'CN=GoVPN Root CA, O=GoVPN, C=US',
      validFrom: '2024-01-01',
      validTo: '2034-01-01',
      status: 'valid',
      serialNumber: '01',
      keySize: 4096,
      algorithm: 'RSA',
    },
    {
      id: '2',
      name: 'GoVPN Server',
      type: 'server',
      subject: 'CN=vpn.company.com, O=Company, C=US',
      issuer: 'CN=GoVPN Root CA, O=GoVPN, C=US',
      validFrom: '2024-01-01',
      validTo: '2025-01-01',
      status: 'expiring',
      serialNumber: '02',
      keySize: 2048,
      algorithm: 'RSA',
    },
    {
      id: '3',
      name: 'john.doe',
      type: 'client',
      subject: 'CN=john.doe, O=Company, C=US',
      issuer: 'CN=GoVPN Root CA, O=GoVPN, C=US',
      validFrom: '2024-01-01',
      validTo: '2025-01-01',
      status: 'valid',
      serialNumber: '03',
      keySize: 2048,
      algorithm: 'RSA',
    },
    {
      id: '4',
      name: 'jane.smith',
      type: 'client',
      subject: 'CN=jane.smith, O=Company, C=US',
      issuer: 'CN=GoVPN Root CA, O=GoVPN, C=US',
      validFrom: '2023-01-01',
      validTo: '2024-01-01',
      status: 'expired',
      serialNumber: '04',
      keySize: 2048,
      algorithm: 'RSA',
    },
  ])

  const [newCert, setNewCert] = useState({
    name: '',
    type: 'client' as 'ca' | 'server' | 'client',
    commonName: '',
    organization: '',
    country: 'US',
    keySize: 2048,
    validityDays: 365,
    email: '',
  })

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const handleCreateCertificate = () => {
    const newCertificate: Certificate = {
      id: Date.now().toString(),
      name: newCert.name,
      type: newCert.type,
      subject: `CN=${newCert.commonName}, O=${newCert.organization}, C=${newCert.country}`,
      issuer: 'CN=GoVPN Root CA, O=GoVPN, C=US',
      validFrom: new Date().toISOString().split('T')[0] || '',
      validTo: new Date(Date.now() + newCert.validityDays * 24 * 60 * 60 * 1000).toISOString().split('T')[0] || '',
      status: 'valid',
      serialNumber: (certificates.length + 1).toString().padStart(2, '0'),
      keySize: newCert.keySize,
      algorithm: 'RSA',
    }
    setCertificates([...certificates, newCertificate])
    setCreateDialogOpen(false)
    setNewCert({
      name: '',
      type: 'client',
      commonName: '',
      organization: '',
      country: 'US',
      keySize: 2048,
      validityDays: 365,
      email: '',
    })
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'valid': return 'success'
      case 'expiring': return 'warning'
      case 'expired': return 'error'
      case 'revoked': return 'error'
      default: return 'default'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'valid': return <CheckCircleIcon color="success" />
      case 'expiring': return <WarningIcon color="warning" />
      case 'expired': return <ErrorIcon color="error" />
      case 'revoked': return <ErrorIcon color="error" />
      default: return <CheckCircleIcon />
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ca': return '🏛️'
      case 'server': return '🖥️'
      case 'client': return '👤'
      default: return '📜'
    }
  }

  const getDaysUntilExpiry = (validTo: string) => {
    const today = new Date()
    const expiry = new Date(validTo)
    const diffTime = expiry.getTime() - today.getTime()
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return diffDays
  }

  const handleViewCertificate = (cert: Certificate) => {
    setSelectedCert(cert)
    setViewDialogOpen(true)
  }

  const handleDownloadCertificate = (cert: Certificate) => {
    // TODO: Implement certificate download
    console.log('Downloading certificate:', cert.name)
  }

  const handleRevokeCertificate = (certId: string) => {
    setCertificates(certificates.map(cert =>
      cert.id === certId ? { ...cert, status: 'revoked' as const } : cert
    ))
  }

  const caCertificates = certificates.filter(cert => cert.type === 'ca')
  const serverCertificates = certificates.filter(cert => cert.type === 'server')
  const clientCertificates = certificates.filter(cert => cert.type === 'client')

  const getExpiringCertificates = () => {
    return certificates.filter(cert => {
      const days = getDaysUntilExpiry(cert.validTo)
      return days <= 30 && days > 0
    })
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('certificates.title')}
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
            variant="outlined"
            startIcon={<UploadIcon />}
            onClick={() => console.log('Import certificate...')}
          >
            {t('certificates.import')}
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={() => setCreateDialogOpen(true)}
          >
            {t('certificates.create')}
          </Button>
        </Box>
      </Box>

      {/* Warnings */}
      {getExpiringCertificates().length > 0 && (
        <Alert severity="warning" sx={{ mb: 3 }}>
          <Typography variant="subtitle2" gutterBottom>
            {t('certificates.expiringWarning')}:
          </Typography>
          {getExpiringCertificates().map(cert => (
            <Typography key={cert.id} variant="body2">
              • {cert.name} - {t('certificates.expiresIn', { days: getDaysUntilExpiry(cert.validTo) })}
            </Typography>
          ))}
        </Alert>
      )}

      {/* Statistics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <SecurityIcon color="primary" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('certificates.totalCertificates')}
                  </Typography>
                  <Typography variant="h4">
                    {certificates.length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <CheckCircleIcon color="success" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('certificates.validCertificates')}
                  </Typography>
                  <Typography variant="h4">
                    {certificates.filter(c => c.status === 'valid').length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <WarningIcon color="warning" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('certificates.expiringCertificates')}
                  </Typography>
                  <Typography variant="h4">
                    {getExpiringCertificates().length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <ErrorIcon color="error" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('certificates.expiredCertificates')}
                  </Typography>
                  <Typography variant="h4">
                    {certificates.filter(c => c.status === 'expired' || c.status === 'revoked').length}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label={`${t('certificates.ca')} (${caCertificates.length})`} />
          <Tab label={`${t('certificates.server')} (${serverCertificates.length})`} />
          <Tab label={`${t('certificates.client')} (${clientCertificates.length})`} />
          <Tab label={t('certificates.all')} />
        </Tabs>
      </Box>

      {/* CA certificates */}
      <TabPanel value={tabValue} index={0}>
        <CertificateTable certificates={caCertificates} onView={handleViewCertificate} onDownload={handleDownloadCertificate} onRevoke={handleRevokeCertificate} />
      </TabPanel>

      {/* Server certificates */}
      <TabPanel value={tabValue} index={1}>
        <CertificateTable certificates={serverCertificates} onView={handleViewCertificate} onDownload={handleDownloadCertificate} onRevoke={handleRevokeCertificate} />
      </TabPanel>

      {/* Client certificates */}
      <TabPanel value={tabValue} index={2}>
        <CertificateTable certificates={clientCertificates} onView={handleViewCertificate} onDownload={handleDownloadCertificate} onRevoke={handleRevokeCertificate} />
      </TabPanel>

      {/* All certificates */}
      <TabPanel value={tabValue} index={3}>
        <CertificateTable certificates={certificates} onView={handleViewCertificate} onDownload={handleDownloadCertificate} onRevoke={handleRevokeCertificate} />
      </TabPanel>

      {/* Create certificate dialog */}
      <Dialog open={createDialogOpen} onClose={() => setCreateDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{t('certificates.createCertificateDialog.title')}</DialogTitle>
        <DialogContent>
          <Grid container spacing={2} sx={{ mt: 1 }}>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('certificates.createCertificateDialog.name')}
                value={newCert.name}
                onChange={(e) => setNewCert({ ...newCert, name: e.target.value })}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <FormControl fullWidth>
                <InputLabel>{t('certificates.createCertificateDialog.type')}</InputLabel>
                <Select
                  value={newCert.type}
                  label={t('certificates.createCertificateDialog.type')}
                  onChange={(e) => setNewCert({ ...newCert, type: e.target.value as any })}
                >
                  <MenuItem value="ca">{t('certificates.types.ca')}</MenuItem>
                  <MenuItem value="server">{t('certificates.types.server')}</MenuItem>
                  <MenuItem value="client">{t('certificates.types.client')}</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('certificates.createCertificateDialog.commonName')}
                value={newCert.commonName}
                onChange={(e) => setNewCert({ ...newCert, commonName: e.target.value })}
                placeholder={newCert.type === 'server' ? 'vpn.company.com' : 'john.doe'}
              />
            </Grid>
            <Grid item xs={12} md={6}>
              <TextField
                fullWidth
                label={t('certificates.createCertificateDialog.organization')}
                value={newCert.organization}
                onChange={(e) => setNewCert({ ...newCert, organization: e.target.value })}
              />
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                label={t('certificates.createCertificateDialog.country')}
                value={newCert.country}
                onChange={(e) => setNewCert({ ...newCert, country: e.target.value })}
                inputProps={{ maxLength: 2 }}
              />
            </Grid>
            <Grid item xs={12} md={4}>
              <FormControl fullWidth>
                <InputLabel>{t('certificates.createCertificateDialog.keySize')}</InputLabel>
                <Select
                  value={newCert.keySize}
                  label={t('certificates.createCertificateDialog.keySize')}
                  onChange={(e) => setNewCert({ ...newCert, keySize: e.target.value as number })}
                >
                  <MenuItem value={2048}>2048 bit</MenuItem>
                  <MenuItem value={4096}>4096 bit</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={4}>
              <TextField
                fullWidth
                label={t('certificates.createCertificateDialog.validityDays')}
                type="number"
                value={newCert.validityDays}
                onChange={(e) => setNewCert({ ...newCert, validityDays: parseInt(e.target.value) })}
              />
            </Grid>
            {newCert.type === 'client' && (
              <Grid item xs={12}>
                <TextField
                  fullWidth
                  label={t('certificates.createCertificateDialog.email')}
                  type="email"
                  value={newCert.email}
                  onChange={(e) => setNewCert({ ...newCert, email: e.target.value })}
                />
              </Grid>
            )}
          </Grid>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>{t('common.cancel')}</Button>
          <Button onClick={handleCreateCertificate} variant="contained">{t('common.create')}</Button>
        </DialogActions>
      </Dialog>

      {/* Certificate details dialog */}
      <Dialog open={viewDialogOpen} onClose={() => setViewDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{t('certificates.certificateDetails')}</DialogTitle>
        <DialogContent>
          {selectedCert && (
            <Box sx={{ mt: 2 }}>
              <Grid container spacing={2}>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>{t('common.name')}:</Typography>
                  <Typography variant="body2" gutterBottom>{selectedCert.name}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>{t('common.type')}:</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <span>{getTypeIcon(selectedCert.type)}</span>
                    <Typography variant="body2">{selectedCert.type}</Typography>
                  </Box>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>{t('certificates.subject')}:</Typography>
                  <Typography variant="body2" fontFamily="monospace" gutterBottom>
                    {selectedCert.subject}
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>{t('certificates.issuer')}:</Typography>
                  <Typography variant="body2" fontFamily="monospace" gutterBottom>
                    {selectedCert.issuer}
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>{t('certificates.validFrom')}:</Typography>
                  <Typography variant="body2" gutterBottom>{selectedCert.validFrom}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>{t('certificates.validTo')}:</Typography>
                  <Typography variant="body2" gutterBottom>{selectedCert.validTo}</Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>{t('certificates.serialNumber')}:</Typography>
                  <Typography variant="body2" fontFamily="monospace" gutterBottom>
                    {selectedCert.serialNumber}
                  </Typography>
                </Grid>
                <Grid item xs={12} md={6}>
                  <Typography variant="subtitle2" gutterBottom>{t('certificates.algorithm')}:</Typography>
                  <Typography variant="body2" gutterBottom>
                    {selectedCert.algorithm} {selectedCert.keySize} bit
                  </Typography>
                </Grid>
                <Grid item xs={12}>
                  <Typography variant="subtitle2" gutterBottom>{t('common.status')}:</Typography>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    {getStatusIcon(selectedCert.status)}
                    <Chip
                      label={selectedCert.status}
                      color={getStatusColor(selectedCert.status) as any}
                      size="small"
                    />
                  </Box>
                </Grid>
              </Grid>
            </Box>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setViewDialogOpen(false)}>{t('common.close')}</Button>
          {selectedCert && (
            <Button
              onClick={() => handleDownloadCertificate(selectedCert)}
              variant="contained"
              startIcon={<DownloadIcon />}
            >
              {t('common.download')}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  )
}

// Certificate table component
function CertificateTable({ 
  certificates, 
  onView, 
  onDownload, 
  onRevoke 
}: { 
  certificates: Certificate[]
  onView: (cert: Certificate) => void
  onDownload: (cert: Certificate) => void
  onRevoke: (certId: string) => void
}) {
  const { t } = useTranslation()

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'valid': return 'success'
      case 'expiring': return 'warning'
      case 'expired': return 'error'
      case 'revoked': return 'error'
      default: return 'default'
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'ca': return '🏛️'
      case 'server': return '🖥️'
      case 'client': return '👤'
      default: return '📜'
    }
  }

  const getDaysUntilExpiry = (validTo: string) => {
    const today = new Date()
    const expiry = new Date(validTo)
    const diffTime = expiry.getTime() - today.getTime()
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24))
    return diffDays
  }

  return (
    <TableContainer component={Card}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>{t('common.name')}</TableCell>
            <TableCell>{t('common.type')}</TableCell>
            <TableCell>{t('certificates.subject')}</TableCell>
            <TableCell>{t('certificates.validUntil')}</TableCell>
            <TableCell>{t('common.status')}</TableCell>
            <TableCell>{t('certificates.algorithm')}</TableCell>
            <TableCell>{t('common.actions')}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {certificates.map((cert) => (
            <TableRow key={cert.id}>
              <TableCell>
                <Typography variant="subtitle2">{cert.name}</Typography>
              </TableCell>
              <TableCell>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <span>{getTypeIcon(cert.type)}</span>
                  <Typography variant="body2">{cert.type}</Typography>
                </Box>
              </TableCell>
              <TableCell>
                <Typography variant="body2" fontFamily="monospace">
                  {cert.subject.split(',')[0]}
                </Typography>
              </TableCell>
              <TableCell>
                <Box>
                  <Typography variant="body2">{cert.validTo}</Typography>
                  {cert.status === 'expiring' && (
                    <Typography variant="caption" color="warning.main">
                      {getDaysUntilExpiry(cert.validTo)} days
                    </Typography>
                  )}
                </Box>
              </TableCell>
              <TableCell>
                <Chip
                  label={cert.status}
                  color={getStatusColor(cert.status) as any}
                  size="small"
                />
              </TableCell>
              <TableCell>
                <Typography variant="body2">
                  {cert.algorithm} {cert.keySize}
                </Typography>
              </TableCell>
              <TableCell>
                <Box sx={{ display: 'flex', gap: 1 }}>
                  <Tooltip title={t('common.view')}>
                    <IconButton size="small" color="primary" onClick={() => onView(cert)}>
                      <VisibilityIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t('common.download')}>
                    <IconButton size="small" color="info" onClick={() => onDownload(cert)}>
                      <DownloadIcon />
                    </IconButton>
                  </Tooltip>
                  {cert.status !== 'revoked' && cert.status !== 'expired' && (
                    <Tooltip title={t('certificates.revoke')}>
                      <IconButton size="small" color="error" onClick={() => onRevoke(cert.id)}>
                        <DeleteIcon />
                      </IconButton>
                    </Tooltip>
                  )}
                </Box>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
} 