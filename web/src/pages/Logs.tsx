import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Chip,
  Button,
  TextField,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Tabs,
  Tab,
  Pagination,
  Paper,
  Accordion,
  AccordionSummary,
  AccordionDetails,
} from '@mui/material'
import {
  List as ListIcon,
  FilterList as FilterIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Info as InfoIcon,
  Warning as WarningIcon,
  Error as ErrorIcon,
  CheckCircle as CheckCircleIcon,
  Search as SearchIcon,
  ExpandMore as ExpandMoreIcon,
} from '@mui/icons-material'
import { formatDate } from '@/utils/dateUtils'
import LocalizedDateInput from '@/components/LocalizedDateInput'

interface LogEntry {
  id: string
  timestamp: string
  level: 'error' | 'warning' | 'info' | 'debug'
  component: string
  message: string
  details?: string
  user?: string
  ip?: string
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
      id={`logs-tabpanel-${index}`}
      aria-labelledby={`logs-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  )
}

export default function Logs() {
  const { t } = useTranslation()
  const [tabValue, setTabValue] = useState(0)
  const [logs, _setLogs] = useState<LogEntry[]>([
    {
      id: '1',
      timestamp: '2024-03-15 14:30:25',
      level: 'info',
      component: 'Authentication',
      message: 'Successful OIDC login',
      user: 'john.doe',
      ip: '192.168.1.100',
    },
    {
      id: '2',
      timestamp: '2024-03-15 14:28:15',
      level: 'warning',
      component: 'Obfuscation',
      message: 'DPI detection triggered, switching method from HTTP to TLS',
      details: 'Source: CN region, Method: HTTP Mimicry → TLS Tunnel',
      user: 'bob.wilson',
      ip: '10.0.1.102',
    },
    {
      id: '3',
      timestamp: '2024-03-15 14:25:42',
      level: 'error',
      component: 'VPN',
      message: 'Connection failed due to certificate validation error',
      details: 'Certificate expired: CN=jane.smith, Issuer: GoVPN Root CA',
      user: 'jane.smith',
      ip: '172.16.0.50',
    },
    {
      id: '4',
      timestamp: '2024-03-15 14:20:12',
      level: 'info',
      component: 'PKI',
      message: 'New client certificate generated',
      details: 'CN=alice.johnson, Key Size: 2048, Validity: 365 days',
      user: 'admin',
      ip: '192.168.1.1',
    },
    {
      id: '5',
      timestamp: '2024-03-15 14:15:33',
      level: 'warning',
      component: 'LDAP',
      message: 'LDAP server connection timeout, fallback to local auth',
      details: 'Server: ldap.company.com:636, Timeout: 30s',
    },
  ])

  const [filters, setFilters] = useState({
    level: '',
    component: '',
    search: '',
    dateFrom: '',
    dateTo: '',
  })

  const [page, setPage] = useState(1)
  const logsPerPage = 20

  const handleTabChange = (_event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue)
  }

  const filteredLogs = logs.filter(log => {
    return (
      (!filters.level || log.level === filters.level) &&
      (!filters.component || log.component.toLowerCase().includes(filters.component.toLowerCase())) &&
      (!filters.search || log.message.toLowerCase().includes(filters.search.toLowerCase()))
    )
  })

  const logCounts = {
    total: logs.length,
    error: logs.filter(log => log.level === 'error').length,
    warning: logs.filter(log => log.level === 'warning').length,
    info: logs.filter(log => log.level === 'info').length,
    debug: logs.filter(log => log.level === 'debug').length,
  }

  const auditLogs = logs.filter(log => log.user)
  const systemLogs = logs.filter(log => !log.user)

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('logs.title')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => console.log('Refreshing logs...')}
          >
            {t('common.refresh')}
          </Button>
          <Button
            variant="outlined"
            startIcon={<DownloadIcon />}
            onClick={() => console.log('Exporting logs...')}
          >
            {t('common.export')}
          </Button>
        </Box>
      </Box>

      {/* Log statistics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={6} sm={4} md={2.4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ListIcon color="primary" />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('logs.total')}
                  </Typography>
                  <Typography variant="h5">
                    {logCounts.total}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={4} md={2.4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ErrorIcon color="error" />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('logs.errors')}
                  </Typography>
                  <Typography variant="h5">
                    {logCounts.error}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={4} md={2.4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <WarningIcon color="warning" />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('logs.warnings')}
                  </Typography>
                  <Typography variant="h5">
                    {logCounts.warning}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={4} md={2.4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <InfoIcon color="info" />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('logs.info')}
                  </Typography>
                  <Typography variant="h5">
                    {logCounts.info}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={6} sm={4} md={2.4}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CheckCircleIcon color="success" />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('logs.debug')}
                  </Typography>
                  <Typography variant="h5">
                    {logCounts.debug}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Filters */}
      <Card sx={{ mb: 4 }}>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <FilterIcon />
            {t('common.filter')}
          </Typography>
          <Grid container spacing={2}>
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                label={t('common.search')}
                value={filters.search}
                onChange={(e) => setFilters({ ...filters, search: e.target.value })}
                InputProps={{
                  startAdornment: <SearchIcon color="action" sx={{ mr: 1 }} />,
                }}
              />
            </Grid>
            <Grid item xs={12} md={2}>
              <FormControl fullWidth>
                <InputLabel>{t('logs.level')}</InputLabel>
                <Select
                  value={filters.level}
                  label={t('logs.level')}
                  onChange={(e) => setFilters({ ...filters, level: e.target.value })}
                >
                  <MenuItem value="">{t('logs.all')}</MenuItem>
                  <MenuItem value="error">{t('logs.errors')}</MenuItem>
                  <MenuItem value="warning">{t('logs.warnings')}</MenuItem>
                  <MenuItem value="info">{t('logs.info')}</MenuItem>
                  <MenuItem value="debug">{t('logs.debug')}</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid item xs={12} md={3}>
              <TextField
                fullWidth
                label={t('logs.component')}
                value={filters.component}
                onChange={(e) => setFilters({ ...filters, component: e.target.value })}
              />
            </Grid>
            <Grid item xs={6} md={2}>
              <LocalizedDateInput
                fullWidth
                label={t('logs.dateFrom')}
                value={filters.dateFrom}
                onChange={(value) => setFilters({ ...filters, dateFrom: value })}
              />
            </Grid>
            <Grid item xs={6} md={2}>
              <LocalizedDateInput
                fullWidth
                label={t('logs.dateTo')}
                value={filters.dateTo}
                onChange={(value) => setFilters({ ...filters, dateTo: value })}
              />
            </Grid>
          </Grid>
        </CardContent>
      </Card>

      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={tabValue} onChange={handleTabChange}>
          <Tab label={`${t('logs.allLogs')} (${filteredLogs.length})`} />
          <Tab label={`${t('logs.auditLogs')} (${auditLogs.length})`} />
          <Tab label={`${t('logs.systemLogs')} (${systemLogs.length})`} />
        </Tabs>
      </Box>

      {/* All logs */}
      <TabPanel value={tabValue} index={0}>
        <LogTable logs={filteredLogs} />
      </TabPanel>

      {/* User audit */}
      <TabPanel value={tabValue} index={1}>
        <LogTable logs={auditLogs} />
      </TabPanel>

      {/* System logs */}
      <TabPanel value={tabValue} index={2}>
        <LogTable logs={systemLogs} />
      </TabPanel>

      {/* Pagination */}
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 3 }}>
        <Pagination
          count={Math.ceil(filteredLogs.length / logsPerPage)}
          page={page}
          onChange={(_event, value) => setPage(value)}
        />
      </Box>
    </Box>
  )
}

// Log table component
function LogTable({ logs }: { logs: LogEntry[] }) {
  const { t, i18n } = useTranslation()
  
  const getLevelIcon = (level: string) => {
    switch (level) {
      case 'error': return <ErrorIcon color="error" />
      case 'warning': return <WarningIcon color="warning" />
      case 'info': return <InfoIcon color="info" />
      case 'debug': return <CheckCircleIcon color="success" />
      default: return <InfoIcon />
    }
  }

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'error': return 'error'
      case 'warning': return 'warning'
      case 'info': return 'info'
      case 'debug': return 'success'
      default: return 'default'
    }
  }

  return (
    <TableContainer component={Paper}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>{t('logs.timestamp')}</TableCell>
            <TableCell>{t('logs.level')}</TableCell>
            <TableCell>{t('logs.component')}</TableCell>
            <TableCell>{t('logs.message')}</TableCell>
            <TableCell>{t('logs.user')}</TableCell>
            <TableCell>{t('logs.ip')}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {logs.map((log) => (
            <TableRow key={log.id} sx={{ '&:hover': { backgroundColor: 'action.hover' } }}>
              <TableCell>
                <Typography variant="body2" fontFamily="monospace">
                  {formatDate(log.timestamp, i18n.language, true)}
                </Typography>
              </TableCell>
              <TableCell>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {getLevelIcon(log.level)}
                  <Chip
                    label={log.level.toUpperCase()}
                    color={getLevelColor(log.level) as any}
                    size="small"
                  />
                </Box>
              </TableCell>
              <TableCell>
                <Typography variant="body2" sx={{ fontWeight: 'medium' }}>
                  {log.component}
                </Typography>
              </TableCell>
              <TableCell>
                <Box>
                  <Typography variant="body2">{log.message}</Typography>
                  {log.details && (
                    <Accordion sx={{ mt: 1 }}>
                      <AccordionSummary
                        expandIcon={<ExpandMoreIcon />}
                        sx={{ minHeight: 'auto', '& .MuiAccordionSummary-content': { margin: 0 } }}
                      >
                        <Typography variant="caption" color="text.secondary">
                          {t('logs.details')}
                        </Typography>
                      </AccordionSummary>
                      <AccordionDetails sx={{ pt: 0 }}>
                        <Typography variant="body2" color="text.secondary" fontFamily="monospace">
                          {log.details}
                        </Typography>
                      </AccordionDetails>
                    </Accordion>
                  )}
                </Box>
              </TableCell>
              <TableCell>
                {log.user ? (
                  <Typography variant="body2">{log.user}</Typography>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    {t('logs.system')}
                  </Typography>
                )}
              </TableCell>
              <TableCell>
                {log.ip ? (
                  <Typography variant="body2" fontFamily="monospace">
                    {log.ip}
                  </Typography>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    -
                  </Typography>
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
} 