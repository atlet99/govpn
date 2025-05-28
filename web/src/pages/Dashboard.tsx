import { useState, useEffect, useCallback } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Box,
  Card,
  CardContent,
  Typography,
  Grid,
  LinearProgress,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Alert,
  IconButton,
  Tooltip,
  Fade,
} from '@mui/material'
import {
  People as PeopleIcon,
  Security as SecurityIcon,
  Speed as SpeedIcon,
  Storage as StorageIcon,
  NetworkCheck as NetworkIcon,
  Shield as ShieldIcon,
  Visibility as VisibilityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
} from '@mui/icons-material'
import { formatRelativeTime } from '@/utils/dateUtils'

interface SystemStats {
  activeConnections: number
  totalUsers: number
  securityScore: number
  averageSpeed: number
  storageUsed: number
  obfuscationActive: boolean
  dpiDetected: boolean
  uptime: string
  networkLatency: number
}

interface Connection {
  id: string
  username: string
  ip: string
  country: string
  connected: string
  bytesIn: number
  bytesOut: number
  obfuscationMethod: string
  status: 'active' | 'idle' | 'disconnecting'
}

interface SecurityAlert {
  id: string
  type: 'warning' | 'error' | 'info'
  message: string
  timestamp: string
}

const StatCard = ({ 
  title, 
  value, 
  subtitle, 
  icon, 
  color = 'primary',
  progress,
  status 
}: { 
  title: string
  value: string | number
  subtitle?: string
  icon: React.ReactNode
  color?: 'primary' | 'success' | 'warning' | 'error' | 'info'
  progress?: number
  status?: 'online' | 'offline' | 'warning'
}) => {
  const { t } = useTranslation()
  
  return (
    <Card sx={{ height: '100%' }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
          <Box>
            <Typography color="text.secondary" variant="body2" gutterBottom>
              {title}
            </Typography>
            <Typography variant="h4" component="div" color={`${color}.main`}>
              {value}
            </Typography>
            {subtitle && (
              <Typography variant="body2" color="text.secondary">
                {subtitle}
              </Typography>
            )}
          </Box>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {status && (
              <Chip 
                size="small" 
                label={t(`common.${status}`)} 
                color={status === 'online' ? 'success' : status === 'warning' ? 'warning' : 'error'}
                variant="outlined"
              />
            )}
            <Box sx={{ color: `${color}.main` }}>
              {icon}
            </Box>
          </Box>
        </Box>
        {progress !== undefined && (
          <Box>
            <LinearProgress 
              variant="determinate" 
              value={progress} 
              color={color}
              sx={{ height: 8, borderRadius: 4 }}
            />
            <Typography variant="caption" color="text.secondary" sx={{ mt: 1 }}>
              {progress}% {t('dashboard.used')}
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  )
}

export default function Dashboard() {
  const { t } = useTranslation()
  const [stats, setStats] = useState<SystemStats>({
    activeConnections: 156,
    totalUsers: 342,
    securityScore: 98,
    averageSpeed: 85.4,
    storageUsed: 45,
    obfuscationActive: true,
    dpiDetected: false,
    uptime: '15 days 4 hours',
    networkLatency: 12,
  })

  const [connections, setConnections] = useState<Connection[]>([
    {
      id: '1',
      username: 'john.doe',
      ip: '192.168.1.100',
      country: 'US',
      connected: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), // 2 hours ago
      bytesIn: 1024 * 1024 * 150,
      bytesOut: 1024 * 1024 * 89,
      obfuscationMethod: 'TLS Tunnel',
      status: 'active',
    },
    {
      id: '2',
      username: 'jane.smith',
      ip: '192.168.1.101',
      country: 'DE',
      connected: new Date(Date.now() - 45 * 60 * 1000).toISOString(), // 45 minutes ago
      bytesIn: 1024 * 1024 * 67,
      bytesOut: 1024 * 1024 * 23,
      obfuscationMethod: 'HTTP Mimicry',
      status: 'active',
    },
    {
      id: '3',
      username: 'bob.wilson',
      ip: '192.168.1.102',
      country: 'CN',
      connected: new Date(Date.now() - 60 * 60 * 1000).toISOString(), // 1 hour ago
      bytesIn: 1024 * 1024 * 234,
      bytesOut: 1024 * 1024 * 156,
      obfuscationMethod: 'DNS Tunnel',
      status: 'idle',
    },
  ])

  // Base notification data (without translations)
  const [alertsData, setAlertsData] = useState<Array<{
    id: string
    type: 'warning' | 'error' | 'info'
    messageKey: string
    params: Record<string, string>
    timestamp: string
  }>>([
    {
      id: '1',
      type: 'warning',
      messageKey: 'dashboard.securityAlerts.dpiDetected',
      params: { region: 'CN' },
      timestamp: new Date(Date.now() - 5 * 60 * 1000).toISOString(), // 5 minutes ago
    },
    {
      id: '2',
      type: 'info',
      messageKey: 'dashboard.securityAlerts.obfuscationSwitched',
      params: { username: 'bob.wilson' },
      timestamp: new Date(Date.now() - 12 * 60 * 1000).toISOString(), // 12 minutes ago
    },
    {
      id: '3',
      type: 'error',
      messageKey: 'dashboard.securityAlerts.connectionBlocked',
      params: { ip: '192.168.1.200' },
      timestamp: new Date(Date.now() - 25 * 60 * 1000).toISOString(), // 25 minutes ago
    },
    {
      id: '4',
      type: 'warning',
      messageKey: 'dashboard.securityAlerts.authFailure',
      params: { ip: '10.0.0.15' },
      timestamp: new Date(Date.now() - 45 * 60 * 1000).toISOString(), // 45 minutes ago
    },
  ])

  const [isUpdating, setIsUpdating] = useState(false)
  const [lastUpdate, setLastUpdate] = useState(new Date())

  // Generate localized notifications dynamically
  const alerts: SecurityAlert[] = alertsData.map(alert => ({
    id: alert.id,
    type: alert.type,
    message: t(alert.messageKey, alert.params),
    timestamp: alert.timestamp,
  }))

  // Functions for generating random data
  const generateRandomStats = useCallback((): SystemStats => {
    const baseStats = {
      activeConnections: Math.floor(Math.random() * 50) + 120, // 120-170
      totalUsers: Math.floor(Math.random() * 100) + 300, // 300-400
      securityScore: Math.floor(Math.random() * 10) + 90, // 90-100
      averageSpeed: Math.floor(Math.random() * 30) + 70, // 70-100
      storageUsed: Math.floor(Math.random() * 30) + 40, // 40-70
      obfuscationActive: Math.random() > 0.1, // 90% chance active
      dpiDetected: Math.random() < 0.2, // 20% chance detected
      uptime: '15 days 4 hours', // Keep static for now
      networkLatency: Math.floor(Math.random() * 20) + 5, // 5-25ms
    }
    return baseStats
  }, [])

  const generateRandomConnection = useCallback((): Connection => {
    const usernames = ['alice.cooper', 'mike.johnson', 'sarah.connor', 'david.smith', 'emma.watson']
    const countries = ['US', 'DE', 'FR', 'JP', 'CA', 'AU', 'UK', 'NL']
    const methods = ['TLS Tunnel', 'HTTP Mimicry', 'DNS Tunnel', 'XOR Obfuscation']
    const statuses: ('active' | 'idle' | 'disconnecting')[] = ['active', 'idle', 'disconnecting']
    
    const username = usernames[Math.floor(Math.random() * usernames.length)]
    const country = countries[Math.floor(Math.random() * countries.length)]
    const method = methods[Math.floor(Math.random() * methods.length)]
    const status = statuses[Math.floor(Math.random() * statuses.length)]
    
    return {
      id: Math.random().toString(36).substr(2, 9),
      username: username || 'unknown',
      ip: `192.168.1.${Math.floor(Math.random() * 200) + 50}`,
      country: country || 'US',
      connected: new Date(Date.now() - Math.random() * 4 * 60 * 60 * 1000).toISOString(),
      bytesIn: Math.floor(Math.random() * 500) * 1024 * 1024,
      bytesOut: Math.floor(Math.random() * 200) * 1024 * 1024,
      obfuscationMethod: method || 'TLS Tunnel',
      status: status || 'active',
    }
  }, [])

  const generateRandomAlert = useCallback(() => {
    const alertTypes = [
      {
        type: 'warning' as const,
        messageKey: 'dashboard.securityAlerts.dpiDetected',
        params: { region: ['CN', 'RU', 'IR', 'TR'][Math.floor(Math.random() * 4)] || 'CN' },
      },
      {
        type: 'info' as const,
        messageKey: 'dashboard.securityAlerts.obfuscationSwitched',
        params: { username: ['alice.cooper', 'mike.johnson', 'sarah.connor'][Math.floor(Math.random() * 3)] || 'unknown' },
      },
      {
        type: 'error' as const,
        messageKey: 'dashboard.securityAlerts.connectionBlocked',
        params: { ip: `192.168.1.${Math.floor(Math.random() * 200) + 50}` },
      },
      {
        type: 'warning' as const,
        messageKey: 'dashboard.securityAlerts.authFailure',
        params: { ip: `10.0.0.${Math.floor(Math.random() * 200) + 10}` },
      },
      {
        type: 'info' as const,
        messageKey: 'dashboard.securityAlerts.newConnection',
        params: { 
          country: ['United States', 'Germany', 'France', 'Japan'][Math.floor(Math.random() * 4)] || 'United States',
          ip: `192.168.1.${Math.floor(Math.random() * 200) + 50}`
        },
      },
    ]
    
    const randomAlert = alertTypes[Math.floor(Math.random() * alertTypes.length)]
    if (!randomAlert) {
      return {
        id: Math.random().toString(36).substr(2, 9),
        type: 'info' as const,
        messageKey: 'dashboard.securityAlerts.dpiDetected',
        params: { region: 'CN' },
        timestamp: new Date().toISOString(),
      }
    }
    
    return {
      id: Math.random().toString(36).substr(2, 9),
      type: randomAlert.type,
      messageKey: randomAlert.messageKey,
      params: randomAlert.params,
      timestamp: new Date().toISOString(),
    }
  }, [])

  // Data update function
  const updateData = useCallback(() => {
    setIsUpdating(true)
    
    // Update statistics
    setStats(generateRandomStats())
    
    // Sometimes add new connection
    if (Math.random() < 0.3) {
      setConnections(prev => {
        const newConnection = generateRandomConnection()
        const updated = [newConnection, ...prev.slice(0, 4)] // Keep max 5 connections
        return updated
      })
    } else {
      // Update traffic for existing connections
      setConnections(prev => prev.map(conn => ({
        ...conn,
        bytesIn: conn.bytesIn + Math.floor(Math.random() * 10) * 1024 * 1024,
        bytesOut: conn.bytesOut + Math.floor(Math.random() * 5) * 1024 * 1024,
      })))
    }
    
    // Sometimes add new notification
    if (Math.random() < 0.4) {
      const newAlert = generateRandomAlert()
      setAlertsData(prev => [newAlert, ...prev.slice(0, 3)]) // Keep max 4 notifications
    }
    
    setLastUpdate(new Date())
    
    // Remove update indicator after short time
    setTimeout(() => setIsUpdating(false), 500)
  }, [generateRandomStats, generateRandomConnection, generateRandomAlert])

  // Auto-update every 5 seconds
  useEffect(() => {
    const interval = setInterval(updateData, 5000)
    return () => clearInterval(interval)
  }, [updateData])

  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB']
    if (bytes === 0) return '0 B'
    const i = Math.floor(Math.log(bytes) / Math.log(1024))
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
  }

  const handleRefresh = () => {
    updateData()
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('dashboard.title')}
        </Typography>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Typography variant="caption" color="text.secondary">
            {t('common.timeAgo.justNow')}: {lastUpdate.toLocaleTimeString()}
          </Typography>
          <Tooltip title={t('dashboard.refreshData')}>
            <IconButton 
              onClick={handleRefresh} 
              color="primary"
              disabled={isUpdating}
              sx={{
                animation: isUpdating ? 'spin 1s linear infinite' : 'none',
                '@keyframes spin': {
                  '0%': { transform: 'rotate(0deg)' },
                  '100%': { transform: 'rotate(360deg)' },
                },
              }}
            >
              <RefreshIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Box>

      {/* Main metrics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title={t('dashboard.activeConnections')}
            value={stats.activeConnections}
            subtitle={`${t('network.of')} ${stats.totalUsers} ${t('dashboard.totalUsers').toLowerCase()}`}
            icon={<PeopleIcon sx={{ fontSize: 40 }} />}
            color="primary"
            status="online"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title={t('dashboard.security')}
            value={`${stats.securityScore}%`}
            subtitle={t('dashboard.securityLevel')}
            icon={<SecurityIcon sx={{ fontSize: 40 }} />}
            color="success"
            progress={stats.securityScore}
            status={stats.securityScore > 95 ? 'online' : 'warning'}
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title={t('dashboard.averageSpeed')}
            value={`${stats.averageSpeed} Mbps`}
            subtitle={`${t('dashboard.latency')}: ${stats.networkLatency}ms`}
            icon={<SpeedIcon sx={{ fontSize: 40 }} />}
            color="info"
            status="online"
          />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <StatCard
            title={t('dashboard.diskUsage')}
            value={`${stats.storageUsed}%`}
            subtitle={t('dashboard.logsAndConfigs')}
            icon={<StorageIcon sx={{ fontSize: 40 }} />}
            color={stats.storageUsed > 80 ? 'warning' : 'success'}
            progress={stats.storageUsed}
            status={stats.storageUsed > 90 ? 'warning' : 'online'}
          />
        </Grid>
      </Grid>

      {/* System status */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <ShieldIcon />
                {t('dashboard.obfuscationStatus')}
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography>{t('dashboard.obfuscationActive')}</Typography>
                  <Chip 
                    icon={stats.obfuscationActive ? <CheckCircleIcon /> : <ErrorIcon />}
                    label={stats.obfuscationActive ? t('common.enabled') : t('common.disabled')}
                    color={stats.obfuscationActive ? 'success' : 'error'}
                    variant="outlined"
                  />
                </Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography>{t('dashboard.dpiDetection')}</Typography>
                  <Chip 
                    icon={stats.dpiDetected ? <WarningIcon /> : <CheckCircleIcon />}
                    label={stats.dpiDetected ? t('dashboard.detected') : t('dashboard.notDetected')}
                    color={stats.dpiDetected ? 'warning' : 'success'}
                    variant="outlined"
                  />
                </Box>
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography>{t('dashboard.uptime')}</Typography>
                  <Typography color="text.secondary">{stats.uptime}</Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={6}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <WarningIcon />
                {t('dashboard.securityNotifications')}
              </Typography>
              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                {alerts.map((alert, index) => (
                  <Fade in={true} timeout={300 + index * 100} key={alert.id}>
                    <Alert 
                      severity={alert.type}
                      sx={{ fontSize: '0.875rem' }}
                    >
                      <Box>
                        <Typography variant="body2">{alert.message}</Typography>
                        <Typography variant="caption" color="text.secondary">
                          {formatRelativeTime(alert.timestamp, t)}
                        </Typography>
                      </Box>
                    </Alert>
                  </Fade>
                ))}
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Active connections */}
      <Card>
        <CardContent>
          <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <NetworkIcon />
            {t('dashboard.activeConnectionsTable')}
          </Typography>
          <TableContainer>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell>{t('dashboard.user')}</TableCell>
                  <TableCell>{t('dashboard.ipAddress')}</TableCell>
                  <TableCell>{t('dashboard.country')}</TableCell>
                  <TableCell>{t('dashboard.connectedTime')}</TableCell>
                  <TableCell>{t('dashboard.traffic')} ↓/↑</TableCell>
                  <TableCell>{t('dashboard.obfuscationMethod')}</TableCell>
                  <TableCell>{t('common.status')}</TableCell>
                  <TableCell>{t('common.actions')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {connections.map((connection) => (
                  <TableRow key={connection.id}>
                    <TableCell>{connection.username}</TableCell>
                    <TableCell>
                      <Typography variant="body2" fontFamily="monospace">
                        {connection.ip}
                      </Typography>
                    </TableCell>
                    <TableCell>{connection.country}</TableCell>
                    <TableCell>{formatRelativeTime(connection.connected, t)}</TableCell>
                    <TableCell>
                      <Typography variant="body2">
                        {formatBytes(connection.bytesIn)} / {formatBytes(connection.bytesOut)}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={connection.obfuscationMethod}
                        size="small"
                        variant="outlined"
                        color="primary"
                      />
                    </TableCell>
                    <TableCell>
                      <Chip 
                        label={t(`common.${connection.status}`)}
                        size="small"
                        color={
                          connection.status === 'active' ? 'success' : 
                          connection.status === 'idle' ? 'warning' : 'error'
                        }
                      />
                    </TableCell>
                    <TableCell>
                      <Tooltip title={t('common.view')}>
                        <IconButton size="small" color="primary">
                          <VisibilityIcon />
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
    </Box>
  )
} 