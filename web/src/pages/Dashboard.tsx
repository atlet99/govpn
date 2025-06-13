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
import { apiClient } from '@/services/api'

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

interface AlertData {
  id: string
  type: 'success' | 'warning' | 'error' | 'info'
  title: string
  message: string
  timestamp: string
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
    activeConnections: 0,
    totalUsers: 0,
    securityScore: 95,
    averageSpeed: 0,
    storageUsed: 45,
    obfuscationActive: true,
    dpiDetected: false,
    uptime: '0 minutes',
    networkLatency: 12,
  })

  const [connections, setConnections] = useState<Connection[]>([])
  const [isUpdating, setIsUpdating] = useState(false)
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date())
  const [alertsData, setAlertsData] = useState<AlertData[]>([])

  // Load real data from API
  const loadData = useCallback(async () => {
    try {
      setIsUpdating(true)

      // Load server status
      const statusResponse = await apiClient.getStatus()
      if (statusResponse.success && statusResponse.data) {
        const serverStatus = statusResponse.data
        setStats(prev => ({
          ...prev,
          activeConnections: serverStatus.clientCount || 0,
          uptime: serverStatus.startTime ? formatUptime(Date.now() - Number(serverStatus.startTime) * 1000) : 'Unknown',
        }))
      }

      // Load connections
      const connectionsResponse = await apiClient.getConnections()
      if (connectionsResponse.success && connectionsResponse.data) {
        const apiConnections = connectionsResponse.data.map(conn => ({
          id: conn.id,
          username: conn.username,
          ip: conn.virtualIP,
          country: conn.location || 'Unknown',
          connected: conn.connectedAt,
          bytesIn: conn.bytesIn,
          bytesOut: conn.bytesOut,
          obfuscationMethod: conn.obfuscationMethod || 'None',
          status: conn.status === 'connected' ? 'active' as const : 'idle' as const,
        }))
        setConnections(apiConnections)
      }

      // Load users count
      const usersResponse = await apiClient.getUsers()
      if (usersResponse.success && usersResponse.data && Array.isArray(usersResponse.data)) {
        setStats(prev => ({
          ...prev,
          totalUsers: usersResponse.data!.length,
        }))
      }

      setLastUpdate(new Date())
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
      // Add error alert
      const errorAlert: AlertData = {
        id: Math.random().toString(36).substr(2, 9),
        type: 'error',
        title: 'Connection Error',
        message: 'Failed to load dashboard data from server',
        timestamp: new Date().toISOString(),
      }
      setAlertsData(prev => [errorAlert, ...prev.slice(0, 3)])
    } finally {
      setIsUpdating(false)
    }
  }, [])

  // Initial load
  useEffect(() => {
    loadData()
  }, [loadData])

  // Auto-refresh every 10 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      loadData()
    }, 10000)
    return () => clearInterval(interval)
  }, [loadData])

  const formatUptime = (milliseconds: number) => {
    const seconds = Math.floor(milliseconds / 1000)
    const minutes = Math.floor(seconds / 60)
    const hours = Math.floor(minutes / 60)
    const days = Math.floor(hours / 24)

    if (days > 0) {
      return `${days} days ${hours % 24} hours`
    } else if (hours > 0) {
      return `${hours} hours ${minutes % 60} minutes`
    } else {
      return `${minutes} minutes`
    }
  }

  const formatBytes = (bytes: number) => {
    const sizes = ['B', 'KB', 'MB', 'GB']
    if (bytes === 0) return '0 B'
    const i = Math.floor(Math.log(bytes) / Math.log(1024))
    return Math.round(bytes / Math.pow(1024, i) * 100) / 100 + ' ' + sizes[i]
  }

  const formatRelativeTime = (timestamp: string) => {
    const now = new Date()
    const time = new Date(timestamp)
    const diffInMinutes = Math.floor((now.getTime() - time.getTime()) / (1000 * 60))

    if (diffInMinutes < 60) {
      return `${diffInMinutes}m ago`
    } else if (diffInMinutes < 24 * 60) {
      const hours = Math.floor(diffInMinutes / 60)
      return `${hours}h ago`
    } else {
      const days = Math.floor(diffInMinutes / (24 * 60))
      return `${days}d ago`
    }
  }

  const handleRefresh = () => {
    loadData()
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
                {alertsData.map((alert, index) => (
                  <Fade in={true} timeout={300 + index * 100} key={alert.id}>
                    <Alert 
                      severity={alert.type}
                      sx={{ fontSize: '0.875rem' }}
                    >
                      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <Box sx={{ flex: 1 }}>
                          <Typography variant="body2" color="text.primary" sx={{ fontWeight: 500 }}>
                            {alert.title}
                          </Typography>
                          <Typography variant="caption" color="text.secondary">
                            {alert.message}
                          </Typography>
                        </Box>
                        <Typography variant="caption" color="text.secondary" sx={{ ml: 1, whiteSpace: 'nowrap' }}>
                          {formatRelativeTime(alert.timestamp)}
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
                    <TableCell>{formatRelativeTime(connection.connected)}</TableCell>
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