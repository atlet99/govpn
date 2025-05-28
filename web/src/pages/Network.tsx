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
  LinearProgress,
  Tooltip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Divider,
} from '@mui/material'
import {
  NetworkCheck as NetworkCheckIcon,
  Speed as SpeedIcon,
  People as PeopleIcon,
  Router as RouterIcon,
  Warning as WarningIcon,
  CheckCircle as CheckCircleIcon,
  Error as ErrorIcon,
  Refresh as RefreshIcon,
  Block as BlockIcon,
  Visibility as VisibilityIcon,
  Close as CloseIcon,
  TrendingUp as TrendingUpIcon,
  TrendingDown as TrendingDownIcon,
} from '@mui/icons-material'

interface Connection {
  id: string
  username: string
  realIP: string
  virtualIP: string
  protocol: string
  connectedTime: string
  bytesIn: number
  bytesOut: number
  location: string
  obfuscationMethod: string
  status: 'active' | 'idle' | 'disconnecting'
}

interface NetworkStats {
  totalConnections: number
  activeConnections: number
  bandwidthUsage: number
  maxBandwidth: number
  packetsIn: number
  packetsOut: number
  errors: number
  dropped: number
}

interface TunnelInfo {
  interface: string
  ip: string
  mtu: number
  status: 'up' | 'down'
  packets: { rx: number; tx: number }
  bytes: { rx: number; tx: number }
  errors: { rx: number; tx: number }
}

export default function Network() {
  const { t } = useTranslation()
  const [connections, setConnections] = useState<Connection[]>([
    {
      id: '1',
      username: 'john.doe',
      realIP: '203.0.113.45',
      virtualIP: '10.8.0.2',
      protocol: 'WireGuard',
      connectedTime: '1h 15m',
      bytesIn: 1024 * 1024 * 234,
      bytesOut: 1024 * 1024 * 156,
      location: 'Moscow, Russia',
      obfuscationMethod: 'DNS Tunnel',
      status: 'active',
    },
    {
      id: '2',
      username: 'bob.wilson',
      realIP: '198.51.100.123',
      virtualIP: '10.8.0.3',
      protocol: 'OpenVPN',
      connectedTime: '1h 15m',
      bytesIn: 1024 * 1024 * 234,
      bytesOut: 1024 * 1024 * 156,
      location: 'Moscow, Russia',
      obfuscationMethod: 'DNS Tunnel',
      status: 'active',
    },
    {
      id: '3',
      username: 'alice.johnson',
      realIP: '192.0.2.78',
      virtualIP: '10.8.0.4',
      protocol: 'WireGuard',
      connectedTime: '1h 15m',
      bytesIn: 1024 * 1024 * 234,
      bytesOut: 1024 * 1024 * 156,
      location: 'Moscow, Russia',
      obfuscationMethod: 'DNS Tunnel',
      status: 'active',
    },
  ])

  const [networkStats, _setNetworkStats] = useState<NetworkStats>({
    totalConnections: 15,
    activeConnections: 12,
    bandwidthUsage: 75.5,
    maxBandwidth: 1000,
    packetsIn: 125893,
    packetsOut: 98432,
    errors: 23,
    dropped: 7,
  })

  const [tunnelInfo, _setTunnelInfo] = useState<TunnelInfo[]>([
    {
      interface: 'wg0',
      ip: '10.8.0.1/24',
      mtu: 1420,
      status: 'up',
      packets: { rx: 125893, tx: 98432 },
      bytes: { rx: 45678912, tx: 23456789 },
      errors: { rx: 12, tx: 11 },
    },
    {
      interface: 'tun0',
      ip: '10.9.0.1/24',
      mtu: 1500,
      status: 'up',
      packets: { rx: 67234, tx: 45123 },
      bytes: { rx: 23456789, tx: 12345678 },
      errors: { rx: 5, tx: 6 },
    },
  ])

  const [selectedConnection, setSelectedConnection] = useState<Connection | null>(null)
  const [detailsDialogOpen, setDetailsDialogOpen] = useState(false)

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success'
      case 'idle': return 'warning'
      case 'disconnecting': return 'error'
      default: return 'default'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'active': return <CheckCircleIcon color="success" />
      case 'idle': return <WarningIcon color="warning" />
      case 'disconnecting': return <ErrorIcon color="error" />
      default: return <CheckCircleIcon />
    }
  }

  const handleDisconnectUser = (connectionId: string) => {
    setConnections(connections.map(conn =>
      conn.id === connectionId ? { ...conn, status: 'disconnecting' as const } : conn
    ))
    setTimeout(() => {
      setConnections(prev => prev.filter(conn => conn.id !== connectionId))
    }, 2000)
  }

  const handleViewDetails = (connection: Connection) => {
    setSelectedConnection(connection)
    setDetailsDialogOpen(true)
  }

  const calculateTotalTraffic = () => {
    return connections.reduce((total, conn) => ({
      bytesIn: total.bytesIn + conn.bytesIn,
      bytesOut: total.bytesOut + conn.bytesOut,
    }), { bytesIn: 0, bytesOut: 0 })
  }

  const totalTraffic = calculateTotalTraffic()

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('network.title')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={() => console.log('Refreshing network stats...')}
          >
            {t('common.refresh')}
          </Button>
        </Box>
      </Box>

      {/* Overall statistics */}
      <Grid container spacing={3} sx={{ mb: 4 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <PeopleIcon color="primary" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('network.activeConnections')}
                  </Typography>
                  <Typography variant="h4">
                    {networkStats.activeConnections}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {t('network.of')} {networkStats.totalConnections} {t('network.total')}
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
                <SpeedIcon color="info" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('network.bandwidthUsage')}
                  </Typography>
                  <Typography variant="h4">
                    {networkStats.bandwidthUsage.toFixed(1)}%
                  </Typography>
                  <LinearProgress
                    variant="determinate"
                    value={networkStats.bandwidthUsage}
                    sx={{ mt: 1, width: '100%' }}
                  />
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                <TrendingUpIcon color="success" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('network.incomingTraffic')}
                  </Typography>
                  <Typography variant="h6">
                    {formatBytes(totalTraffic.bytesIn)}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {networkStats.packetsIn} {t('network.packets')}
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
                <TrendingDownIcon color="warning" sx={{ fontSize: 40 }} />
                <Box>
                  <Typography color="text.secondary" variant="body2">
                    {t('network.outgoingTraffic')}
                  </Typography>
                  <Typography variant="h6">
                    {formatBytes(totalTraffic.bytesOut)}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {networkStats.packetsOut} {t('network.packets')}
                  </Typography>
                </Box>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      <Grid container spacing={3}>
        {/* Active connections */}
        <Grid item xs={12} lg={8}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <NetworkCheckIcon />
                {t('network.activeConnections')}
              </Typography>
              <TableContainer>
                <Table>
                  <TableHead>
                    <TableRow>
                      <TableCell>{t('network.user')}</TableCell>
                      <TableCell>{t('network.realIP')}</TableCell>
                      <TableCell>{t('network.virtualIP')}</TableCell>
                      <TableCell>{t('network.protocol')}</TableCell>
                      <TableCell>{t('network.time')}</TableCell>
                      <TableCell>{t('network.traffic')}</TableCell>
                      <TableCell>{t('common.status')}</TableCell>
                      <TableCell>{t('common.actions')}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {connections.map((connection) => (
                      <TableRow key={connection.id}>
                        <TableCell>
                          <Box>
                            <Typography variant="subtitle2">{connection.username}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {connection.location}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {connection.realIP}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {connection.virtualIP}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box>
                            <Typography variant="body2">{connection.protocol}</Typography>
                            <Typography variant="caption" color="text.secondary">
                              {connection.obfuscationMethod}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Typography variant="body2" fontFamily="monospace">
                            {connection.connectedTime}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Box>
                            <Typography variant="body2">
                              ↓ {formatBytes(connection.bytesIn)}
                            </Typography>
                            <Typography variant="body2">
                              ↑ {formatBytes(connection.bytesOut)}
                            </Typography>
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                            {getStatusIcon(connection.status)}
                            <Chip
                              label={connection.status}
                              color={getStatusColor(connection.status) as any}
                              size="small"
                            />
                          </Box>
                        </TableCell>
                        <TableCell>
                          <Box sx={{ display: 'flex', gap: 1 }}>
                            <Tooltip title={t('common.details')}>
                              <IconButton size="small" onClick={() => handleViewDetails(connection)}>
                                <VisibilityIcon />
                              </IconButton>
                            </Tooltip>
                            <Tooltip title={t('network.disconnect')}>
                              <IconButton 
                                size="small" 
                                color="error"
                                onClick={() => handleDisconnectUser(connection.id)}
                              >
                                <CloseIcon />
                              </IconButton>
                            </Tooltip>
                          </Box>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </CardContent>
          </Card>
        </Grid>

        {/* Tunnel information */}
        <Grid item xs={12} lg={4}>
          <Card>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <RouterIcon />
                {t('network.tunnelStatus')}
              </Typography>
              <List>
                {tunnelInfo.map((tunnel, index) => (
                  <Box key={tunnel.interface}>
                    <ListItem>
                      <ListItemIcon>
                        {tunnel.status === 'up' ? (
                          <CheckCircleIcon color="success" />
                        ) : (
                          <ErrorIcon color="error" />
                        )}
                      </ListItemIcon>
                      <ListItemText
                        primary={
                          <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
                            <Typography variant="subtitle2">{tunnel.interface}</Typography>
                            <Chip
                              label={tunnel.status}
                              color={tunnel.status === 'up' ? 'success' : 'error'}
                              size="small"
                            />
                          </Box>
                        }
                        secondary={
                          <Box>
                            <Typography variant="caption" display="block">
                              IP: {tunnel.ip} | MTU: {tunnel.mtu}
                            </Typography>
                            <Typography variant="caption" display="block">
                              RX: {formatBytes(tunnel.bytes.rx)} ({tunnel.packets.rx} {t('network.packets')})
                            </Typography>
                            <Typography variant="caption" display="block">
                              TX: {formatBytes(tunnel.bytes.tx)} ({tunnel.packets.tx} {t('network.packets')})
                            </Typography>
                            {(tunnel.errors.rx > 0 || tunnel.errors.tx > 0) && (
                              <Typography variant="caption" color="error" display="block">
                                {t('network.errorsRxTx', { rx: tunnel.errors.rx, tx: tunnel.errors.tx })}
                              </Typography>
                            )}
                          </Box>
                        }
                      />
                    </ListItem>
                    {index < tunnelInfo.length - 1 && <Divider />}
                  </Box>
                ))}
              </List>
            </CardContent>
          </Card>

          {/* System warnings */}
          <Card sx={{ mt: 2 }}>
            <CardContent>
              <Typography variant="h6" gutterBottom sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <WarningIcon />
                {t('network.systemNotifications')}
              </Typography>
              {networkStats.errors > 0 && (
                <Alert severity="warning" sx={{ mb: 2 }}>
                  {t('network.networkErrors', { errors: networkStats.errors, dropped: networkStats.dropped })}
                </Alert>
              )}
              {networkStats.bandwidthUsage > 90 && (
                <Alert severity="error" sx={{ mb: 2 }}>
                  {t('network.highBandwidth', { usage: networkStats.bandwidthUsage.toFixed(1) })}
                </Alert>
              )}
              {networkStats.activeConnections === networkStats.totalConnections && (
                <Alert severity="info">
                  {t('network.connectionLimit')}
                </Alert>
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Connection details dialog */}
      <Dialog open={detailsDialogOpen} onClose={() => setDetailsDialogOpen(false)} maxWidth="md" fullWidth>
        <DialogTitle>{t('network.connectionDetails')}</DialogTitle>
        <DialogContent>
          {selectedConnection && (
            <Grid container spacing={2} sx={{ mt: 1 }}>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.user')}:</Typography>
                <Typography variant="body2" gutterBottom>{selectedConnection.username}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('common.status')}:</Typography>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  {getStatusIcon(selectedConnection.status)}
                  <Typography variant="body2">{selectedConnection.status}</Typography>
                </Box>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.realIP')}:</Typography>
                <Typography variant="body2" fontFamily="monospace" gutterBottom>
                  {selectedConnection.realIP}
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.virtualIP')}:</Typography>
                <Typography variant="body2" fontFamily="monospace" gutterBottom>
                  {selectedConnection.virtualIP}
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.protocol')}:</Typography>
                <Typography variant="body2" gutterBottom>{selectedConnection.protocol}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.obfuscation')}:</Typography>
                <Typography variant="body2" gutterBottom>{selectedConnection.obfuscationMethod}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.location')}:</Typography>
                <Typography variant="body2" gutterBottom>{selectedConnection.location}</Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.time')}:</Typography>
                <Typography variant="body2" gutterBottom>
                  {selectedConnection.connectedTime}
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.incomingTraffic')}:</Typography>
                <Typography variant="body2" gutterBottom>
                  {formatBytes(selectedConnection.bytesIn)}
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <Typography variant="subtitle2" gutterBottom>{t('network.outgoingTraffic')}:</Typography>
                <Typography variant="body2" gutterBottom>
                  {formatBytes(selectedConnection.bytesOut)}
                </Typography>
              </Grid>
            </Grid>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDetailsDialogOpen(false)}>{t('common.close')}</Button>
          {selectedConnection && (
            <Button
              onClick={() => handleDisconnectUser(selectedConnection.id)}
              color="error"
              variant="contained"
              startIcon={<BlockIcon />}
            >
              {t('network.disconnectUser')}
            </Button>
          )}
        </DialogActions>
      </Dialog>
    </Box>
  )
} 