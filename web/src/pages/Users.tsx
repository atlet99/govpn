import { useState, useEffect } from 'react'
import { useTranslation } from 'react-i18next'
import {
  Box,
  Button,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
  Chip,
  IconButton,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  TextField,
  MenuItem,
  FormControl,
  InputLabel,
  Select,
  Alert,
  Snackbar,
  Tooltip,
  Card,
  CardContent,
  Grid,
  Avatar,
} from '@mui/material'
import {
  Add as AddIcon,
  Edit as EditIcon,
  Delete as DeleteIcon,
  Refresh as RefreshIcon,
  People as PeopleIcon,
  PersonAdd as PersonAddIcon,
  PersonOff as PersonOffIcon,
  Check as CheckIcon,
  Close as CloseIcon,
} from '@mui/icons-material'

interface User {
  id: string
  username: string
  email: string
  role: 'admin' | 'user' | 'viewer'
  status: 'active' | 'inactive' | 'suspended'
  lastLogin: string
  createdAt: string
  updatedAt: string
}

interface CreateUserData {
  username: string
  email: string
  password: string
  role: 'admin' | 'user' | 'viewer'
  status: 'active' | 'inactive' | 'suspended'
}

const mockUsers: User[] = [
  {
    id: '1',
    username: 'admin',
    email: 'admin@govpn.com',
    role: 'admin',
    status: 'active',
    lastLogin: '2024-03-20 15:30:00',
    createdAt: '2024-01-15 10:00:00',
    updatedAt: '2024-03-20 15:30:00',
  },
  {
    id: '2',
    username: 'john.doe',
    email: 'john.doe@company.com',
    role: 'user',
    status: 'active',
    lastLogin: '2024-03-20 14:45:00',
    createdAt: '2024-02-01 09:15:00',
    updatedAt: '2024-03-15 11:20:00',
  },
  {
    id: '3',
    username: 'jane.smith',
    email: 'jane.smith@company.com',
    role: 'user',
    status: 'inactive',
    lastLogin: '2024-03-18 16:20:00',
    createdAt: '2024-02-10 14:30:00',
    updatedAt: '2024-03-18 16:20:00',
  },
  {
    id: '4',
    username: 'bob.wilson',
    email: 'bob.wilson@company.com',
    role: 'viewer',
    status: 'suspended',
    lastLogin: '2024-03-17 09:00:00',
    createdAt: '2024-03-01 08:45:00',
    updatedAt: '2024-03-19 13:15:00',
  },
]

export default function Users() {
  const { t } = useTranslation()
  const [users, setUsers] = useState<User[]>(mockUsers)
  const [loading, setLoading] = useState(false)
  const [openDialog, setOpenDialog] = useState(false)
  const [editingUser, setEditingUser] = useState<User | null>(null)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [userToDelete, setUserToDelete] = useState<User | null>(null)
  const [snackbar, setSnackbar] = useState({ open: false, message: '', severity: 'success' as 'success' | 'error' })
  
  const [formData, setFormData] = useState<CreateUserData>({
    username: '',
    email: '',
    password: '',
    role: 'user',
    status: 'active',
  })

  useEffect(() => {
    loadUsers()
  }, [])

  const loadUsers = async () => {
    setLoading(true)
    try {
      // TODO: Replace with actual API call
      // const response = await fetch('/api/v1/users')
      // const data = await response.json()
      // setUsers(data.users)
      
      // Simulating API delay
      await new Promise(resolve => setTimeout(resolve, 1000))
      setUsers(mockUsers)
    } catch (error) {
      console.error('Error loading users:', error)
      showSnackbar(t('common.loadError'), 'error')
    } finally {
      setLoading(false)
    }
  }

  const showSnackbar = (message: string, severity: 'success' | 'error') => {
    setSnackbar({ open: true, message, severity })
  }

  const handleCreateUser = async () => {
    try {
      // TODO: Replace with actual API call
      // const response = await fetch('/api/v1/users', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(formData)
      // })
      
      const newUser: User = {
        id: Date.now().toString(),
        ...formData,
        lastLogin: '',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }
      
      setUsers([...users, newUser])
      setOpenDialog(false)
      resetForm()
      showSnackbar(t('users.createSuccess'), 'success')
    } catch (error) {
      console.error('Error creating user:', error)
      showSnackbar(t('users.createError'), 'error')
    }
  }

  const handleUpdateUser = async () => {
    if (!editingUser) return
    
    try {
      // TODO: Replace with actual API call
      const updatedUser = {
        ...editingUser,
        ...formData,
        updatedAt: new Date().toISOString(),
      }
      
      setUsers(users.map(u => u.id === editingUser.id ? updatedUser : u))
      setOpenDialog(false)
      setEditingUser(null)
      resetForm()
      showSnackbar(t('users.updateSuccess'), 'success')
    } catch (error) {
      console.error('Error updating user:', error)
      showSnackbar(t('users.updateError'), 'error')
    }
  }

  const handleDeleteUser = async () => {
    if (!userToDelete) return
    
    try {
      // TODO: Replace with actual API call
      setUsers(users.filter(u => u.id !== userToDelete.id))
      setDeleteConfirmOpen(false)
      setUserToDelete(null)
      showSnackbar(t('users.deleteSuccess'), 'success')
    } catch (error) {
      console.error('Error deleting user:', error)
      showSnackbar(t('users.deleteError'), 'error')
    }
  }

  const resetForm = () => {
    setFormData({
      username: '',
      email: '',
      password: '',
      role: 'user',
      status: 'active',
    })
  }

  const openCreateDialog = () => {
    resetForm()
    setEditingUser(null)
    setOpenDialog(true)
  }

  const openEditDialog = (user: User) => {
    setFormData({
      username: user.username,
      email: user.email,
      password: '',
      role: user.role,
      status: user.status,
    })
    setEditingUser(user)
    setOpenDialog(true)
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'success'
      case 'inactive': return 'default'
      case 'suspended': return 'error'
      default: return 'default'
    }
  }

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'primary'
      case 'user': return 'secondary' 
      case 'viewer': return 'default'
      default: return 'default'
    }
  }

  const formatDate = (dateString: string) => {
    if (!dateString) return t('common.never')
    return new Date(dateString).toLocaleDateString() + ' ' + new Date(dateString).toLocaleTimeString()
  }

  const stats = {
    total: users.length,
    active: users.filter(u => u.status === 'active').length,
    inactive: users.filter(u => u.status === 'inactive').length,
    suspended: users.filter(u => u.status === 'suspended').length,
  }

  return (
    <Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
        <Typography variant="h4" gutterBottom>
          {t('users.title')}
        </Typography>
        <Box sx={{ display: 'flex', gap: 2 }}>
          <Button
            variant="outlined"
            startIcon={<RefreshIcon />}
            onClick={loadUsers}
            disabled={loading}
          >
            {t('common.refresh')}
          </Button>
          <Button
            variant="contained"
            startIcon={<AddIcon />}
            onClick={openCreateDialog}
          >
            {t('users.addUser')}
          </Button>
        </Box>
      </Box>

      {/* Statistics Cards */}
      <Grid container spacing={3} sx={{ mb: 3 }}>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Avatar sx={{ bgcolor: 'primary.main' }}>
                <PeopleIcon />
              </Avatar>
              <Box>
                <Typography color="text.secondary" gutterBottom>
                  {t('users.totalUsers')}
                </Typography>
                <Typography variant="h5">{stats.total}</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Avatar sx={{ bgcolor: 'success.main' }}>
                <CheckIcon />
              </Avatar>
              <Box>
                <Typography color="text.secondary" gutterBottom>
                  {t('users.activeUsers')}
                </Typography>
                <Typography variant="h5">{stats.active}</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Avatar sx={{ bgcolor: 'grey.500' }}>
                <PersonOffIcon />
              </Avatar>
              <Box>
                <Typography color="text.secondary" gutterBottom>
                  {t('users.inactiveUsers')}
                </Typography>
                <Typography variant="h5">{stats.inactive}</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <Card>
            <CardContent sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Avatar sx={{ bgcolor: 'error.main' }}>
                <CloseIcon />
              </Avatar>
              <Box>
                <Typography color="text.secondary" gutterBottom>
                  {t('users.suspendedUsers')}
                </Typography>
                <Typography variant="h5">{stats.suspended}</Typography>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Users Table */}
      <TableContainer component={Paper}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>{t('users.username')}</TableCell>
              <TableCell>{t('users.email')}</TableCell>
              <TableCell>{t('users.role')}</TableCell>
              <TableCell>{t('common.status')}</TableCell>
              <TableCell>{t('users.lastLogin')}</TableCell>
              <TableCell>{t('users.createdAt')}</TableCell>
              <TableCell>{t('common.actions')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((user) => (
              <TableRow key={user.id} hover>
                <TableCell>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                    <Avatar sx={{ width: 32, height: 32 }}>
                      {user.username.charAt(0).toUpperCase()}
                    </Avatar>
                    {user.username}
                  </Box>
                </TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>
                  <Chip
                    label={t(`users.roles.${user.role}`)}
                    color={getRoleColor(user.role) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={t(`users.statuses.${user.status}`)}
                    color={getStatusColor(user.status) as any}
                    size="small"
                  />
                </TableCell>
                <TableCell>{formatDate(user.lastLogin)}</TableCell>
                <TableCell>{formatDate(user.createdAt)}</TableCell>
                <TableCell>
                  <Tooltip title={t('common.edit')}>
                    <IconButton
                      size="small"
                      onClick={() => openEditDialog(user)}
                    >
                      <EditIcon />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title={t('common.delete')}>
                    <IconButton
                      size="small"
                      color="error"
                      onClick={() => {
                        setUserToDelete(user)
                        setDeleteConfirmOpen(true)
                      }}
                    >
                      <DeleteIcon />
                    </IconButton>
                  </Tooltip>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create/Edit User Dialog */}
      <Dialog open={openDialog} onClose={() => setOpenDialog(false)} maxWidth="sm" fullWidth>
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {editingUser ? <EditIcon /> : <PersonAddIcon />}
            {editingUser ? t('users.editUser') : t('users.createUser')}
          </Box>
        </DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
            <TextField
              label={t('users.username')}
              value={formData.username}
              onChange={(e) => setFormData({ ...formData, username: e.target.value })}
              fullWidth
              required
            />
            <TextField
              label={t('users.email')}
              type="email"
              value={formData.email}
              onChange={(e) => setFormData({ ...formData, email: e.target.value })}
              fullWidth
              required
            />
            {!editingUser && (
              <TextField
                label={t('users.password')}
                type="password"
                value={formData.password}
                onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                fullWidth
                required
              />
            )}
            <FormControl fullWidth>
              <InputLabel>{t('users.role')}</InputLabel>
              <Select
                value={formData.role}
                label={t('users.role')}
                onChange={(e) => setFormData({ ...formData, role: e.target.value as any })}
              >
                <MenuItem value="admin">{t('users.roles.admin')}</MenuItem>
                <MenuItem value="user">{t('users.roles.user')}</MenuItem>
                <MenuItem value="viewer">{t('users.roles.viewer')}</MenuItem>
              </Select>
            </FormControl>
            <FormControl fullWidth>
              <InputLabel>{t('common.status')}</InputLabel>
              <Select
                value={formData.status}
                label={t('common.status')}
                onChange={(e) => setFormData({ ...formData, status: e.target.value as any })}
              >
                <MenuItem value="active">{t('users.statuses.active')}</MenuItem>
                <MenuItem value="inactive">{t('users.statuses.inactive')}</MenuItem>
                <MenuItem value="suspended">{t('users.statuses.suspended')}</MenuItem>
              </Select>
            </FormControl>
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpenDialog(false)}>{t('common.cancel')}</Button>
          <Button
            variant="contained"
            onClick={editingUser ? handleUpdateUser : handleCreateUser}
            startIcon={editingUser ? <EditIcon /> : <AddIcon />}
          >
            {editingUser ? t('common.update') : t('common.create')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteConfirmOpen} onClose={() => setDeleteConfirmOpen(false)}>
        <DialogTitle>{t('users.deleteConfirmTitle')}</DialogTitle>
        <DialogContent>
          <Typography>
            {t('users.deleteConfirmMessage', { username: userToDelete?.username })}
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirmOpen(false)}>{t('common.cancel')}</Button>
          <Button color="error" variant="contained" onClick={handleDeleteUser}>
            {t('common.delete')}
          </Button>
        </DialogActions>
      </Dialog>

      {/* Snackbar for notifications */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar({ ...snackbar, open: false })}
      >
        <Alert severity={snackbar.severity} sx={{ width: '100%' }}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  )
} 