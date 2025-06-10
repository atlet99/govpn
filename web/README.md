# GoVPN Web Interface

Modern administrative panel for managing GoVPN server, built with React + TypeScript + Material-UI.

## Quick Start

### Launch development environment

```bash
# From project root
./scripts/dev-start.sh
```

Or manually:

```bash
# 1. Start API server
go build -o govpn-dev-api ./cmd/dev-api
./govpn-dev-api -port 8080 -host 127.0.0.1

# 2. Start web interface
cd web
npm install
npm run dev
```

Open http://localhost:5173 in browser.

## Project Structure

```
web/
├── public/                    # Static assets
├── src/
│   ├── components/           # React components
│   │   ├── LanguageSwitcher.tsx
│   │   ├── ThemeSwitcher.tsx
│   │   └── MainLayout.tsx
│   ├── contexts/             # React contexts
│   │   ├── AuthContext.tsx
│   │   ├── SettingsContext.tsx
│   │   └── ThemeContext.tsx
│   ├── pages/                # Application pages
│   │   ├── Login.tsx
│   │   ├── Dashboard.tsx
│   │   ├── Users.tsx         # User management
│   │   ├── Network.tsx       # Network connections
│   │   ├── Certificates.tsx  # Certificate management
│   │   ├── Authentication.tsx
│   │   ├── Obfuscation.tsx
│   │   ├── Logs.tsx
│   │   └── Settings.tsx
│   ├── services/             # API clients
│   │   └── api.ts           # Typed API client
│   ├── locales/             # Translations
│   │   ├── en.json          # English (483 lines)
│   │   └── ru.json          # Russian (483 lines)
│   ├── App.tsx              # Main component
│   └── main.tsx             # Entry point
├── package.json             # Dependencies
├── tsconfig.json           # TypeScript configuration
├── vite.config.ts          # Vite configuration
└── README.md               # This documentation
```

## Main Features

### 1. User Management (`/users`)

- **User list view** with filtering and search
- **Create new users** with roles (admin/user/viewer)
- **Edit user profiles**
- **Manage statuses** (active/inactive/suspended)
- **Delete users** with confirmation
- **Statistics**: total count, active, inactive

### 2. Dashboard (`/`)

- **Real-time server statistics**
- **Connection information**
- **Traffic (inbound/outbound)**
- **Active routes**
- **Server uptime**

### 3. Network connections (`/network`)

- **List of active connections**
- **Client information**: IP addresses, protocols, traffic
- **Client geolocation**
- **Obfuscation methods**
- **Connection management**

### 4. Certificate management (`/certificates`)

- **View certificates** (CA, server, client)
- **Create new certificates**
- **Check validity and statuses**
- **Revoke certificates**
- **Algorithm and serial number information**

### 5. Authentication settings (`/authentication`)

- **Configure authentication methods**
- **LDAP/OIDC integration**
- **Multi-factor authentication (MFA)**
- **Session management**

### 6. Obfuscation settings (`/obfuscation`)

- **Configure obfuscation methods**
- **Regional profiles**
- **DPI bypass**
- **Effectiveness statistics**

### 7. System logs (`/logs`)

- **Real-time log viewing**
- **Filter by levels and components**
- **Content search**
- **Log export**

### 8. Settings (`/settings`)

- **Server configuration**
- **Network settings**
- **Security**
- **Backup**

## Internationalization

Full multi-language support:

- **Russian language**: 483 lines of translations
- **English language**: 483 lines of translations
- **Dynamic language switching**
- **Save user preferences** in localStorage

### Translation structure

```json
{
  "common": {
    "save": "Save",
    "cancel": "Cancel",
    "delete": "Delete",
    // ... common translations
  },
  "navigation": {
    "dashboard": "Dashboard",
    "users": "Users",
    // ... navigation
  },
  "users": {
    "title": "User Management",
    "createUser": "Create User",
    // ... translations for users page
  }
  // ... other sections
}
```

## UI/UX Design

### Material-UI components

- **Cards** for information grouping
- **Chips** for statuses and roles
- **Dialogs** for modal windows
- **Snackbars** for notifications
- **Data tables** with sorting and filtering
- **Icons** for intuitive understanding

### Themes

- **Light theme** (default)
- **Dark theme**
- **System theme** (automatic switching)
- **Save preferences**

### Responsiveness

- **Desktop** - full functionality
- **Tablet** - adapted interface
- **Mobile** - optimized display

## API Integration

### Typed API client

```typescript
// Example of API client usage
import { api } from '../services/api'

// Get users
const response = await api.getUsers()
if (response.success) {
  setUsers(response.data)
}

// Create user
const newUser = await api.createUser({
  username: 'john.doe',
  email: 'john@example.com',
  password: 'secure_password',
  role: 'user',
  status: 'active'
})
```

### Data interfaces

```typescript
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

interface ServerStatus {
  running: boolean
  clientCount: number
  bytesIn: number
  bytesOut: number
  activeRoutes: string[]
  startTime: string
  uptime: number
}
```

## 🔐 Security

### Authentication

- **JWT tokens** for authorization
- **Automatic token refresh**
- **Secure storage** in localStorage
- **Automatic logout** on session expiration

### Protected routes

```typescript
// Protected route component
<ProtectedRoute>
  <UsersPage />
</ProtectedRoute>
```

## 📦 Dependencies

### Main

- **React 18** - UI library
- **TypeScript** - typing
- **Material-UI (MUI)** - design system
- **React Router** - routing
- **i18next** - internationalization
- **Vite** - bundler

### Development tools

- **ESLint** - linter
- **Prettier** - code formatting
- **TypeScript** - type checking

## 🚀 Deployment

### Development

```bash
npm run dev         # Start dev server
npm run build       # Build for production
npm run preview     # Preview build
```

### Production

```bash
# Build
npm run build

# Result in dist/ folder
# Can be deployed to any web server (nginx, apache, etc.)
```

## 🧪 Testing

```bash
npm run test        # Run tests (when added)
npm run lint        # Code check
npm run type-check  # TypeScript type check
```

## 🔧 Configuration

### Environment variables

```env
VITE_API_URL=http://localhost:8080/api/v1  # API server URL
```

### Vite configuration

```typescript
// vite.config.ts
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8080'  // API proxying
    }
  }
})
```

## 📈 Monitoring and metrics

- **Performance monitoring** via browser DevTools
- **Network request** tracking
- **Error tracking** in console
- **Bundle size analysis**

## 🤝 Development

### Adding a new page

1. Create component in `src/pages/`
2. Add translations in `src/locales/`
3. Add route in `App.tsx`
4. Add navigation in `MainLayout.tsx`

### Adding API endpoint

1. Add interfaces in `src/services/api.ts`
2. Add methods in `ApiClient` class
3. Use in components

### Coding style

- **TypeScript** strict typing
- **Functional components** with hooks
- **Material-UI** for styling
- **i18next** for texts

---

**GoVPN Web Interface** - full-featured administrative panel, ready for production use! 🚀 