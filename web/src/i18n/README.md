# Internationalization (i18n)

This project uses `react-i18next` for multiple language support.

## Structure

```
src/i18n/
├── index.ts          # i18n configuration
├── locales/
│   ├── en.json       # English translations (main language)
│   └── ru.json       # Russian translations
└── README.md         # This documentation
```

## Usage

### In components

```tsx
import { useTranslation } from 'react-i18next'

function MyComponent() {
  const { t } = useTranslation()
  
  return (
    <div>
      <h1>{t('common.title')}</h1>
      <p>{t('common.description')}</p>
    </div>
  )
}
```

### With parameters

```tsx
// In JSON file:
{
  "welcome": "Welcome, {{username}}!"
}

// In component:
{t('welcome', { username: 'John' })}
```

### Language switching

```tsx
import { useTranslation } from 'react-i18next'

function LanguageSwitcher() {
  const { i18n } = useTranslation()
  
  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng)
  }
  
  return (
    <select onChange={(e) => changeLanguage(e.target.value)}>
      <option value="en">English</option>
      <option value="ru">Русский</option>
    </select>
  )
}
```

## Translation structure

Translations are organized by sections:

- `common` - common elements (buttons, statuses, actions)
- `navigation` - navigation elements
- `auth` - authentication
- `dashboard` - main dashboard
- `users` - user management
- `network` - network monitoring
- `obfuscation` - traffic obfuscation
- `authentication` - authentication settings
- `certificates` - certificate management
- `logs` - logs and audit
- `settings` - system settings

## Adding a new language

1. Create a new file in `src/i18n/locales/` (e.g., `de.json`)
2. Copy the structure from `en.json`
3. Translate all strings
4. Add the language to configuration:

```ts
// src/i18n/index.ts
import de from './locales/de.json'

const resources = {
  en: { translation: en },
  ru: { translation: ru },
  de: { translation: de }, // New language
}
```

5. Update the `LanguageSwitcher` component:

```tsx
const languages = [
  { code: 'en', name: 'English', flag: '🇺🇸' },
  { code: 'ru', name: 'Русский', flag: '🇷🇺' },
  { code: 'de', name: 'Deutsch', flag: '🇩🇪' }, // New language
]
```

## Best practices

### Key naming
- Use dot notation: `section.subsection.key`
- Keys should be descriptive: `user.createDialog.title`
- Avoid too deep nesting (maximum 3 levels)

### Translation organization
- Group related translations in one section
- Use common keys for repeating elements
- Move frequently used phrases to `common`

### Pluralization
```json
{
  "items": "{{count}} item",
  "items_plural": "{{count}} items"
}
```

```tsx
{t('items', { count: itemCount })}
```

### Formatting
```json
{
  "lastLogin": "Last login: {{date, datetime}}"
}
```

```tsx
{t('lastLogin', { date: new Date() })}
```

## Configuration

### Auto language detection
The system automatically detects the language in the following order:
1. Saved in localStorage
2. Browser language
3. English (fallback)

### Caching
The selected language is saved in localStorage and restored on the next visit.

### Debugging
In development mode, i18n debugging is enabled. Check the browser console for translation issues.

## Components

### LanguageSwitcher
Ready-to-use component for language switching with flags and language names.

```tsx
import LanguageSwitcher from '@/components/LanguageSwitcher'

function Header() {
  return (
    <div>
      <LanguageSwitcher />
    </div>
  )
}
```

## Typing

For better typing, you can create types for translation keys:

```ts
// types/i18n.ts
export type TranslationKey = 
  | 'common.save'
  | 'common.cancel'
  | 'dashboard.title'
  // ... other keys
```

This will help avoid typos in translation keys and provide autocompletion in the IDE. 