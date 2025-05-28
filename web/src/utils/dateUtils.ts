export const formatDate = (date: Date | string, language: string, includeTime = false): string => {
  const dateObj = typeof date === 'string' ? new Date(date) : date
  
  if (isNaN(dateObj.getTime())) {
    return ''
  }

  if (language === 'en') {
    // English format
    if (includeTime) {
      return dateObj.toLocaleString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      }).replace(/(\d+)\/(\d+)\/(\d+),/, '$3-$1-$2')
    } else {
      return dateObj.toLocaleDateString('en-US', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      }).replace(/(\d+)\/(\d+)\/(\d+)/, '$3-$1-$2')
    }
  } else {
    // Russian format
    if (includeTime) {
      return dateObj.toLocaleString('ru-RU', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      })
    } else {
      return dateObj.toLocaleDateString('ru-RU', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit'
      })
    }
  }
}

export const formatRelativeTime = (date: Date | string, t: (key: string, options?: any) => string): string => {
  const dateObj = typeof date === 'string' ? new Date(date) : date
  const now = new Date()
  const diffMs = now.getTime() - dateObj.getTime()
  const diffMinutes = Math.floor(diffMs / (1000 * 60))
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
  const diffWeeks = Math.floor(diffMs / (1000 * 60 * 60 * 24 * 7))

  if (diffMinutes < 1) {
    return t('common.timeAgo.justNow') || 'just now'
  } else if (diffMinutes < 60) {
    return t('common.timeAgo.minutesAgo', { count: diffMinutes }) || `${diffMinutes} minutes ago`
  } else if (diffHours < 24) {
    return t('common.timeAgo.hoursAgo', { count: diffHours }) || `${diffHours} hours ago`
  } else if (diffDays < 7) {
    return t('common.timeAgo.daysAgo', { count: diffDays }) || `${diffDays} days ago`
  } else {
    return t('common.timeAgo.weeksAgo', { count: diffWeeks }) || `${diffWeeks} weeks ago`
  }
}

export const formatDateForInput = (date: Date | string): string => {
  const dateObj = typeof date === 'string' ? new Date(date) : date
  
  if (isNaN(dateObj.getTime())) {
    return ''
  }

  // Always return in YYYY-MM-DD format for HTML input
  const isoString = dateObj.toISOString()
  const datePart = isoString.split('T')[0]
  return datePart || ''
}

export const parseDateFromInput = (dateString: string): Date | null => {
  if (!dateString) return null
  
  const date = new Date(dateString + 'T00:00:00')
  return isNaN(date.getTime()) ? null : date
} 