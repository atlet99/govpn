import { useTranslation } from 'react-i18next'
import { DatePicker } from '@mui/x-date-pickers/DatePicker'
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider'
import { AdapterDateFns } from '@mui/x-date-pickers/AdapterDateFns'
import { ru, enUS } from 'date-fns/locale'
import { TextFieldProps } from '@mui/material'

interface LocalizedDateInputProps extends Omit<TextFieldProps, 'type' | 'value' | 'onChange'> {
  value: string
  onChange: (value: string) => void
}

export default function LocalizedDateInput({ value, onChange, ...props }: LocalizedDateInputProps) {
  const { i18n } = useTranslation()

  const isEnglish = i18n.language === 'en'
  const locale = isEnglish ? enUS : ru

  // Convert string to Date object
  const parseValue = (dateString: string): Date | null => {
    if (!dateString) return null

    if (isEnglish) {
      // English format: YYYY-MM-DD
      return new Date(dateString)
    } else {
      // Russian format: DD.MM.YYYY
      const parts = dateString.split('.')
      if (parts.length === 3 && parts[0] && parts[1] && parts[2]) {
        const day = parseInt(parts[0], 10)
        const month = parseInt(parts[1], 10) - 1 // months in Date start from 0
        const year = parseInt(parts[2], 10)
        return new Date(year, month, day)
      }
      return null
    }
  }

  // Convert Date object to string
  const formatValue = (date: Date | null): string => {
    if (!date) return ''

    if (isEnglish) {
      // English format: YYYY-MM-DD
      const isoString = date.toISOString().split('T')[0]
      return isoString || ''
    } else {
      // Russian format: DD.MM.YYYY
      const day = date.getDate().toString().padStart(2, '0')
      const month = (date.getMonth() + 1).toString().padStart(2, '0')
      const year = date.getFullYear()
      return `${day}.${month}.${year}`
    }
  }

  const handleChange = (date: Date | null) => {
    const formattedValue = formatValue(date)
    onChange(formattedValue)
  }

  const dateValue = parseValue(value)
  const inputFormat = isEnglish ? 'yyyy-MM-dd' : 'dd.MM.yyyy'
  const helperText = isEnglish ? 'Format: YYYY-MM-DD' : 'Формат: ДД.ММ.ГГГГ'
  const placeholder = isEnglish ? 'YYYY-MM-DD' : 'ДД.ММ.ГГГГ'

  return (
    <LocalizationProvider dateAdapter={AdapterDateFns} adapterLocale={locale}>
      <DatePicker
        value={dateValue}
        onChange={handleChange}
        format={inputFormat}
        slotProps={{
          textField: {
            ...props,
            helperText,
            placeholder,
            InputLabelProps: { shrink: true },
            inputProps: {
              placeholder: placeholder, // Duplicate placeholder for reliability
            },
          },
          field: {
            clearable: true,
          },
        }}
        localeText={{
          fieldYearPlaceholder: () => isEnglish ? 'YYYY' : 'ГГГГ',
          fieldMonthPlaceholder: () => isEnglish ? 'MM' : 'ММ',
          fieldDayPlaceholder: () => isEnglish ? 'DD' : 'ДД',
        }}
      />
    </LocalizationProvider>
  )
} 