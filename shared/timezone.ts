// Timezone utilities for PST handling

export const PST_TIMEZONE = "America/Los_Angeles";

/**
 * Get current date in PST timezone in YYYY-MM-DD format
 */
export function getCurrentPSTDate(): string {
  const now = new Date();
  return now.toLocaleDateString('en-CA', { 
    timeZone: PST_TIMEZONE 
  });
}

/**
 * Get current time in PST timezone in HH:MM format
 */
export function getCurrentPSTTime(): string {
  const now = new Date();
  return now.toLocaleTimeString('en-US', { 
    timeZone: PST_TIMEZONE,
    hour12: false,
    hour: '2-digit',
    minute: '2-digit'
  });
}

/**
 * Convert a date string to PST date
 */
export function toPSTDate(dateString: string): string {
  const date = new Date(dateString + 'T12:00:00Z'); // Use noon UTC to avoid edge cases
  return date.toLocaleDateString('en-CA', { 
    timeZone: PST_TIMEZONE 
  });
}

/**
 * Get date range for filtering in PST
 */
export function getPSTDateRange(range: 'today' | 'week' | 'month' | 'quarter' | 'year'): { startDate: string; endDate: string } {
  const now = new Date();
  const pstDate = now.toLocaleDateString('en-CA', { timeZone: PST_TIMEZONE });
  const today = new Date(pstDate + 'T00:00:00');
  
  switch (range) {
    case 'today':
      return {
        startDate: pstDate,
        endDate: pstDate,
      };
    case 'week': {
      const startDate = new Date(today);
      startDate.setDate(today.getDate() - 7);
      return {
        startDate: startDate.toLocaleDateString('en-CA', { timeZone: PST_TIMEZONE }),
        endDate: pstDate,
      };
    }
    case 'month': {
      const startDate = new Date(today);
      startDate.setMonth(today.getMonth() - 1);
      return {
        startDate: startDate.toLocaleDateString('en-CA', { timeZone: PST_TIMEZONE }),
        endDate: pstDate,
      };
    }
    case 'quarter': {
      const startDate = new Date(today);
      startDate.setMonth(today.getMonth() - 3);
      return {
        startDate: startDate.toLocaleDateString('en-CA', { timeZone: PST_TIMEZONE }),
        endDate: pstDate,
      };
    }
    case 'year': {
      const startDate = new Date(today);
      startDate.setFullYear(today.getFullYear() - 1);
      return {
        startDate: startDate.toLocaleDateString('en-CA', { timeZone: PST_TIMEZONE }),
        endDate: pstDate,
      };
    }
    default:
      return {
        startDate: pstDate,
        endDate: pstDate,
      };
  }
}

/**
 * Format a date string for display in PST context
 */
export function formatPSTDate(dateString: string): string {
  const date = new Date(dateString + 'T12:00:00Z');
  return date.toLocaleDateString('en-US', { 
    timeZone: PST_TIMEZONE,
    month: 'short', 
    day: 'numeric', 
    year: 'numeric' 
  });
}

/**
 * Format time string for display in PST context
 */
export function formatPSTTime(timeString: string): string {
  const [hours, minutes] = timeString.split(':');
  const hour = parseInt(hours);
  const ampm = hour >= 12 ? 'PM' : 'AM';
  const displayHour = hour % 12 || 12;
  return `${displayHour}:${minutes} ${ampm}`;
}

/**
 * Get the maximum date allowed (today in PST) for date inputs
 */
export function getMaxPSTDate(): string {
  return getCurrentPSTDate();
}

/**
 * Quick date selection helper for PST
 */
export function getPSTDateOffset(daysAgo: number): string {
  const now = new Date();
  const pstDate = now.toLocaleDateString('en-CA', { timeZone: PST_TIMEZONE });
  const today = new Date(pstDate + 'T00:00:00');
  const targetDate = new Date(today);
  targetDate.setDate(today.getDate() - daysAgo);
  
  return targetDate.toLocaleDateString('en-CA', { timeZone: PST_TIMEZONE });
}