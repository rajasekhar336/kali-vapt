/**
 * Logger Utility - VAPT Platform
 * 
 * Environment-aware logging that only outputs to console in development.
 * In production, errors are silently handled or could be sent to a
 * server-side logging service like Sentry.
 */

const isDevelopment = import.meta.env.DEV;

interface LogContext {
  [key: string]: unknown;
}

/**
 * Log an error - only outputs to console in development
 * In production, returns a generic error message
 */
export function logError(message: string, error?: unknown, context?: LogContext): void {
  if (isDevelopment) {
    console.error(`[ERROR] ${message}`, error, context);
  }
  // In production, you could send to a logging service here
  // Example: sendToLoggingService({ level: 'error', message, error, context });
}

/**
 * Log a warning - only outputs to console in development
 */
export function logWarn(message: string, context?: LogContext): void {
  if (isDevelopment) {
    console.warn(`[WARN] ${message}`, context);
  }
}

/**
 * Log info - only outputs to console in development
 */
export function logInfo(message: string, context?: LogContext): void {
  if (isDevelopment) {
    console.log(`[INFO] ${message}`, context);
  }
}

/**
 * Get a user-friendly error message for display
 * Never expose internal error details to end users
 */
export function getUserFriendlyError(error?: unknown): string {
  // Always return generic messages to users
  // The actual error is logged via logError for developers
  return 'An error occurred. Please try again.';
}

/**
 * Get user-friendly messages for specific error contexts
 */
export const ErrorMessages = {
  LOGIN_FAILED: 'Invalid username or password. Please try again.',
  SESSION_CHECK_FAILED: 'Unable to verify your session. Please log in again.',
  LOGOUT_FAILED: 'Unable to log out. Please try again.',
  LOAD_FINDINGS_FAILED: 'Unable to load findings. Please refresh the page.',
  UPDATE_STATUS_FAILED: 'Unable to update status. Please try again.',
  UPDATE_NOTES_FAILED: 'Unable to save notes. Please try again.',
  BATCH_UPDATE_FAILED: 'Unable to update selected items. Please try again.',
  LOAD_DOMAINS_FAILED: 'Unable to load domains. Please refresh the page.',
  CREATE_DOMAIN_FAILED: 'Unable to create domain. Please try again.',
  VALIDATION_ERROR: 'Please check your input and try again.',
} as const;
