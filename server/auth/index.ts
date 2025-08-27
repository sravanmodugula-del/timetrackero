// Authentication and Authorization Module Exports

export * from './types';
export * from './permissions';  
export * from './authorization';
export * from './middleware';

// Re-export existing auth functions
export { setupAuth, isAuthenticated, getSession } from '../replitAuth';

// Main authentication check - enhanced version
export { isAuthenticated as requireAuth } from '../replitAuth';