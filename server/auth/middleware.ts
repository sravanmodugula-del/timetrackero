import type { RequestHandler } from 'express';
import { isAuthenticated as baseIsAuthenticated } from '../replitAuth';
import { createAuthContextMiddleware } from './authorization';
import { storage } from '../storage';

// Combined middleware that checks authentication and builds auth context
export const requireAuthWithContext: RequestHandler = async (req, res, next) => {
  // First check authentication
  baseIsAuthenticated(req, res, (err?: any) => {
    if (err) return next(err);
    
    // Then attach auth context
    const attachContext = createAuthContextMiddleware(storage);
    attachContext(req, res, next);
  });
};

// Export individual middlewares for flexibility
export const attachAuthContext = createAuthContextMiddleware(storage);