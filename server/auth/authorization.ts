import type { RequestHandler } from 'express';
import { Role, Permission, AuthContext, AuthorizationResult } from './types';
import { getRolePermissions, hasPermission, canAccessResource } from './permissions';
// Note: storage import removed to avoid circular dependency - we'll inject it as needed

declare global {
  namespace Express {
    interface Request {
      authContext?: AuthContext | null;
    }
  }
}

// Build auth context from authenticated user
export async function buildAuthContext(req: any, storageInstance: any): Promise<AuthContext | null> {
  if (!req.user || !req.user.claims) {
    return null;
  }

  const userId = req.user.claims.sub;
  
  try {
    // Get user role and department/organization info from employee record
    const employee = await storageInstance.getEmployeeByUserId(userId);
    
    let role = Role.EMPLOYEE; // Default role
    let departmentId: string | undefined;
    let organizationId: string | undefined;
    
    if (employee) {
      departmentId = employee.department;
      
      // Get department to find organization
      if (departmentId) {
        const department = await storageInstance.getDepartment(departmentId, userId);
        if (department?.organization) {
          organizationId = department.organization.id;
        }
        
        // Check if user is a department manager
        if (department?.managerId === employee.id) {
          role = Role.MANAGER;
        }
      }
    }
    
    // Check for admin role (could be based on specific user IDs or other criteria)
    // For now, we'll use a simple check - you can enhance this
    const adminUsers = process.env.ADMIN_USERS?.split(',') || [];
    if (adminUsers.includes(userId)) {
      role = Role.ADMIN;
    }
    
    const permissions = getRolePermissions(role);
    
    return {
      user: req.user,
      role,
      permissions,
      departmentId,
      organizationId,
    };
  } catch (error) {
    console.error('Error building auth context:', error);
    return null;
  }
}

// Middleware factory to build and attach auth context
export function createAuthContextMiddleware(storageInstance: any): RequestHandler {
  return async (req, res, next) => {
    if (req.user) {
      req.authContext = await buildAuthContext(req, storageInstance);
    }
    next();
  };
}

// Check if user has required permission
export function authorize(...requiredPermissions: Permission[]): RequestHandler {
  return async (req, res, next) => {
    const authContext = req.authContext;
    
    if (!authContext) {
      return res.status(401).json({ 
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    // Check permissions
    const hasRequiredPermissions = requiredPermissions.every(permission => 
      hasPermission(authContext.permissions, permission)
    );
    
    if (!hasRequiredPermissions) {
      return res.status(403).json({ 
        message: 'Insufficient permissions',
        code: 'INSUFFICIENT_PERMISSIONS',
        requiredPermissions,
        userPermissions: authContext.permissions
      });
    }
    
    next();
  };
}

// Check if user can access a specific resource
export function authorizeResource(
  requiredPermission: Permission,
  resourceOwnerIdGetter?: (req: any) => string,
  departmentIdGetter?: (req: any) => string
): RequestHandler {
  return async (req, res, next) => {
    const authContext = req.authContext;
    
    if (!authContext) {
      return res.status(401).json({ 
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    const userId = authContext.user.claims.sub;
    const resourceOwnerId = resourceOwnerIdGetter?.(req) || userId;
    const resourceDepartmentId = departmentIdGetter?.(req);
    
    const canAccess = canAccessResource(
      authContext.permissions,
      userId,
      resourceOwnerId,
      requiredPermission,
      resourceDepartmentId,
      authContext.departmentId
    );
    
    if (!canAccess) {
      return res.status(403).json({ 
        message: 'Access denied to this resource',
        code: 'RESOURCE_ACCESS_DENIED',
        requiredPermission
      });
    }
    
    next();
  };
}

// Role-based authorization
export function requireRole(...allowedRoles: Role[]): RequestHandler {
  return async (req, res, next) => {
    const authContext = req.authContext;
    
    if (!authContext) {
      return res.status(401).json({ 
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    if (!allowedRoles.includes(authContext.role)) {
      return res.status(403).json({ 
        message: 'Role not authorized',
        code: 'ROLE_NOT_AUTHORIZED',
        requiredRoles: allowedRoles,
        userRole: authContext.role
      });
    }
    
    next();
  };
}

// Helper function to check authorization without middleware
export async function checkAuthorization(
  req: any,
  requiredPermissions: Permission[]
): Promise<AuthorizationResult> {
  const authContext = req.authContext;
  
  if (!authContext) {
    return {
      authorized: false,
      reason: 'Authentication required'
    };
  }
  
  const hasRequiredPermissions = requiredPermissions.every(permission => 
    hasPermission(authContext.permissions, permission)
  );
  
  if (!hasRequiredPermissions) {
    return {
      authorized: false,
      reason: 'Insufficient permissions',
      requiredPermissions
    };
  }
  
  return { authorized: true };
}

// Department-scoped authorization
export function requireDepartmentAccess(): RequestHandler {
  return async (req, res, next) => {
    const authContext = req.authContext;
    
    if (!authContext) {
      return res.status(401).json({ 
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    // Admins can access any department
    if (authContext.role === Role.ADMIN) {
      return next();
    }
    
    // Managers and employees need department assignment
    if (!authContext.departmentId) {
      return res.status(403).json({ 
        message: 'No department assignment found',
        code: 'NO_DEPARTMENT_ACCESS'
      });
    }
    
    next();
  };
}

// Organization-scoped authorization
export function requireOrganizationAccess(): RequestHandler {
  return async (req, res, next) => {
    const authContext = req.authContext;
    
    if (!authContext) {
      return res.status(401).json({ 
        message: 'Authentication required',
        code: 'AUTH_REQUIRED'
      });
    }
    
    // Admins can access any organization
    if (authContext.role === Role.ADMIN) {
      return next();
    }
    
    // Users need organization assignment through department
    if (!authContext.organizationId) {
      return res.status(403).json({ 
        message: 'No organization access found',
        code: 'NO_ORGANIZATION_ACCESS'
      });
    }
    
    next();
  };
}