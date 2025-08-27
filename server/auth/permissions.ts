import { Role, Permission } from './types';

// Role-based permission mappings
export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  [Role.ADMIN]: [
    // Full system access
    Permission.SYSTEM_ADMIN,
    Permission.MANAGE_USERS,
    Permission.MANAGE_ROLES,
    
    // Organization and department management
    Permission.CREATE_ORGANIZATION,
    Permission.UPDATE_ORGANIZATION,
    Permission.DELETE_ORGANIZATION,
    Permission.VIEW_ORGANIZATION,
    Permission.CREATE_DEPARTMENT,
    Permission.UPDATE_DEPARTMENT,
    Permission.DELETE_DEPARTMENT,
    Permission.VIEW_DEPARTMENT,
    Permission.MANAGE_DEPARTMENT,
    
    // Employee management
    Permission.CREATE_EMPLOYEE,
    Permission.UPDATE_EMPLOYEE,
    Permission.DELETE_EMPLOYEE,
    Permission.VIEW_EMPLOYEE,
    Permission.MANAGE_EMPLOYEE_ASSIGNMENTS,
    
    // Project management
    Permission.CREATE_PROJECT,
    Permission.UPDATE_PROJECT,
    Permission.DELETE_PROJECT,
    Permission.VIEW_PROJECT,
    Permission.ASSIGN_PROJECT,
    
    // Time tracking
    Permission.CREATE_TIME_ENTRY,
    Permission.UPDATE_TIME_ENTRY,
    Permission.DELETE_TIME_ENTRY,
    Permission.VIEW_TIME_ENTRY,
    Permission.VIEW_ALL_TIME_ENTRIES,
    
    // Reporting and analytics
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_REPORTS,
    Permission.VIEW_ANALYTICS,
    Permission.EXPORT_DATA,
  ],
  
  [Role.MANAGER]: [
    // Department management (limited to own department)
    Permission.VIEW_DEPARTMENT,
    Permission.MANAGE_DEPARTMENT,
    
    // Employee management (limited to own department)
    Permission.CREATE_EMPLOYEE,
    Permission.UPDATE_EMPLOYEE,
    Permission.VIEW_EMPLOYEE,
    Permission.MANAGE_EMPLOYEE_ASSIGNMENTS,
    
    // Project management
    Permission.CREATE_PROJECT,
    Permission.UPDATE_PROJECT,
    Permission.VIEW_PROJECT,
    Permission.ASSIGN_PROJECT,
    
    // Time tracking (own and department)
    Permission.CREATE_TIME_ENTRY,
    Permission.UPDATE_TIME_ENTRY,
    Permission.DELETE_TIME_ENTRY,
    Permission.VIEW_TIME_ENTRY,
    Permission.VIEW_ALL_TIME_ENTRIES, // Limited to department
    
    // Reporting
    Permission.VIEW_DASHBOARD,
    Permission.VIEW_REPORTS,
    Permission.VIEW_ANALYTICS,
    Permission.EXPORT_DATA,
  ],
  
  [Role.EMPLOYEE]: [
    // Basic project access
    Permission.VIEW_PROJECT,
    
    // Own time tracking
    Permission.CREATE_TIME_ENTRY,
    Permission.UPDATE_TIME_ENTRY,
    Permission.DELETE_TIME_ENTRY,
    Permission.VIEW_TIME_ENTRY,
    
    // Basic dashboard
    Permission.VIEW_DASHBOARD,
  ],
  
  [Role.VIEWER]: [
    // Read-only access
    Permission.VIEW_PROJECT,
    Permission.VIEW_TIME_ENTRY,
    Permission.VIEW_DASHBOARD,
  ],
};

export function getRolePermissions(role: Role): Permission[] {
  return ROLE_PERMISSIONS[role] || [];
}

export function hasPermission(userPermissions: Permission[], requiredPermission: Permission): boolean {
  return userPermissions.includes(requiredPermission) || userPermissions.includes(Permission.SYSTEM_ADMIN);
}

export function hasAnyPermission(userPermissions: Permission[], requiredPermissions: Permission[]): boolean {
  return requiredPermissions.some(permission => hasPermission(userPermissions, permission));
}

export function hasAllPermissions(userPermissions: Permission[], requiredPermissions: Permission[]): boolean {
  return requiredPermissions.every(permission => hasPermission(userPermissions, permission));
}

// Resource-specific permission checks
export function canAccessResource(
  userPermissions: Permission[], 
  userId: string, 
  resourceOwnerId: string, 
  requiredPermission: Permission,
  departmentId?: string,
  userDepartmentId?: string
): boolean {
  // System admin can access everything
  if (userPermissions.includes(Permission.SYSTEM_ADMIN)) {
    return true;
  }
  
  // Check if user has the specific permission
  if (!hasPermission(userPermissions, requiredPermission)) {
    return false;
  }
  
  // For certain permissions, users can only access their own resources
  const ownResourcePermissions = [
    Permission.UPDATE_TIME_ENTRY,
    Permission.DELETE_TIME_ENTRY,
  ];
  
  if (ownResourcePermissions.includes(requiredPermission)) {
    return userId === resourceOwnerId;
  }
  
  // For department-level permissions, check department access
  const departmentPermissions = [
    Permission.VIEW_ALL_TIME_ENTRIES,
    Permission.MANAGE_EMPLOYEE_ASSIGNMENTS,
  ];
  
  if (departmentPermissions.includes(requiredPermission) && departmentId && userDepartmentId) {
    return departmentId === userDepartmentId;
  }
  
  return true;
}