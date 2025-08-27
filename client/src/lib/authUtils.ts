export function isUnauthorizedError(error: Error): boolean {
  return /^401: .*Unauthorized/.test(error.message);
}

// Permission constants for frontend use
export const PERMISSIONS = {
  // Project permissions
  CREATE_PROJECT: 'create_project',
  UPDATE_PROJECT: 'update_project',
  DELETE_PROJECT: 'delete_project',
  VIEW_PROJECT: 'view_project',
  ASSIGN_PROJECT: 'assign_project',
  
  // Time entry permissions
  CREATE_TIME_ENTRY: 'create_time_entry',
  UPDATE_TIME_ENTRY: 'update_time_entry',
  DELETE_TIME_ENTRY: 'delete_time_entry',
  VIEW_TIME_ENTRY: 'view_time_entry',
  VIEW_ALL_TIME_ENTRIES: 'view_all_time_entries',
  
  // Employee management permissions
  CREATE_EMPLOYEE: 'create_employee',
  UPDATE_EMPLOYEE: 'update_employee',
  DELETE_EMPLOYEE: 'delete_employee',
  VIEW_EMPLOYEE: 'view_employee',
  MANAGE_EMPLOYEE_ASSIGNMENTS: 'manage_employee_assignments',
  
  // Department and organization permissions
  CREATE_DEPARTMENT: 'create_department',
  UPDATE_DEPARTMENT: 'update_department',
  DELETE_DEPARTMENT: 'delete_department',
  VIEW_DEPARTMENT: 'view_department',
  MANAGE_DEPARTMENT: 'manage_department',
  
  CREATE_ORGANIZATION: 'create_organization',
  UPDATE_ORGANIZATION: 'update_organization',
  DELETE_ORGANIZATION: 'delete_organization',
  VIEW_ORGANIZATION: 'view_organization',
  
  // Dashboard and reporting permissions
  VIEW_DASHBOARD: 'view_dashboard',
  VIEW_REPORTS: 'view_reports',
  VIEW_ANALYTICS: 'view_analytics',
  EXPORT_DATA: 'export_data',
  
  // System administration
  MANAGE_USERS: 'manage_users',
  MANAGE_ROLES: 'manage_roles',
  SYSTEM_ADMIN: 'system_admin'
} as const;

// Role constants
export const ROLES = {
  ADMIN: 'admin',
  MANAGER: 'manager',
  EMPLOYEE: 'employee',
  VIEWER: 'viewer'
} as const;