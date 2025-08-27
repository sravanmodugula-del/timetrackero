import { useQuery } from "@tanstack/react-query";

export interface AuthContext {
  role: string;
  permissions: string[];
  departmentId?: string;
  organizationId?: string;
}

export interface AuthenticatedUser {
  id: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  profileImageUrl?: string;
  role: string;
  isActive: boolean;
  lastLoginAt?: string;
  authContext?: AuthContext;
}

export function useAuth() {
  const { data: user, isLoading } = useQuery<AuthenticatedUser>({
    queryKey: ["/api/auth/user"],
    retry: false,
  });

  return {
    user,
    isLoading,
    isAuthenticated: !!user,
    // Auth context helpers
    role: user?.authContext?.role || 'employee',
    permissions: user?.authContext?.permissions || [],
    departmentId: user?.authContext?.departmentId,
    organizationId: user?.authContext?.organizationId,
  };
}

// Permission checking hooks
export function usePermissions() {
  const { permissions } = useAuth();
  
  const hasPermission = (permission: string) => {
    return permissions.includes(permission) || permissions.includes('system_admin');
  };
  
  const hasAnyPermission = (requiredPermissions: string[]) => {
    return requiredPermissions.some(permission => hasPermission(permission));
  };
  
  const hasAllPermissions = (requiredPermissions: string[]) => {
    return requiredPermissions.every(permission => hasPermission(permission));
  };
  
  return {
    permissions,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
  };
}

// Role checking hook
export function useRole() {
  const { role } = useAuth();
  
  const isAdmin = () => role === 'admin';
  const isManager = () => role === 'manager';
  const isEmployee = () => role === 'employee';
  const isViewer = () => role === 'viewer';
  
  const hasRole = (requiredRole: string) => role === requiredRole;
  const hasAnyRole = (requiredRoles: string[]) => requiredRoles.includes(role);
  
  return {
    role,
    isAdmin,
    isManager,
    isEmployee,
    isViewer,
    hasRole,
    hasAnyRole,
  };
}