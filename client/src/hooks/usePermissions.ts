import { useAuth } from "@/hooks/useAuth";

const roleDisplayNames = {
  admin: 'Admin',
  manager: 'Department Manager',
  project_manager: 'Project Manager',
  employee: 'Employee',
  viewer: 'Viewer',
};

export interface Permissions {
  canCreateProjects: boolean;
  canEditProjects: boolean;
  canDeleteProjects: boolean;
  canManageEmployees: boolean;
  canViewDepartmentData: boolean;
  canViewAllProjects: boolean;
  canManageSystem: boolean;
  canCreateTasks: boolean;
  canEditTasks: boolean;
  canViewReports: boolean;
  canExportData: boolean;
}

export function usePermissions(): Permissions {
  const { user } = useAuth();
  const role = user?.authContext?.role || user?.role || 'employee';

  const permissions: Record<string, Permissions> = {
    admin: {
      canCreateProjects: true,
      canEditProjects: true,
      canDeleteProjects: true,
      canManageEmployees: true,
      canViewDepartmentData: true,
      canViewAllProjects: true,
      canManageSystem: true,
      canCreateTasks: true,
      canEditTasks: true,
      canViewReports: true,
      canExportData: true,
    },
    manager: {
      canCreateProjects: false,
      canEditProjects: false,
      canDeleteProjects: false,
      canManageEmployees: true,
      canViewDepartmentData: true,
      canViewAllProjects: true,
      canManageSystem: false,
      canCreateTasks: false,
      canEditTasks: false,
      canViewReports: true,
      canExportData: false,
    },
    project_manager: {
      canCreateProjects: true,
      canEditProjects: true,
      canDeleteProjects: false,
      canManageEmployees: false,
      canViewDepartmentData: false,
      canViewAllProjects: true,
      canManageSystem: false,
      canCreateTasks: true,
      canEditTasks: true,
      canViewReports: true,
      canExportData: false,
    },
    employee: {
      canCreateProjects: false,
      canEditProjects: false,
      canDeleteProjects: false,
      canManageEmployees: false,
      canViewDepartmentData: false,
      canViewAllProjects: false,
      canManageSystem: false,
      canCreateTasks: false,
      canEditTasks: false,
      canViewReports: false,
      canExportData: false,
    },
    viewer: {
      canCreateProjects: false,
      canEditProjects: false,
      canDeleteProjects: false,
      canManageEmployees: false,
      canViewDepartmentData: false,
      canViewAllProjects: false,
      canManageSystem: false,
      canCreateTasks: false,
      canEditTasks: false,
      canViewReports: false,
      canExportData: false,
    },
  };

  return permissions[role as keyof typeof permissions] || permissions.employee;
}

export function useRole() {
  const { user } = useAuth();
  const role = user?.authContext?.role || user?.role || 'employee';
  
  console.log('useRole hook:', { user: user?.role, authContextRole: user?.authContext?.role, finalRole: role });

  const isAdmin = () => role === 'admin';
  const isManager = () => role === 'manager';  
  const isEmployee = () => role === 'employee';
  const isViewer = () => role === 'viewer';
  const isProjectManager = () => role === 'project_manager';

  const hasRole = (requiredRole: string) => role === requiredRole;
  const hasAnyRole = (requiredRoles: string[]) => requiredRoles.includes(role);

  return {
    role,
    displayName: roleDisplayNames[role as keyof typeof roleDisplayNames] || 'Employee',
    isAdmin,
    isManager,
    isEmployee,
    isViewer,
    isProjectManager,
    hasRole,
    hasAnyRole,
  };
}