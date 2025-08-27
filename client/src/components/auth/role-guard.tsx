import { usePermissions, useRole } from "@/hooks/useAuth";

interface RoleGuardProps {
  children: React.ReactNode;
  permissions?: string[];
  roles?: string[];
  fallback?: React.ReactNode;
  requireAll?: boolean; // For permissions: true = all required, false = any required
}

export default function RoleGuard({ 
  children, 
  permissions = [], 
  roles = [],
  fallback = null,
  requireAll = true
}: RoleGuardProps) {
  const { hasAllPermissions, hasAnyPermission } = usePermissions();
  const { hasAnyRole } = useRole();

  // Check role requirements
  if (roles.length > 0 && !hasAnyRole(roles)) {
    return <>{fallback}</>;
  }

  // Check permission requirements
  if (permissions.length > 0) {
    const hasRequiredPermissions = requireAll 
      ? hasAllPermissions(permissions)
      : hasAnyPermission(permissions);
    
    if (!hasRequiredPermissions) {
      return <>{fallback}</>;
    }
  }

  return <>{children}</>;
}

// Convenience components for common use cases
export function AdminOnly({ children, fallback }: { children: React.ReactNode; fallback?: React.ReactNode }) {
  return (
    <RoleGuard roles={['admin']} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

export function ManagerOrAdmin({ children, fallback }: { children: React.ReactNode; fallback?: React.ReactNode }) {
  return (
    <RoleGuard roles={['admin', 'manager']} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}

export function PermissionGuard({ 
  permission, 
  children, 
  fallback 
}: { 
  permission: string; 
  children: React.ReactNode; 
  fallback?: React.ReactNode 
}) {
  return (
    <RoleGuard permissions={[permission]} fallback={fallback}>
      {children}
    </RoleGuard>
  );
}