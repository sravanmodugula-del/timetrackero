import { useRole } from "@/hooks/usePermissions";
import { usePermissions } from "@/hooks/usePermissions";
import NotFound from "@/pages/not-found";

interface ProtectedRouteProps {
  children: React.ReactNode;
  requiredPermissions?: string[];
  allowedRoles?: string[];
  blockEmployees?: boolean;
}

export function ProtectedRoute({ 
  children, 
  requiredPermissions = [], 
  allowedRoles = [],
  blockEmployees = false 
}: ProtectedRouteProps) {
  const role = useRole();
  const permissions = usePermissions();

  // Block employees from accessing certain routes
  if (blockEmployees && role.isEmployee) {
    console.log('🚫 Employee blocked from accessing protected route');
    return <NotFound />;
  }

  // Check role-based access
  if (allowedRoles.length > 0 && !allowedRoles.includes(role.role)) {
    console.log('🚫 Role not allowed:', role.role, 'Required:', allowedRoles);
    return <NotFound />;
  }

  // Check permission-based access
  if (requiredPermissions.length > 0) {
    const hasAllPermissions = requiredPermissions.every(permission => 
      permissions[permission as keyof typeof permissions]
    );
    
    if (!hasAllPermissions) {
      console.log('🚫 Insufficient permissions');
      return <NotFound />;
    }
  }

  return <>{children}</>;
}