import { useAuth, usePermissions, useRole } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useEffect } from "react";

interface ProtectedRouteProps {
  children: React.ReactNode;
  permissions?: string[];
  roles?: string[];
  fallback?: React.ReactNode;
  redirectToLogin?: boolean;
}

export default function ProtectedRoute({ 
  children, 
  permissions = [], 
  roles = [],
  fallback,
  redirectToLogin = true
}: ProtectedRouteProps) {
  const { isAuthenticated, isLoading } = useAuth();
  const { hasAllPermissions } = usePermissions();
  const { hasAnyRole } = useRole();
  const { toast } = useToast();

  useEffect(() => {
    if (!isLoading && !isAuthenticated && redirectToLogin) {
      toast({
        title: "Authentication Required",
        description: "Please log in to access this page",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 1000);
    }
  }, [isAuthenticated, isLoading, toast, redirectToLogin]);

  // Loading state
  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  // Not authenticated
  if (!isAuthenticated) {
    return fallback || (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Authentication Required</h2>
          <p className="text-muted-foreground mb-4">Please log in to access this page</p>
          <button 
            onClick={() => window.location.href = "/api/login"}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90"
          >
            Log In
          </button>
        </div>
      </div>
    );
  }

  // Check role requirements
  if (roles.length > 0 && !hasAnyRole(roles)) {
    return fallback || (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Access Denied</h2>
          <p className="text-muted-foreground mb-4">
            You don't have the required role to access this page
          </p>
          <p className="text-sm text-muted-foreground">
            Required roles: {roles.join(', ')}
          </p>
        </div>
      </div>
    );
  }

  // Check permission requirements
  if (permissions.length > 0 && !hasAllPermissions(permissions)) {
    return fallback || (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <h2 className="text-2xl font-bold mb-4">Insufficient Permissions</h2>
          <p className="text-muted-foreground mb-4">
            You don't have the required permissions to access this page
          </p>
          <p className="text-sm text-muted-foreground">
            Required permissions: {permissions.join(', ')}
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}