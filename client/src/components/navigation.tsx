import { Link, useLocation } from "wouter";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { 
  Home, 
  Clock, 
  ClipboardList, 
  FolderOpen, 
  CheckSquare, 
  Users, 
  Building2, 
  Building,
  TestTube,
  LogOut,
  FileBarChart,
  UserCog
} from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { usePermissions, useRole } from "@/hooks/usePermissions";
import { cn } from "@/lib/utils";
import { Logo } from "@/components/ui/logo";

const getNavItemsForRole = (permissions: any, role: any) => {
  
  const baseItems = [
    { path: "/", label: "Dashboard", icon: Home },
    { path: "/time-entry", label: "Time Entry", icon: Clock },
    { path: "/time-log", label: "Time Log", icon: ClipboardList },
  ];

  const conditionalItems = [
    // Projects - show to users who can view all projects
    { path: "/projects", label: "Projects", icon: FolderOpen, condition: permissions.canViewAllProjects },
    // Tasks - show to users who can create or edit tasks
    { path: "/tasks", label: "Tasks", icon: CheckSquare, condition: permissions.canCreateTasks || permissions.canEditTasks },
    // Reports - show to users who can view reports
    { path: "/reports", label: "Reports", icon: FileBarChart, condition: permissions.canViewReports },
    // Employees - show to users who can manage employees
    { path: "/employees", label: "Employees", icon: Users, condition: permissions.canManageEmployees },
    // Departments - show to users who can view department data
    { path: "/departments", label: "Departments", icon: Building2, condition: permissions.canViewDepartmentData },
    // Organizations - admin only
    { path: "/organizations", label: "Organizations", icon: Building, condition: role.isAdmin() },
    // User Management - admin only
    { path: "/admin/users", label: "User Management", icon: UserCog, condition: role.isAdmin() },
    // Role testing - show to all for testing
    { path: "/role-testing", label: "Role Testing", icon: TestTube, badge: "TEST", condition: true },
  ];

  return [
    ...baseItems,
    ...conditionalItems.filter(item => item.condition)
  ];
};

export default function Navigation() {
  const [location] = useLocation();
  const { user } = useAuth();
  const permissions = usePermissions();
  const role = useRole();
  
  const navItems = getNavItemsForRole(permissions, role);

  const getRoleColor = (role: string) => {
    switch (role) {
      case "admin": return "bg-red-100 text-red-800";
      case "manager": return "bg-blue-100 text-blue-800";
      case "project_manager": return "bg-green-100 text-green-800";
      case "employee": return "bg-yellow-100 text-yellow-800";
      case "viewer": return "bg-gray-100 text-gray-800";
      default: return "bg-gray-100 text-gray-800";
    }
  };

  return (
    <nav className="w-64 bg-card border-r border-border h-screen p-4 flex flex-col">
      {/* Header */}
      <div className="mb-8">
        <Logo size="md" showText={true} />
        {user && (
          <div className="mt-3 p-3 bg-muted rounded-lg">
            <div className="flex items-center gap-2 mb-2">
              <div className="w-8 h-8 bg-primary rounded-full flex items-center justify-center text-primary-foreground text-sm font-medium">
                {user.firstName?.[0] || user.email?.[0] || "U"}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">
                  {user.firstName} {user.lastName}
                </p>
                <p className="text-xs text-muted-foreground truncate">
                  {user.email}
                </p>
              </div>
            </div>
            <Badge className={cn("text-xs", getRoleColor(user.role || "employee"))}>
              {(user.role || "employee").replace("_", " ").toUpperCase()}
            </Badge>
          </div>
        )}
      </div>

      {/* Navigation Links */}
      <div className="flex-1 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = location === item.path;
          
          return (
            <Link key={item.path} href={item.path}>
              <Button
                variant={isActive ? "secondary" : "ghost"}
                className={cn(
                  "w-full justify-start gap-3 h-10",
                  isActive && "bg-secondary text-secondary-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                <span className="flex-1 text-left">{item.label}</span>
                {(item as any).badge && (
                  <Badge variant="outline" className="text-xs">
                    {(item as any).badge}
                  </Badge>
                )}
              </Button>
            </Link>
          );
        })}
      </div>

      {/* Logout */}
      <div className="mt-auto pt-4 border-t border-border">
        <Button
          variant="ghost"
          className="w-full justify-start gap-3 h-10 text-muted-foreground hover:text-foreground"
          onClick={() => window.location.href = "/api/logout"}
        >
          <LogOut className="h-4 w-4" />
          <span>Logout</span>
        </Button>
      </div>
    </nav>
  );
}