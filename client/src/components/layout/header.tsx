import { useAuth } from "@/hooks/useAuth";
import { usePermissions } from "@/hooks/usePermissions";
import { Link, useLocation } from "wouter";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { Clock, BarChart3, Plus, List, FolderOpen, CheckSquare, Users, Building, FileText } from "lucide-react";
import { cn } from "@/lib/utils";
import UserMenu from "@/components/layout/user-menu";
import type { Organization } from "@shared/schema";

export default function Header() {
  const { user } = useAuth();
  const [location] = useLocation();
  const { canViewReports } = usePermissions();

  // Fetch organizations to display the first one in header
  const { data: organizations = [] } = useQuery<Organization[]>({
    queryKey: ["/api/organizations"],
    retry: false,
  });

  const organizationName = organizations.length > 0 ? organizations[0].name : "TimeTracker Pro";

  const allNavigationItems = [
    { name: "Dashboard", href: "/", icon: BarChart3, current: location === "/" },
    { name: "Projects", href: "/projects", icon: FolderOpen, current: location === "/projects" },
    { name: "Tasks", href: "/tasks", icon: CheckSquare, current: location === "/tasks" },
    { name: "Employees", href: "/employees", icon: Users, current: location === "/employees" },
    { name: "Organizations", href: "/organizations", icon: Building, current: location === "/organizations" },
    { name: "Departments", href: "/departments", icon: Users, current: location === "/departments" },
    { name: "Reports", href: "/reports", icon: FileText, current: location === "/reports", requiresPermission: "canViewReports" },
    { name: "Log Time", href: "/time-entry", icon: Plus, current: location === "/time-entry" },
    { name: "Time Log", href: "/time-log", icon: List, current: location === "/time-log" },
  ];

  // Filter navigation items based on permissions
  const navigation = allNavigationItems.filter(item => {
    if (item.requiresPermission === "canViewReports") {
      return canViewReports;
    }
    return true; // Show all other items
  });



  return (
    <header className="bg-white shadow-sm border-b border-gray-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div className="flex items-center">
            <div className="flex items-center">
              <div className="w-8 h-8 bg-primary text-white rounded-lg flex items-center justify-center mr-3">
                <Clock className="w-5 h-5" />
              </div>
              <h1 className="text-xl font-bold text-gray-900">{organizationName}</h1>
            </div>
          </div>
          
          <nav className="hidden md:flex space-x-8">
            {navigation.map((item) => {
              const Icon = item.icon;
              return (
                <Link key={item.name} href={item.href}>
                  <button
                    className={cn(
                      "inline-flex items-center px-1 py-4 text-sm font-medium border-b-2 transition-colors",
                      item.current
                        ? "text-primary border-primary"
                        : "text-gray-500 border-transparent hover:text-gray-700 hover:border-gray-300"
                    )}
                  >
                    <Icon className="w-4 h-4 mr-2" />
                    {item.name}
                  </button>
                </Link>
              );
            })}
          </nav>

          <div className="flex items-center space-x-4">
            <UserMenu />
          </div>
        </div>
      </div>

      {/* Mobile Navigation */}
      <div className="md:hidden border-t border-gray-200">
        <div className="px-4 py-3 space-y-1">
          {navigation.map((item) => {
            const Icon = item.icon;
            return (
              <Link key={item.name} href={item.href}>
                <button
                  className={cn(
                    "w-full text-left px-3 py-2 text-sm font-medium rounded-md transition-colors",
                    item.current
                      ? "text-primary bg-primary bg-opacity-10"
                      : "text-gray-600 hover:text-gray-900 hover:bg-gray-50"
                  )}
                >
                  <Icon className="w-4 h-4 mr-2 inline" />
                  {item.name}
                </button>
              </Link>
            );
          })}
        </div>
      </div>
    </header>
  );
}