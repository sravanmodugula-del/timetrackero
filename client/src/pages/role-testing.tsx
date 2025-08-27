import { useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { UserCog, Shield, Users, Eye, RefreshCw } from "lucide-react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";

interface TestUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: string;
  departmentId?: string;
  organizationId?: string;
}

interface TestStatus {
  currentRole: string;
  originalRole: string | null;
  testing: boolean;
  canTest: boolean;
}

const ROLE_PERMISSIONS = {
  admin: {
    name: "System Administrator",
    color: "bg-red-100 text-red-800",
    icon: Shield,
    permissions: [
      "Full system access",
      "User management",
      "All projects and departments",
      "System configuration",
      "All reports and analytics"
    ]
  },
  manager: {
    name: "Department Manager", 
    color: "bg-blue-100 text-blue-800",
    icon: Users,
    permissions: [
      "Department-level management",
      "Employee oversight",
      "Department projects",
      "Department reports",
      "Employee time tracking"
    ]
  },
  project_manager: {
    name: "Project Manager",
    color: "bg-green-100 text-green-800", 
    icon: UserCog,
    permissions: [
      "Project creation and modification",
      "Project-level dashboards",
      "Project reports",
      "Task management",
      "Team member assignment"
    ]
  },
  employee: {
    name: "Employee",
    color: "bg-yellow-100 text-yellow-800",
    icon: UserCog,
    permissions: [
      "Time entry logging",
      "Assigned project access",
      "Personal time reports",
      "Task completion",
      "Profile management"
    ]
  },
  viewer: {
    name: "Viewer",
    color: "bg-gray-100 text-gray-800",
    icon: Eye,
    permissions: [
      "Read-only access",
      "View assigned projects",
      "View own time entries",
      "Basic reports",
      "Limited dashboard access"
    ]
  }
};

export default function RoleTesting() {
  const { user } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [selectedRole, setSelectedRole] = useState<string>("");

  // Fetch current user role info
  const { data: currentUserRole } = useQuery({
    queryKey: ["/api/users/current-role"],
    retry: false,
  });

  // Create test users mutation
  const createTestUsersMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest("/api/admin/create-test-users", "POST", {});
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Test users created successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/test-users"] });
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: `Failed to create test users: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  // Fetch test status
  const { data: testStatus } = useQuery<TestStatus>({
    queryKey: ["/api/admin/test-status"],
    retry: false,
  });

  // Simple role change mutation - works with basic /api/users/change-role endpoint
  const testRoleMutation = useMutation({
    mutationFn: async (testRole: string) => {
      return await apiRequest("/api/users/change-role", "POST", { role: testRole });
    },
    onSuccess: (data) => {
      toast({
        title: "Role Changed Successfully",
        description: `Now testing as ${data.role}`,
      });
      // Invalidate ALL authentication-related queries to force fresh data
      queryClient.invalidateQueries({ queryKey: ["/api/users/current-role"] });
      queryClient.invalidateQueries({ queryKey: ["/api/auth/user"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard"] });
      queryClient.invalidateQueries({ queryKey: ["/api/projects"] });
      queryClient.invalidateQueries({ queryKey: ["/api/employees"] });
      queryClient.invalidateQueries({ queryKey: ["/api/time-entries"] });
      
      // Immediate refresh without delay to apply new role
      window.location.reload();
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: `Failed to change role: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  // Restore admin role mutation
  const restoreRoleMutation = useMutation({
    mutationFn: async () => {
      return await apiRequest("/api/admin/restore-role", "POST", {});
    },
    onSuccess: (data) => {
      toast({
        title: "Role Restored",
        description: data.message,
      });
      // Refresh the page to apply restored role
      setTimeout(() => {
        window.location.reload();
      }, 1000);
    },
    onError: (error) => {
      toast({
        title: "Error",
        description: `Failed to restore role: ${error.message}`,
        variant: "destructive",
      });
    },
  });

  // Fetch test users
  const { data: testUsers = [] } = useQuery<TestUser[]>({
    queryKey: ["/api/admin/test-users"],
    retry: false,
  });

  const handleCreateTestUsers = () => {
    createTestUsersMutation.mutate();
  };

  const handleTestRole = () => {
    if (selectedRole) {
      testRoleMutation.mutate(selectedRole);
    }
  };

  const handleRestoreRole = () => {
    restoreRoleMutation.mutate();
  };

  const getRoleInfo = (role: string) => {
    return ROLE_PERMISSIONS[role as keyof typeof ROLE_PERMISSIONS] || ROLE_PERMISSIONS.employee;
  };

  const currentRole = user?.role || "employee";
  const currentRoleInfo = getRoleInfo(currentRole);
  const IconComponent = currentRoleInfo.icon;

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Role-Based Access Testing</h1>
          <p className="text-muted-foreground">
            Test different user roles and permissions to verify project manager and department manager access levels.
          </p>
        </div>

        {/* Admin Role Testing Status */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-3">
              <IconComponent className="h-5 w-5" />
              Current Role: {currentRoleInfo.name}
              {testStatus?.testing && (
                <Badge variant="outline" className="bg-orange-50 text-orange-800 border-orange-200">
                  TESTING MODE
                </Badge>
              )}
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4 mb-4">
              <Badge className={currentRoleInfo.color}>
                {currentRole.toUpperCase()}
              </Badge>
              <span className="text-sm text-muted-foreground">
                User: {user?.firstName} {user?.lastName} ({user?.email})
              </span>
              {testStatus?.testing && (
                <span className="text-sm text-orange-600 font-medium">
                  Original Role: {testStatus.originalRole?.toUpperCase()}
                </span>
              )}
            </div>

            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 mb-6">
              <div className="flex items-center gap-3">
                <div className="w-2 h-2 bg-blue-500 rounded-full animate-pulse"></div>
                <div>
                  <h4 className="font-semibold text-blue-900">Development Role Testing Mode</h4>
                  <p className="text-sm text-blue-700">
                    You can switch between any role to test different permissions and access levels. All role changes are immediate and temporary.
                  </p>
                </div>
              </div>
            </div>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-3">Current Permissions:</h4>
                <ul className="space-y-2">
                  {currentRoleInfo.permissions.map((permission, index) => (
                    <li key={index} className="flex items-center gap-2 text-sm">
                      <div className="w-2 h-2 bg-green-500 rounded-full"></div>
                      {permission}
                    </li>
                  ))}
                </ul>
              </div>
              
              <div>
                <h4 className="font-semibold mb-3">Switch Role (Testing Mode):</h4>
                <div className="space-y-3">
                  <Select value={selectedRole} onValueChange={setSelectedRole}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select role to test" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin">System Administrator</SelectItem>
                      <SelectItem value="manager">Department Manager</SelectItem>
                      <SelectItem value="project_manager">Project Manager</SelectItem>
                      <SelectItem value="employee">Employee</SelectItem>
                      <SelectItem value="viewer">Viewer</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button 
                    onClick={handleTestRole}
                    disabled={!selectedRole || testRoleMutation.isPending}
                    className="w-full"
                  >
                    {testRoleMutation.isPending ? (
                      <>
                        <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                        Switching Role...
                      </>
                    ) : (
                      "Switch to Selected Role"
                    )}
                  </Button>
                  <p className="text-xs text-muted-foreground">
                    Development mode: Switch between any role to test different access levels and permissions.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Role Comparison */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
          {Object.entries(ROLE_PERMISSIONS).map(([roleKey, roleInfo]) => {
            const RoleIcon = roleInfo.icon;
            return (
              <Card key={roleKey} className={currentRole === roleKey ? "ring-2 ring-primary" : ""}>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <RoleIcon className="h-4 w-4" />
                    {roleInfo.name}
                  </CardTitle>
                  <Badge className={roleInfo.color} variant="secondary">
                    {roleKey.toUpperCase()}
                  </Badge>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-1">
                    {roleInfo.permissions.map((permission, index) => (
                      <li key={index} className="text-sm text-muted-foreground flex items-start gap-2">
                        <div className="w-1.5 h-1.5 bg-gray-400 rounded-full mt-2 flex-shrink-0"></div>
                        {permission}
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Test Users Management */}
        {(currentRole === "admin" || currentRole === "manager") && (
          <Card>
            <CardHeader>
              <CardTitle>Test User Management</CardTitle>
              <p className="text-sm text-muted-foreground">
                Create test users with different roles to test various access levels.
              </p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Button 
                  onClick={handleCreateTestUsers}
                  disabled={createTestUsersMutation.isPending}
                  className="w-full md:w-auto"
                >
                  {createTestUsersMutation.isPending ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Creating Test Users...
                    </>
                  ) : (
                    "Create Test Users"
                  )}
                </Button>

                {testUsers.length > 0 && (
                  <div className="mt-6">
                    <h4 className="font-semibold mb-4">Test Users Created:</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {testUsers.map((testUser) => {
                        const roleInfo = getRoleInfo(testUser.role);
                        return (
                          <div key={testUser.id} className="p-4 border rounded-lg">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-medium">
                                {testUser.firstName} {testUser.lastName}
                              </span>
                              <Badge className={roleInfo.color}>
                                {testUser.role.toUpperCase()}
                              </Badge>
                            </div>
                            <p className="text-sm text-muted-foreground">
                              {testUser.email}
                            </p>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        )}

        <Separator className="my-8" />

        {/* Testing Instructions */}
        <Card>
          <CardHeader>
            <CardTitle>Testing Instructions</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <h4 className="font-semibold text-green-700 mb-2">Project Manager Testing:</h4>
                <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                  <li>Change role to "Project Manager"</li>
                  <li>Navigate to Projects page - should see project creation/editing options</li>
                  <li>Access project-level dashboards and reports</li>
                  <li>Manage tasks within projects</li>
                  <li>View team member assignments</li>
                </ul>
              </div>
              
              <div>
                <h4 className="font-semibold text-blue-700 mb-2">Department Manager Testing:</h4>
                <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                  <li>Change role to "Department Manager"</li>
                  <li>Navigate to Departments page - should see department overview</li>
                  <li>View department-level project data</li>
                  <li>Access employee management features</li>
                  <li>Generate department reports</li>
                </ul>
              </div>

              <div>
                <h4 className="font-semibold text-yellow-700 mb-2">Employee Testing:</h4>
                <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground ml-4">
                  <li>Change role to "Employee"</li>
                  <li>Should only see assigned projects</li>
                  <li>Access time entry and personal reports</li>
                  <li>Limited dashboard access</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}