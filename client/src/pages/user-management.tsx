import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { Users, Link, UserCheck, Clock, Mail } from "lucide-react";
import Header from "@/components/layout/header";
import { useAuth } from "@/hooks/useAuth";
import { usePermissions } from "@/hooks/usePermissions";
import { useEffect } from "react";

interface User {
  id: string;
  email: string;
  firstName: string | null;
  lastName: string | null;
  role: string;
  createdAt: string;
  lastLoginAt: string | null;
}

interface Employee {
  id: string;
  employeeId: string;
  firstName: string;
  lastName: string;
  department: string;
  userId: string | null;
}

export default function UserManagement() {
  const { user, isLoading } = useAuth();
  const { canManageSystem } = usePermissions();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [linkingDialogOpen, setLinkingDialogOpen] = useState(false);
  const [selectedEmployee, setSelectedEmployee] = useState<Employee | null>(null);
  const [selectedUserId, setSelectedUserId] = useState("");
  const [roleChangeDialogOpen, setRoleChangeDialogOpen] = useState(false);
  const [selectedUserForRole, setSelectedUserForRole] = useState<User | null>(null);
  const [newRole, setNewRole] = useState("");

  // Redirect if not admin
  useEffect(() => {
    if (!isLoading && (!canManageSystem || user?.role !== 'admin')) {
      toast({
        title: "Access Denied",
        description: "Only System Administrators can access user management.",
        variant: "destructive",
      });
      window.location.href = "/";
    }
  }, [isLoading, canManageSystem, user, toast]);

  // Fetch all users
  const { data: allUsers = [] } = useQuery<User[]>({
    queryKey: ["/api/admin/users"],
    enabled: canManageSystem && user?.role === 'admin',
    retry: false,
  });

  // Fetch users without employee profile
  const { data: unlinkedUsers = [] } = useQuery<User[]>({
    queryKey: ["/api/admin/users/without-employee"],
    enabled: canManageSystem && user?.role === 'admin',
    retry: false,
  });

  // Fetch employees
  const { data: employees = [] } = useQuery<Employee[]>({
    queryKey: ["/api/employees"],
    enabled: canManageSystem && user?.role === 'admin',
    retry: false,
  });

  // Link user to employee mutation
  const linkUserMutation = useMutation({
    mutationFn: async ({ employeeId, userId }: { employeeId: string; userId: string }) => {
      return apiRequest(`/api/admin/employees/${employeeId}/link-user`, "POST", { userId });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users/without-employee"] });
      queryClient.invalidateQueries({ queryKey: ["/api/employees"] });
      toast({
        title: "Success",
        description: "User successfully linked to employee profile.",
      });
      setLinkingDialogOpen(false);
      setSelectedEmployee(null);
      setSelectedUserId("");
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to link user to employee.",
        variant: "destructive",
      });
    },
  });

  // Update user role mutation
  const updateRoleMutation = useMutation({
    mutationFn: async ({ userId, role }: { userId: string; role: string }) => {
      console.log("🔄 Frontend: Updating role for user:", userId, "to role:", role);
      try {
        const result = await apiRequest(`/api/admin/users/${userId}/role`, "POST", { role });
        console.log("✅ Frontend: Role update successful:", result);
        return result;
      } catch (error) {
        console.error("❌ Frontend: Role update failed:", error);
        throw error;
      }
    },
    onSuccess: (data) => {
      console.log("✅ Frontend: Role mutation success callback:", data);
      queryClient.invalidateQueries({ queryKey: ["/api/admin/users"] });
      toast({
        title: "Success",
        description: "User role updated successfully.",
      });
      setRoleChangeDialogOpen(false);
      setSelectedUserForRole(null);
      setNewRole("");
    },
    onError: (error: any) => {
      console.error("❌ Frontend: Role mutation error callback:", error);
      console.error("Error details:", {
        message: error.message,
        status: error.status,
        response: error.response
      });
      toast({
        title: "Error",
        description: error.message || error.response?.data?.message || "Failed to update user role.",
        variant: "destructive",
      });
    },
  });

  const handleLinkUser = () => {
    if (selectedEmployee && selectedUserId) {
      linkUserMutation.mutate({
        employeeId: selectedEmployee.id,
        userId: selectedUserId,
      });
    }
  };

  const handleRoleChange = () => {
    if (selectedUserForRole && newRole) {
      updateRoleMutation.mutate({
        userId: selectedUserForRole.id,
        role: newRole,
      });
    }
  };

  const openRoleChangeDialog = (user: User) => {
    setSelectedUserForRole(user);
    setNewRole(user.role);
    setRoleChangeDialogOpen(true);
  };

  const formatDate = (dateString: string | null) => {
    if (!dateString) return "Never";
    return new Date(dateString).toLocaleDateString();
  };

  const getRoleColor = (role: string) => {
    switch (role) {
      case 'admin': return 'bg-red-100 text-red-800';
      case 'manager': return 'bg-blue-100 text-blue-800';
      case 'project_manager': return 'bg-green-100 text-green-800';
      case 'employee': return 'bg-gray-100 text-gray-800';
      case 'viewer': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getRoleDisplayName = (role: string) => {
    switch (role) {
      case 'admin': return 'System Administrator';
      case 'manager': return 'Department Manager';
      case 'project_manager': return 'Project Manager';
      case 'employee': return 'Employee';
      case 'viewer': return 'Viewer';
      default: return role.replace('_', ' ').toUpperCase();
    }
  };

  if (isLoading) return <div>Loading...</div>;

  if (!canManageSystem || user?.role !== 'admin') {
    return <div>Access denied</div>;
  }

  const employeesWithoutUser = employees.filter(emp => !emp.userId);

  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="md:flex md:items-center md:justify-between mb-8">
          <div className="flex-1 min-w-0">
            <div className="flex items-center">
              <Users className="w-8 h-8 text-blue-600 mr-3" />
              <div>
                <h2 className="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl sm:truncate">
                  User Management
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                  Manage system users and link them to employee profiles
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Users</CardTitle>
              <Users className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{allUsers.length}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Unlinked Users</CardTitle>
              <Link className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{unlinkedUsers.length}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Employees w/o User</CardTitle>
              <UserCheck className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{employeesWithoutUser.length}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Linked Profiles</CardTitle>
              <UserCheck className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{employees.filter(emp => emp.userId).length}</div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* All Users */}
          <Card>
            <CardHeader>
              <CardTitle>All System Users</CardTitle>
              <CardDescription>Users who have signed up for the application</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {allUsers.map((user) => (
                  <div key={user.id} className="flex items-center justify-between p-4 border rounded-lg">
                    <div className="flex-1">
                      <div className="flex items-center space-x-3">
                        <Mail className="w-4 h-4 text-gray-400" />
                        <div>
                          <p className="font-medium">
                            {user.firstName && user.lastName 
                              ? `${user.firstName} ${user.lastName}` 
                              : user.email}
                          </p>
                          <p className="text-sm text-gray-500">{user.email}</p>
                        </div>
                      </div>
                      <div className="flex items-center justify-between mt-2">
                        <div className="flex items-center space-x-2">
                          <Badge className={getRoleColor(user.role)}>
                            {getRoleDisplayName(user.role)}
                          </Badge>
                          <div className="flex items-center text-xs text-gray-500">
                            <Clock className="w-3 h-3 mr-1" />
                            Last login: {formatDate(user.lastLoginAt)}
                          </div>
                        </div>
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => openRoleChangeDialog(user)}
                          data-testid={`button-change-role-${user.id}`}
                        >
                          Change Role
                        </Button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Employee Linking */}
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Employee Profile Linking</CardTitle>
                  <CardDescription>Link user accounts to employee profiles</CardDescription>
                </div>
                {employeesWithoutUser.length > 0 && unlinkedUsers.length > 0 && (
                  <Dialog open={linkingDialogOpen} onOpenChange={setLinkingDialogOpen}>
                    <DialogTrigger asChild>
                      <Button>
                        <Link className="w-4 h-4 mr-2" />
                        Link User
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Link User to Employee</DialogTitle>
                      </DialogHeader>
                      <div className="space-y-4">
                        <div>
                          <label className="text-sm font-medium">Select Employee</label>
                          <Select onValueChange={(value) => {
                            const employee = employeesWithoutUser.find(emp => emp.id === value);
                            setSelectedEmployee(employee || null);
                          }}>
                            <SelectTrigger>
                              <SelectValue placeholder="Choose employee" />
                            </SelectTrigger>
                            <SelectContent>
                              {employeesWithoutUser.map((employee) => (
                                <SelectItem key={employee.id} value={employee.id}>
                                  {employee.firstName} {employee.lastName} ({employee.department})
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        
                        <div>
                          <label className="text-sm font-medium">Select User</label>
                          <Select onValueChange={setSelectedUserId}>
                            <SelectTrigger>
                              <SelectValue placeholder="Choose user" />
                            </SelectTrigger>
                            <SelectContent>
                              {unlinkedUsers.map((user) => (
                                <SelectItem key={user.id} value={user.id}>
                                  {user.firstName && user.lastName 
                                    ? `${user.firstName} ${user.lastName} (${user.email})` 
                                    : user.email}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                        
                        <Button 
                          onClick={handleLinkUser}
                          disabled={!selectedEmployee || !selectedUserId || linkUserMutation.isPending}
                          className="w-full"
                        >
                          {linkUserMutation.isPending ? "Linking..." : "Link User to Employee"}
                        </Button>
                      </div>
                    </DialogContent>
                  </Dialog>
                )}
              </div>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div>
                  <h4 className="font-medium text-sm text-gray-700 mb-2">Employees without user accounts:</h4>
                  {employeesWithoutUser.length === 0 ? (
                    <p className="text-sm text-gray-500">All employees have linked user accounts</p>
                  ) : (
                    <div className="space-y-2">
                      {employeesWithoutUser.map((employee) => (
                        <div key={employee.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                          <div>
                            <p className="font-medium">{employee.firstName} {employee.lastName}</p>
                            <p className="text-sm text-gray-500">{employee.department}</p>
                          </div>
                          <Badge variant="outline">No User Account</Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
                
                <div>
                  <h4 className="font-medium text-sm text-gray-700 mb-2">Users without employee profiles:</h4>
                  {unlinkedUsers.length === 0 ? (
                    <p className="text-sm text-gray-500">All users have employee profiles</p>
                  ) : (
                    <div className="space-y-2">
                      {unlinkedUsers.map((user) => (
                        <div key={user.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                          <div>
                            <p className="font-medium">
                              {user.firstName && user.lastName 
                                ? `${user.firstName} ${user.lastName}` 
                                : user.email}
                            </p>
                            <p className="text-sm text-gray-500">{user.email}</p>
                          </div>
                          <Badge variant="outline">No Employee Profile</Badge>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Role Change Dialog */}
        <Dialog open={roleChangeDialogOpen} onOpenChange={setRoleChangeDialogOpen}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Change User Role</DialogTitle>
            </DialogHeader>
            {selectedUserForRole && (
              <div className="space-y-4">
                <div className="p-4 bg-gray-50 rounded-lg">
                  <div className="flex items-center space-x-3">
                    <Mail className="w-4 h-4 text-gray-400" />
                    <div>
                      <p className="font-medium">
                        {selectedUserForRole.firstName && selectedUserForRole.lastName 
                          ? `${selectedUserForRole.firstName} ${selectedUserForRole.lastName}` 
                          : selectedUserForRole.email}
                      </p>
                      <p className="text-sm text-gray-500">{selectedUserForRole.email}</p>
                    </div>
                  </div>
                  <div className="mt-2">
                    <Badge className={getRoleColor(selectedUserForRole.role)}>
                      Current: {getRoleDisplayName(selectedUserForRole.role)}
                    </Badge>
                  </div>
                </div>

                <div>
                  <label className="text-sm font-medium block mb-2">Select New Role</label>
                  <Select value={newRole} onValueChange={setNewRole}>
                    <SelectTrigger data-testid="select-new-role">
                      <SelectValue placeholder="Choose new role" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="admin" data-testid="option-admin">
                        <div className="flex items-center justify-between w-full">
                          <span>System Administrator</span>
                          <Badge className="ml-2 bg-red-100 text-red-800">Full Access</Badge>
                        </div>
                      </SelectItem>
                      <SelectItem value="manager" data-testid="option-manager">
                        <div className="flex items-center justify-between w-full">
                          <span>Department Manager</span>
                          <Badge className="ml-2 bg-blue-100 text-blue-800">Department</Badge>
                        </div>
                      </SelectItem>
                      <SelectItem value="project_manager" data-testid="option-project-manager">
                        <div className="flex items-center justify-between w-full">
                          <span>Project Manager</span>
                          <Badge className="ml-2 bg-green-100 text-green-800">Project</Badge>
                        </div>
                      </SelectItem>
                      <SelectItem value="employee" data-testid="option-employee">
                        <div className="flex items-center justify-between w-full">
                          <span>Employee</span>
                          <Badge className="ml-2 bg-gray-100 text-gray-800">Basic</Badge>
                        </div>
                      </SelectItem>
                      <SelectItem value="viewer" data-testid="option-viewer">
                        <div className="flex items-center justify-between w-full">
                          <span>Viewer</span>
                          <Badge className="ml-2 bg-yellow-100 text-yellow-800">Read-only</Badge>
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Role Description */}
                <div className="p-3 bg-blue-50 rounded-lg">
                  <p className="text-sm text-blue-700">
                    {newRole === 'admin' && "Full system access including user management and system administration."}
                    {newRole === 'manager' && "Department-level management with employee and project oversight within their department."}
                    {newRole === 'project_manager' && "Project creation and management with team assignment capabilities."}
                    {newRole === 'employee' && "Basic project access with personal time tracking and task management."}
                    {newRole === 'viewer' && "Read-only access to assigned projects and own time entries."}
                  </p>
                </div>

                <div className="flex space-x-2">
                  <Button 
                    variant="outline" 
                    onClick={() => setRoleChangeDialogOpen(false)}
                    className="flex-1"
                  >
                    Cancel
                  </Button>
                  <Button 
                    onClick={handleRoleChange}
                    disabled={!newRole || newRole === selectedUserForRole.role || updateRoleMutation.isPending}
                    className="flex-1"
                    data-testid="button-confirm-role-change"
                  >
                    {updateRoleMutation.isPending ? "Updating..." : "Update Role"}
                  </Button>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </main>
    </div>
  );
}