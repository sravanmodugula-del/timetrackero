import { useState, useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { usePermissions } from "@/hooks/usePermissions";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Building2, Plus, Edit, Trash2, Search, UserCheck, Users } from "lucide-react";
import { z } from "zod";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";
import { isUnauthorizedError } from "@/lib/authUtils";
import { insertDepartmentSchema, type DepartmentWithManager, type Employee, type Organization } from "@shared/schema";
import Header from "@/components/layout/header";

// Form schema
const departmentFormSchema = insertDepartmentSchema.omit({ userId: true });
type DepartmentFormData = z.infer<typeof departmentFormSchema>;

export default function Departments() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const { canManageSystem, canViewDepartmentData } = usePermissions();
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState("");
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [editingDepartment, setEditingDepartment] = useState<DepartmentWithManager | null>(null);

  // Redirect to home if not authenticated or insufficient permissions
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
    
    // Check for department access permissions (admin or manager with department data access)
    if (!isLoading && isAuthenticated && !(canManageSystem || canViewDepartmentData)) {
      toast({
        title: "Access Denied",
        description: "Department access permissions required.",
        variant: "destructive",
      });
      window.location.href = "/";
      return;
    }
  }, [isAuthenticated, isLoading, canManageSystem, canViewDepartmentData, toast]);

  const form = useForm<DepartmentFormData>({
    resolver: zodResolver(departmentFormSchema),
    defaultValues: {
      name: "",
      description: "",
      organizationId: "",
      managerId: undefined,
    },
  });

  // Fetch departments
  const { data: departments = [], isLoading: departmentsLoading } = useQuery<DepartmentWithManager[]>({
    queryKey: ["/api/departments"],
    retry: false,
  });

  // Fetch employees for manager assignment
  const { data: employees = [] } = useQuery<Employee[]>({
    queryKey: ["/api/employees"],
    retry: false,
  });

  // Fetch organizations for department assignment
  const { data: organizations = [] } = useQuery<Organization[]>({
    queryKey: ["/api/organizations"],
    retry: false,
  });

  // Create department mutation
  const createDepartment = useMutation({
    mutationFn: async (data: DepartmentFormData) => {
      return apiRequest("/api/departments", "POST", data);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Department created successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/departments"] });
      setIsModalOpen(false);
      form.reset();
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to create department",
        variant: "destructive",
      });
    },
  });

  // Update department mutation
  const updateDepartment = useMutation({
    mutationFn: async (data: DepartmentFormData) => {
      if (!editingDepartment) throw new Error("No department selected for editing");
      return apiRequest(`/api/departments/${editingDepartment.id}`, "PUT", data);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Department updated successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/departments"] });
      setIsModalOpen(false);
      setEditingDepartment(null);
      form.reset();
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to update department",
        variant: "destructive",
      });
    },
  });

  // Delete department mutation
  const deleteDepartment = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest(`/api/departments/${id}`, "DELETE");
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Department deleted successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/departments"] });
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to delete department",
        variant: "destructive",
      });
    },
  });

  // Assign manager mutation
  const assignManager = useMutation({
    mutationFn: async ({ departmentId, managerId }: { departmentId: string; managerId: string | null }) => {
      await apiRequest("POST", `/api/departments/${departmentId}/manager`, { managerId });
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Manager assigned successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/departments"] });
    },
    onError: (error) => {
      if (isUnauthorizedError(error)) {
        toast({
          title: "Unauthorized",
          description: "You are logged out. Logging in again...",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 500);
        return;
      }
      toast({
        title: "Error",
        description: "Failed to assign manager",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: DepartmentFormData) => {
    if (editingDepartment) {
      updateDepartment.mutate(data);
    } else {
      createDepartment.mutate(data);
    }
  };

  const handleEdit = (department: DepartmentWithManager) => {
    setEditingDepartment(department);
    form.reset({
      name: department.name,
      description: department.description || "",
      organizationId: department.organizationId,
      managerId: department.managerId || undefined,
    });
    setIsModalOpen(true);
  };

  const handleDelete = (id: string) => {
    if (confirm("Are you sure you want to delete this department?")) {
      deleteDepartment.mutate(id);
    }
  };

  const handleAssignManager = (departmentId: string, managerId: string | null) => {
    assignManager.mutate({ departmentId, managerId });
  };

  const filteredDepartments = departments.filter(department =>
    department.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    (department.description && department.description.toLowerCase().includes(searchTerm.toLowerCase())) ||
    (department.manager && `${department.manager.firstName} ${department.manager.lastName}`.toLowerCase().includes(searchTerm.toLowerCase()))
  );

  if (isLoading) return null;

  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <main className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="md:flex md:items-center md:justify-between mb-8">
          <div className="flex-1 min-w-0">
            <div className="flex items-center">
              <Building2 className="w-8 h-8 text-blue-600 mr-3" />
              <div>
                <h2 className="text-2xl font-bold leading-7 text-gray-900 sm:text-3xl sm:truncate">
                  Department Management
                </h2>
                <p className="mt-1 text-sm text-gray-500">
                  Manage departments and assign managers
                </p>
              </div>
            </div>
          </div>
          <div className="mt-4 flex md:mt-0 md:ml-4">
            {canManageSystem && (
              <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
                <DialogTrigger asChild>
                  <Button>
                    <Plus className="w-4 h-4 mr-2" />
                    Add Department
                  </Button>
                </DialogTrigger>
              <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                  <DialogTitle>
                    {editingDepartment ? "Edit Department" : "Add New Department"}
                  </DialogTitle>
                  <DialogDescription>
                    {editingDepartment 
                      ? "Update the department details below."
                      : "Create a new department and assign a manager."
                    }
                  </DialogDescription>
                </DialogHeader>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                    <FormField
                      control={form.control}
                      name="name"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Department Name</FormLabel>
                          <FormControl>
                            <Input placeholder="Enter department name" {...field} />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="organizationId"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Organization *</FormLabel>
                          <Select
                            onValueChange={field.onChange}
                            value={field.value}
                          >
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue placeholder="Select an organization" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              {organizations.map((org) => (
                                <SelectItem key={org.id} value={org.id}>
                                  {org.name}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="description"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Description (optional)</FormLabel>
                          <FormControl>
                            <Textarea
                              placeholder="Describe the department..."
                              className="resize-none"
                              rows={3}
                              {...field}
                              value={field.value || ""}
                            />
                          </FormControl>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="managerId"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Department Manager</FormLabel>
                          <Select 
                            onValueChange={(value) => field.onChange(value === "none" ? "" : value)} 
                            value={field.value || "none"}
                          >
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue placeholder="Select a manager" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="none">No manager assigned</SelectItem>
                              {employees.map((employee) => (
                                <SelectItem key={employee.id} value={employee.id}>
                                  {employee.firstName} {employee.lastName} - {employee.employeeId}
                                </SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <DialogFooter>
                      <Button
                        type="button"
                        variant="outline"
                        onClick={() => {
                          setIsModalOpen(false);
                          setEditingDepartment(null);
                          form.reset();
                        }}
                      >
                        Cancel
                      </Button>
                      <Button
                        type="submit"
                        disabled={createDepartment.isPending || updateDepartment.isPending}
                      >
                        {createDepartment.isPending || updateDepartment.isPending
                          ? "Saving..."
                          : editingDepartment
                          ? "Update Department"
                          : "Create Department"
                        }
                      </Button>
                    </DialogFooter>
                  </form>
                </Form>
              </DialogContent>
              </Dialog>
            )}
          </div>
        </div>

        {/* Search */}
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
            <Input
              placeholder="Search departments..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {/* Departments Grid */}
        {departmentsLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader>
                  <div className="flex items-center space-x-3">
                    <div className="w-8 h-8 bg-gray-200 rounded"></div>
                    <div className="h-5 w-32 bg-gray-200 rounded"></div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    <div className="h-4 w-full bg-gray-200 rounded"></div>
                    <div className="h-4 w-3/4 bg-gray-200 rounded"></div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        ) : filteredDepartments.length === 0 ? (
          <div className="text-center py-12">
            <Building2 className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">
              {searchTerm ? "No departments found" : "No departments"}
            </h3>
            <p className="mt-1 text-sm text-gray-500">
              {searchTerm 
                ? "Try adjusting your search terms"
                : "Get started by creating a new department."
              }
            </p>
            {!searchTerm && canManageSystem && (
              <div className="mt-6">
                <Dialog open={isModalOpen} onOpenChange={setIsModalOpen}>
                  <DialogTrigger asChild>
                    <Button>
                      <Plus className="w-4 h-4 mr-2" />
                      Add Department
                    </Button>
                  </DialogTrigger>
                </Dialog>
              </div>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredDepartments.map((department) => (
              <Card key={department.id} className="hover:shadow-md transition-shadow">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <Building2 className="w-6 h-6 text-blue-600" />
                      <CardTitle className="text-lg">{department.name}</CardTitle>
                    </div>
                    {canManageSystem && (
                      <div className="flex space-x-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleEdit(department)}
                        >
                          <Edit className="w-4 h-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDelete(department.id)}
                          className="text-red-600 hover:text-red-700"
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      </div>
                    )}
                  </div>
                </CardHeader>
                <CardContent>
                  {department.description && (
                    <CardDescription className="text-sm text-gray-600 mb-4">
                      {department.description}
                    </CardDescription>
                  )}
                  
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium text-gray-700">Manager:</span>
                      {department.manager ? (
                        <div className="flex items-center space-x-2">
                          <Badge variant="secondary" className="text-xs">
                            <UserCheck className="w-3 h-3 mr-1" />
                            {department.manager.firstName} {department.manager.lastName}
                          </Badge>
                        </div>
                      ) : (
                        <Badge variant="outline" className="text-xs">
                          <Users className="w-3 h-3 mr-1" />
                          No manager
                        </Badge>
                      )}
                    </div>

                    <div className="pt-2">
                      <Select
                        value={department.managerId || "none"}
                        onValueChange={(value) => handleAssignManager(department.id, value === "none" ? null : value)}
                        disabled={assignManager.isPending}
                      >
                        <SelectTrigger className="w-full">
                          <SelectValue placeholder="Assign manager" />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="none">No manager</SelectItem>
                          {employees.map((employee) => (
                            <SelectItem key={employee.id} value={employee.id}>
                              {employee.firstName} {employee.lastName} - {employee.employeeId}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}