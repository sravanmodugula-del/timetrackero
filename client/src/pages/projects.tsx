import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { useAuth } from "@/hooks/useAuth";
import { usePermissions } from "@/hooks/usePermissions";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { insertProjectSchema, type Project, type Employee, type ProjectWithEmployees } from "@shared/schema";
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Plus, Edit2, Trash2, FolderOpen, Users, Globe, Calendar, Settings } from "lucide-react";
import { getProjectStatus } from "@/lib/projectUtils";
import Header from "@/components/layout/header";

const projectFormSchema = insertProjectSchema.omit({ userId: true }).extend({
  assignedEmployeeIds: z.array(z.string()).optional(),
  startDate: z.string().optional(),
  endDate: z.string().optional(),
  projectNumber: z.string().optional(),
});
type ProjectFormData = z.infer<typeof projectFormSchema>;

const projectColors = [
  { value: "#1976D2", label: "Blue", class: "bg-blue-500" },
  { value: "#388E3C", label: "Green", class: "bg-green-500" },
  { value: "#F57C00", label: "Orange", class: "bg-orange-500" },
  { value: "#D32F2F", label: "Red", class: "bg-red-500" },
  { value: "#7B1FA2", label: "Purple", class: "bg-purple-500" },
  { value: "#455A64", label: "Blue Grey", class: "bg-slate-500" },
];

export default function Projects() {
  const { isAuthenticated, isLoading: authLoading, role } = useAuth();
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const permissions = usePermissions();
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingProject, setEditingProject] = useState<ProjectWithEmployees | null>(null);
  const [activeTab, setActiveTab] = useState("details");
  
  const form = useForm<ProjectFormData>({
    resolver: zodResolver(projectFormSchema),
    defaultValues: {
      name: "",
      projectNumber: "",
      description: "",
      color: "#1976D2",
      isEnterpriseWide: true,
      assignedEmployeeIds: [],
      startDate: "",
      endDate: "",
    },
  });

  // Redirect if not authenticated
  if (!authLoading && !isAuthenticated) {
    setTimeout(() => {
      window.location.href = "/api/login";
    }, 500);
    return null;
  }

  const { data: projects, isLoading } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
    enabled: isAuthenticated,
  });

  // Fetch employees for project assignment
  const { data: employees = [] } = useQuery<Employee[]>({
    queryKey: ["/api/employees"],
    enabled: isAuthenticated,
    retry: false,
  });

  const createProject = useMutation({
    mutationFn: async (data: ProjectFormData) => {
      const { assignedEmployeeIds, startDate, endDate, ...projectData } = data;
      
      // Send date strings directly - backend will handle conversion
      const formattedData = {
        ...projectData,
        ...(startDate && startDate.trim() && { startDate }),
        ...(endDate && endDate.trim() && { endDate }),
      };
      
      const project = await apiRequest("/api/projects", "POST", formattedData);
      
      // If project is restricted and has assigned employees, assign them
      if (!data.isEnterpriseWide && assignedEmployeeIds && assignedEmployeeIds.length > 0) {
        await apiRequest(`/api/projects/${project.id}/employees`, "POST", { employeeIds: assignedEmployeeIds });
      }
      
      return project;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/projects"] });
      setIsDialogOpen(false);
      setEditingProject(null);
      setActiveTab("details");
      form.reset();
      toast({
        title: "Success",
        description: "Project created successfully.",
      });
    },
    onError: (error: any) => {
      console.error("Failed to create project:", error);
      if (isUnauthorizedError(error)) {
        toast({
          title: "Authentication Required",
          description: "Please log in to continue.",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 1000);
      } else {
        toast({
          title: "Error",
          description: error.message || "Failed to create project.",
          variant: "destructive",
        });
      }
    },
  });

  const updateProject = useMutation({
    mutationFn: async (data: ProjectFormData) => {
      if (!editingProject) throw new Error("No project selected for editing");
      
      const { assignedEmployeeIds, startDate, endDate, ...projectData } = data;
      
      // Send date strings directly - backend will handle conversion
      const formattedData = {
        ...projectData,
        ...(startDate && startDate.trim() && { startDate }),
        ...(endDate && endDate.trim() && { endDate }),
      };
      
      const project = await apiRequest(`/api/projects/${editingProject.id}`, "PUT", formattedData);
      
      // Update employee assignments for restricted projects
      if (!data.isEnterpriseWide) {
        console.log("Attempting to assign employees:", assignedEmployeeIds);
        try {
          const employeeResponse = await apiRequest(`/api/projects/${editingProject.id}/employees`, "POST", { 
            employeeIds: assignedEmployeeIds || [] 
          });
          console.log("Employee assignment successful:", employeeResponse);
        } catch (employeeError) {
          console.error("Employee assignment failed:", employeeError);
          // Don't throw - let project update succeed even if employee assignment fails
          toast({
            title: "Warning",
            description: "Project updated but employee assignment failed. Please try again.",
            variant: "destructive",
          });
        }
      }
      
      return project;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/projects"] });
      setIsDialogOpen(false);
      setEditingProject(null);
      setActiveTab("details");
      form.reset();
      toast({
        title: "Success",
        description: "Project updated successfully.",
      });
    },
    onError: (error: any) => {
      console.error("Failed to update project:", error);
      if (isUnauthorizedError(error)) {
        toast({
          title: "Authentication Required",
          description: "Please log in to continue.",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 1000);
      } else {
        toast({
          title: "Error",
          description: error.message || "Failed to update project.",
          variant: "destructive",
        });
      }
    },
  });

  const deleteProject = useMutation({
    mutationFn: async (id: string) => {
      await apiRequest(`/api/projects/${id}`, "DELETE");
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/projects"] });
      toast({
        title: "Success",
        description: "Project deleted successfully.",
      });
    },
    onError: (error: any) => {
      console.error("Failed to delete project:", error);
      if (isUnauthorizedError(error)) {
        toast({
          title: "Authentication Required",
          description: "Please log in to continue.",
          variant: "destructive",
        });
        setTimeout(() => {
          window.location.href = "/api/login";
        }, 1000);
      } else {
        toast({
          title: "Error",
          description: error.message || "Failed to delete project.",
          variant: "destructive",
        });
      }
    },
  });

  const onSubmit = async (data: ProjectFormData) => {
    if (editingProject) {
      updateProject.mutate(data);
    } else {
      createProject.mutate(data);
    }
  };

  const getColorClass = (hexColor: string) => {
    const colorMap: { [key: string]: string } = {
      "#1976D2": "bg-blue-500",
      "#388E3C": "bg-green-500",
      "#F57C00": "bg-orange-500",
      "#D32F2F": "bg-red-500",
      "#7B1FA2": "bg-purple-500",
      "#455A64": "bg-slate-500",
    };
    return colorMap[hexColor] || "bg-blue-500";
  };

  const handleEdit = async (project: Project) => {
    // Fetch project with employee assignments if it's restricted
    let projectWithEmployees: ProjectWithEmployees = project;
    if (!project.isEnterpriseWide) {
      try {
        const assignedEmployees = await apiRequest(`/api/projects/${project.id}/employees`, "GET");
        projectWithEmployees = { ...project, assignedEmployees };
      } catch (error) {
        console.error("Failed to fetch project employees:", error);
        projectWithEmployees = { ...project, assignedEmployees: [] };
      }
    }
    
    setEditingProject(projectWithEmployees);
    form.reset({
      name: project.name,
      projectNumber: project.projectNumber || "",
      description: project.description || "",
      color: project.color || "#1976D2",
      startDate: project.startDate ? new Date(project.startDate).toISOString().split('T')[0] : "",
      endDate: project.endDate ? new Date(project.endDate).toISOString().split('T')[0] : "",
      isEnterpriseWide: project.isEnterpriseWide,
      assignedEmployeeIds: projectWithEmployees.assignedEmployees?.map(emp => emp.id) || [],
    });
    setActiveTab("details");
    setIsDialogOpen(true);
  };

  const handleDelete = (id: string) => {
    if (confirm("Are you sure you want to delete this project?")) {
      deleteProject.mutate(id);
    }
  };

  const handleNewProject = () => {
    setEditingProject(null);
    form.reset({
      name: "",
      projectNumber: "",
      description: "",
      color: "#1976D2",
      isEnterpriseWide: true,
      assignedEmployeeIds: [],
      startDate: "",
      endDate: "",
    });
    setActiveTab("details");
    setIsDialogOpen(true);
  };

  const handleDialogClose = () => {
    setIsDialogOpen(false);
    setEditingProject(null);
    setActiveTab("details");
    form.reset({
      name: "",
      projectNumber: "",
      description: "",
      color: "#1976D2",
      isEnterpriseWide: true,
      assignedEmployeeIds: [],
      startDate: "",
      endDate: "",
    });
  };

  if (authLoading || !isAuthenticated) {
    return (
      <div className="container mx-auto py-6">
        <div className="flex justify-center items-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="container mx-auto py-6 space-y-6">
      <Header />
      
      <div className="space-y-6">
        <div className="flex justify-between items-center">
          <div>
            <h1 className="text-3xl font-bold">Projects</h1>
            <p className="text-muted-foreground mt-1">
              Manage your projects and organize your time entries
            </p>
          </div>
          {permissions.canCreateProjects && (
            <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
              <DialogTrigger asChild>
                <Button onClick={handleNewProject} data-testid="button-new-project">
                  <Plus className="w-4 h-4 mr-2" />
                  New Project
                </Button>
              </DialogTrigger>
              <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
                <DialogHeader>
                  <DialogTitle>
                    {editingProject ? "Edit Project" : "Create New Project"}
                  </DialogTitle>
                  <DialogDescription>
                    {editingProject
                      ? "Update the project details and employee assignments."
                      : "Add a new project to organize your time entries."
                    }
                  </DialogDescription>
                </DialogHeader>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
                    <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                      <TabsList className="grid w-full grid-cols-2">
                        <TabsTrigger value="details" className="flex items-center gap-2">
                          <Settings className="w-4 h-4" />
                          Project Details
                        </TabsTrigger>
                        <TabsTrigger 
                          value="employees" 
                          className="flex items-center gap-2" 
                          disabled={form.watch("isEnterpriseWide")}
                          data-testid="tab-employees"
                        >
                          <Users className="w-4 h-4" />
                          Assigned Employees
                          {!form.watch("isEnterpriseWide") && (form.watch("assignedEmployeeIds")?.length || 0) > 0 && (
                            <Badge variant="secondary" className="ml-1">
                              {form.watch("assignedEmployeeIds")?.length || 0}
                            </Badge>
                          )}
                        </TabsTrigger>
                      </TabsList>

                      <TabsContent value="details" className="space-y-4 mt-4">
                        <FormField
                          control={form.control}
                          name="name"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Project Name</FormLabel>
                              <FormControl>
                                <Input placeholder="Enter project name" {...field} data-testid="input-project-name" />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="projectNumber"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Project Number (optional)</FormLabel>
                              <FormControl>
                                <Input 
                                  placeholder="e.g., PRJ-001, 2024-001, etc." 
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
                          name="description"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Description (optional)</FormLabel>
                              <FormControl>
                                <Textarea
                                  placeholder="Describe the project..."
                                  className="resize-none"
                                  rows={3}
                                  {...field}
                                  value={field.value || ""}
                                  data-testid="textarea-project-description"
                                />
                              </FormControl>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <FormField
                          control={form.control}
                          name="color"
                          render={({ field }) => (
                            <FormItem>
                              <FormLabel>Color</FormLabel>
                              <div className="flex flex-wrap gap-2">
                                {projectColors.map((color) => (
                                  <button
                                    key={color.value}
                                    type="button"
                                    className={`w-8 h-8 rounded-full border-2 ${color.class} ${
                                      field.value === color.value
                                        ? "border-gray-900 ring-2 ring-gray-900 ring-offset-2"
                                        : "border-gray-300"
                                    }`}
                                    onClick={() => field.onChange(color.value)}
                                  />
                                ))}
                              </div>
                              <FormMessage />
                            </FormItem>
                          )}
                        />

                        <div className="grid grid-cols-2 gap-4">
                          <FormField
                            control={form.control}
                            name="startDate"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>Start Date (optional)</FormLabel>
                                <FormControl>
                                  <Input 
                                    type="date" 
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
                            name="endDate"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel>End Date (optional)</FormLabel>
                                <FormControl>
                                  <Input 
                                    type="date" 
                                    {...field}
                                    value={field.value || ""}
                                    min={form.watch("startDate") || undefined}
                                  />
                                </FormControl>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        </div>

                        <FormField
                          control={form.control}
                          name="isEnterpriseWide"
                          render={({ field }) => (
                            <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                              <div className="space-y-0.5">
                                <FormLabel className="text-base flex items-center gap-2">
                                  <Globe className="w-4 h-4" />
                                  Enterprise-wide Project
                                </FormLabel>
                                <div className="text-sm text-muted-foreground">
                                  All employees can access this project. Disable to restrict access to specific employees.
                                </div>
                              </div>
                              <FormControl>
                                <Switch
                                  checked={field.value}
                                  onCheckedChange={field.onChange}
                                />
                              </FormControl>
                            </FormItem>
                          )}
                        />
                      </TabsContent>

                      <TabsContent value="employees" className="space-y-4 mt-4">
                        {!form.watch("isEnterpriseWide") ? (
                          <FormField
                            control={form.control}
                            name="assignedEmployeeIds"
                            render={({ field }) => (
                              <FormItem>
                                <FormLabel className="flex items-center gap-2">
                                  <Users className="w-4 h-4" />
                                  Assigned Employees
                                </FormLabel>
                                <FormControl>
                                  <div className="rounded-md border max-h-96 overflow-y-auto">
                                    {employees.length === 0 ? (
                                      <div className="p-4 text-center text-sm text-muted-foreground">
                                        No employees found. Add employees first to assign them to projects.
                                      </div>
                                    ) : (
                                      <ScrollArea className="h-full">
                                        <div className="p-4 space-y-2">
                                          {employees.map((employee) => (
                                            <div key={employee.id} className="flex items-center space-x-2">
                                              <Checkbox
                                                id={`employee-${employee.id}`}
                                                data-testid={`checkbox-employee-${employee.id}`}
                                                checked={field.value?.includes(employee.id) || false}
                                                onCheckedChange={(checked) => {
                                                  const currentValue = field.value || [];
                                                  if (checked) {
                                                    field.onChange([...currentValue, employee.id]);
                                                  } else {
                                                    field.onChange(currentValue.filter(id => id !== employee.id));
                                                  }
                                                }}
                                              />
                                              <label
                                                htmlFor={`employee-${employee.id}`}
                                                className="text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 cursor-pointer flex-1"
                                              >
                                                <div className="flex items-center justify-between">
                                                  <span>{employee.firstName} {employee.lastName}</span>
                                                  <span className="text-xs text-muted-foreground">
                                                    {employee.department} • {employee.employeeId}
                                                  </span>
                                                </div>
                                              </label>
                                            </div>
                                          ))}
                                        </div>
                                      </ScrollArea>
                                    )}
                                  </div>
                                </FormControl>
                                <div className="text-xs text-muted-foreground">
                                  {field.value?.length || 0} employee(s) selected
                                </div>
                                <FormMessage />
                              </FormItem>
                            )}
                          />
                        ) : (
                          <div className="p-8 text-center text-muted-foreground">
                            <Globe className="w-12 h-12 mx-auto mb-4 opacity-50" />
                            <h3 className="font-medium mb-2">Enterprise-wide Project</h3>
                            <p className="text-sm">
                              This project is available to all employees. To assign specific employees, 
                              disable the "Enterprise-wide Project" option in the Project Details tab.
                            </p>
                          </div>
                        )}
                      </TabsContent>
                    </Tabs>

                    <div className="flex justify-end space-x-2 pt-4">
                      <Button
                        type="button"
                        variant="outline"
                        onClick={handleDialogClose}
                      >
                        Cancel
                      </Button>
                      <Button
                        type="submit"
                        disabled={createProject.isPending || updateProject.isPending}
                        data-testid="button-submit-project"
                      >
                        {editingProject ? "Update" : "Create"} Project
                      </Button>
                    </div>
                  </form>
                </Form>
              </DialogContent>
            </Dialog>
          )}
        </div>

        {isLoading ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[...Array(6)].map((_, i) => (
              <Card key={i} className="animate-pulse">
                <CardHeader>
                  <div className="flex items-center space-x-3">
                    <div className="w-4 h-4 bg-gray-200 rounded-full"></div>
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
        ) : !projects || projects.length === 0 ? (
          <div className="text-center py-12">
            <FolderOpen className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900">No projects</h3>
            <p className="mt-1 text-sm text-gray-500">
              Get started by creating a new project.
            </p>
            {permissions.canCreateProjects && (
              <div className="mt-6">
                <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                  <DialogTrigger asChild>
                    <Button onClick={handleNewProject}>
                      <Plus className="w-4 h-4 mr-2" />
                      New Project
                    </Button>
                  </DialogTrigger>
                </Dialog>
              </div>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {projects.map((project) => (
              <Card key={project.id} className="hover:shadow-md transition-shadow" data-testid={`card-project-${project.name}`}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div
                        className={`w-4 h-4 rounded-full ${getColorClass(project.color || "#1976D2")}`}
                      ></div>
                      <div className="flex-1 min-w-0">
                        <CardTitle className="text-lg truncate">{project.name}</CardTitle>
                        {project.projectNumber && (
                          <p className="text-sm text-gray-500 mt-1">#{project.projectNumber}</p>
                        )}
                      </div>
                    </div>
                    <div className="flex space-x-1">
                      {permissions.canEditProjects && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleEdit(project)}
                          data-testid={`button-edit-${project.name}`}
                        >
                          <Edit2 className="w-4 h-4" />
                        </Button>
                      )}
                      {permissions.canDeleteProjects && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleDelete(project.id)}
                          data-testid={`button-delete-${project.name}`}
                        >
                          <Trash2 className="w-4 h-4" />
                        </Button>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {project.description && (
                      <p className="text-sm text-gray-600 line-clamp-2">
                        {project.description}
                      </p>
                    )}
                    <div className="flex items-center justify-between text-xs text-gray-500">
                      <div className="flex items-center space-x-4">
                        {project.startDate && (
                          <div className="flex items-center space-x-1">
                            <Calendar className="w-3 h-3" />
                            <span>{new Date(project.startDate).toLocaleDateString()}</span>
                          </div>
                        )}
                        {getProjectStatus(project) && (
                          <Badge variant="outline" className="text-xs">
                            {getProjectStatus(project)}
                          </Badge>
                        )}
                      </div>
                      <div className="flex items-center space-x-1">
                        {project.isEnterpriseWide ? (
                          <Badge variant="secondary" className="text-xs">
                            <Globe className="w-3 h-3 mr-1" />
                            All Employees
                          </Badge>
                        ) : (
                          <Badge variant="outline" className="text-xs">
                            <Users className="w-3 h-3 mr-1" />
                            Restricted
                          </Badge>
                        )}
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}