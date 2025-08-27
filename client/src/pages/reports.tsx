import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { usePermissions } from "@/hooks/usePermissions";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import Header from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Download, FileText, Calendar, Clock } from "lucide-react";
import type { Project, TimeEntry, Employee } from "@shared/schema";
import { format } from "date-fns";

interface TimeEntryWithEmployee extends TimeEntry {
  employee?: Employee;
  task?: {
    id: string;
    name: string;
    description?: string;
    status: string;
  };
}

export default function Reports() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const { canViewReports } = usePermissions();
  const [selectedProject, setSelectedProject] = useState<string>("");
  
  // Check if user can view reports
  const canAccessReports = canViewReports;

  // Redirect to home if not authenticated or not authorized
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
    
    if (!isLoading && isAuthenticated && !canAccessReports) {
      toast({
        title: "Access Denied",
        description: "You don't have permission to view reports.",
        variant: "destructive",
      });
      // Don't redirect, just show error
    }
  }, [isAuthenticated, isLoading, canAccessReports, toast]);

  // Fetch projects
  const { data: projects = [] } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
    enabled: isAuthenticated && canAccessReports,
  });

  // Fetch time entries for selected project
  const { data: timeEntries = [], isLoading: timeEntriesLoading, refetch } = useQuery<TimeEntryWithEmployee[]>({
    queryKey: ["/api/reports/project-time-entries", selectedProject],
    queryFn: async () => {
      return await apiRequest(`/api/reports/project-time-entries/${selectedProject}`, "GET");
    },
    enabled: isAuthenticated && canAccessReports && !!selectedProject,
  });

  const formatDuration = (hours: number) => {
    const wholeHours = Math.floor(hours);
    const minutes = Math.round((hours - wholeHours) * 60);
    return `${wholeHours}h ${minutes}m`;
  };

  const getTotalHours = () => {
    return timeEntries.reduce((total, entry) => {
      const duration = typeof entry.duration === 'number' ? entry.duration : parseFloat(entry.duration as string) || 0;
      return total + duration;
    }, 0);
  };

  const exportToCSV = () => {
    if (!timeEntries.length) {
      toast({
        title: "No Data",
        description: "No time entries to export.",
        variant: "destructive",
      });
      return;
    }

    const selectedProjectName = projects.find(p => p.id === selectedProject)?.name || "Unknown Project";
    
    // CSV headers
    const headers = [
      "Date",
      "Project Number",
      "Project Name",
      "Employee",
      "Task",
      "Description", 
      "Duration (Hours)",
      "Created At"
    ];

    // CSV rows
    const rows = timeEntries.map(entry => {
      const duration = typeof entry.duration === 'number' ? entry.duration : parseFloat(entry.duration as string) || 0;
      const selectedProjectData = projects.find(p => p.id === selectedProject);
      return [
        entry.date ? format(new Date(entry.date), "MM/dd/yyyy") : "Unknown Date",
        selectedProjectData?.projectNumber || "",
        selectedProjectData?.name || "Unknown Project",
        entry.employee ? `${entry.employee.firstName} ${entry.employee.lastName}` : "Unknown Employee",
        entry.task ? entry.task.name : "No Task",
        entry.description || "",
        duration.toFixed(2),
        entry.createdAt ? format(new Date(entry.createdAt), "MM/dd/yyyy HH:mm:ss") : "Unknown"
      ];
    });

    // Create CSV content
    const csvContent = [
      headers.join(","),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(","))
    ].join("\n");

    // Download CSV
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const link = document.createElement("a");
    const url = URL.createObjectURL(blob);
    link.setAttribute("href", url);
    link.setAttribute("download", `${selectedProjectName}_time_entries_${format(new Date(), "yyyy-MM-dd")}.csv`);
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    toast({
      title: "Export Successful",
      description: "Time entries exported to CSV file.",
    });
  };

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

  if (!canAccessReports) {
    return (
      <div className="min-h-screen bg-background">
        <Header />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <Card>
            <CardContent className="p-8 text-center">
              <FileText className="mx-auto h-12 w-12 text-gray-400 mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Access Denied</h3>
              <p className="text-gray-600">You don't have permission to view project reports.</p>
            </CardContent>
          </Card>
        </main>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Project Reports</h2>
          <p className="text-gray-600">View and export time entries for projects</p>
        </div>

        {/* Project Selection */}
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="w-5 h-5" />
              Select Project
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row sm:items-end gap-4">
              <div className="flex-1">
                <label className="block text-sm font-medium text-gray-700 mb-1">Project</label>
                <Select value={selectedProject} onValueChange={setSelectedProject}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Choose a project to view reports" />
                  </SelectTrigger>
                  <SelectContent>
                    {projects.map(project => (
                      <SelectItem key={project.id} value={project.id}>
                        <div className="flex items-center gap-2">
                          <div 
                            className="w-3 h-3 rounded-full" 
                            style={{ backgroundColor: project.color || "#1976D2" }}
                          ></div>
                          {project.name}
                          {project.projectNumber && (
                            <span className="text-xs text-gray-500">#{project.projectNumber}</span>
                          )}
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              {selectedProject && timeEntries.length > 0 && (
                <Button onClick={exportToCSV} className="flex items-center gap-2">
                  <Download className="w-4 h-4" />
                  Export CSV
                </Button>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Report Content */}
        {!selectedProject ? (
          <Card>
            <CardContent className="p-8 text-center">
              <FileText className="mx-auto h-12 w-12 text-gray-400 mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">Select a Project</h3>
              <p className="text-gray-600">Choose a project from the dropdown above to view its time entries.</p>
            </CardContent>
          </Card>
        ) : timeEntriesLoading ? (
          <Card>
            <CardContent className="p-8 text-center">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
              <p className="text-muted-foreground">Loading time entries...</p>
            </CardContent>
          </Card>
        ) : timeEntries.length === 0 ? (
          <Card>
            <CardContent className="p-8 text-center">
              <Clock className="mx-auto h-12 w-12 text-gray-400 mb-4" />
              <h3 className="text-lg font-medium text-gray-900 mb-2">No Time Entries</h3>
              <p className="text-gray-600">No time entries found for this project.</p>
            </CardContent>
          </Card>
        ) : (
          <>
            {/* Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-6">
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center">
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-600">Total Entries</p>
                      <p className="text-2xl font-bold text-gray-900">{timeEntries.length}</p>
                    </div>
                    <Calendar className="w-8 h-8 text-blue-600" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center">
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-600">Total Hours</p>
                      <p className="text-2xl font-bold text-gray-900">{formatDuration(getTotalHours())}</p>
                    </div>
                    <Clock className="w-8 h-8 text-green-600" />
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardContent className="p-6">
                  <div className="flex items-center">
                    <div className="flex-1">
                      <p className="text-sm font-medium text-gray-600">Unique Employees</p>
                      <p className="text-2xl font-bold text-gray-900">
                        {new Set(timeEntries.map(entry => entry.employee?.id).filter(Boolean)).size}
                      </p>
                    </div>
                    <FileText className="w-8 h-8 text-purple-600" />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Time Entries Table */}
            <Card>
              <CardHeader>
                <CardTitle>Time Entries</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Date</TableHead>
                        <TableHead>Project #</TableHead>
                        <TableHead>Employee</TableHead>
                        <TableHead>Task</TableHead>
                        <TableHead>Description</TableHead>
                        <TableHead>Duration</TableHead>
                        <TableHead>Created</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {timeEntries.map((entry) => {
                        const selectedProjectData = projects.find(p => p.id === selectedProject);
                        return (
                          <TableRow key={entry.id}>
                            <TableCell>
                              <Badge variant="outline">
                                {entry.date ? format(new Date(entry.date), "MMM dd, yyyy") : "Unknown Date"}
                              </Badge>
                            </TableCell>
                            <TableCell>
                              {selectedProjectData?.projectNumber ? (
                                <Badge variant="outline" className="bg-blue-50 text-blue-700">
                                  {selectedProjectData.projectNumber}
                                </Badge>
                              ) : (
                                <span className="text-gray-400 text-sm">—</span>
                              )}
                            </TableCell>
                            <TableCell>
                              {entry.employee 
                                ? `${entry.employee.firstName} ${entry.employee.lastName}`
                                : "Unknown Employee"
                              }
                            </TableCell>
                            <TableCell>
                              {entry.task ? (
                                <Badge variant="secondary" className="bg-green-100 text-green-800">
                                  {entry.task.name}
                                </Badge>
                              ) : (
                                <span className="text-gray-400 text-sm">No task</span>
                              )}
                            </TableCell>
                            <TableCell className="max-w-xs">
                              <div className="truncate" title={entry.description || ""}>
                                {entry.description || "No description"}
                              </div>
                            </TableCell>
                            <TableCell>
                              <Badge className="bg-blue-100 text-blue-800">
                                {formatDuration(typeof entry.duration === 'number' ? entry.duration : parseFloat(entry.duration as string) || 0)}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-sm text-gray-500">
                              {entry.createdAt ? format(new Date(entry.createdAt), "MMM dd, HH:mm") : "Unknown"}
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </main>
    </div>
  );
}