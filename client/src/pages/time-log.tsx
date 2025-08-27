import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import Header from "@/components/layout/header";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Pencil, Trash2, Download, Plus } from "lucide-react";
import { Link } from "wouter";
import type { TimeEntryWithProject, Project } from "@shared/schema";
import EnhancedTimeEntryModal from "@/components/time/enhanced-time-entry-modal";
import { apiRequest } from "@/lib/queryClient";

export default function TimeLog() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const [selectedProject, setSelectedProject] = useState<string>("all");
  const [dateRange, setDateRange] = useState<string>("month");
  const [editingEntry, setEditingEntry] = useState<TimeEntryWithProject | null>(null);

  // Redirect to home if not authenticated
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
  }, [isAuthenticated, isLoading, toast]);

  // Fetch projects
  const { data: projects } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
    enabled: isAuthenticated,
  });

  // Calculate date filters
  const getDateFilters = () => {
    const now = new Date();
    const todayPST = now.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
    const today = new Date(todayPST + 'T00:00:00');
    
    switch (dateRange) {
      case "today":
        return {
          startDate: todayPST,
          endDate: todayPST,
        };
      case "week": {
        const startDate = new Date(today);
        startDate.setDate(today.getDate() - 7);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
      case "quarter": {
        const startDate = new Date(today);
        startDate.setMonth(today.getMonth() - 3);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
      default: { // month
        const startDate = new Date(today);
        startDate.setMonth(today.getMonth() - 1);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
    }
  };

  // Fetch time entries
  const { startDate, endDate } = getDateFilters();
  const { data: timeEntries, isLoading: entriesLoading, refetch } = useQuery<TimeEntryWithProject[]>({
    queryKey: ["/api/time-entries", { projectId: selectedProject, startDate, endDate }],
    queryFn: async () => {
      const params = new URLSearchParams({
        projectId: selectedProject,
        startDate,
        endDate,
      });
      const response = await fetch(`/api/time-entries?${params}`);
      if (!response.ok) {
        throw new Error(`${response.status}: ${response.statusText}`);
      }
      return response.json();
    },
    enabled: isAuthenticated,
  });

  const handleDeleteEntry = async (entryId: string) => {
    if (!confirm('Are you sure you want to delete this time entry?')) {
      return;
    }

    try {
      await apiRequest(`/api/time-entries/${entryId}`, 'DELETE');
      toast({
        title: "Success",
        description: "Time entry deleted successfully",
      });
      refetch();
    } catch (error) {
      if (isUnauthorizedError(error as Error)) {
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
        description: "Failed to delete time entry",
        variant: "destructive",
      });
    }
  };

  const formatTime = (time: string) => {
    const [hours, minutes] = time.split(':');
    const hour = parseInt(hours);
    const ampm = hour >= 12 ? 'PM' : 'AM';
    const displayHour = hour % 12 || 12;
    return `${displayHour}:${minutes} ${ampm}`;
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString + 'T00:00:00');
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      year: 'numeric' 
    });
  };

  const getProjectColor = (project: Project) => {
    const colors = {
      '#1976D2': 'bg-primary/10 text-primary',
      '#388E3C': 'bg-green-100 text-green-700',
      '#F57C00': 'bg-orange-100 text-orange-700',
      '#D32F2F': 'bg-red-100 text-red-700',
    };
    return colors[project.color as keyof typeof colors] || 'bg-gray-100 text-gray-700';
  };

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h2 className="text-2xl font-bold text-gray-900 mb-2">Time Log</h2>
          <p className="text-gray-600">View and edit your time entries</p>
        </div>

        {/* Filters */}
        <Card className="mb-6">
          <CardContent className="p-6">
            <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
              <div className="flex flex-col sm:flex-row gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Filter by Project</label>
                  <Select value={selectedProject} onValueChange={setSelectedProject}>
                    <SelectTrigger className="w-48">
                      <SelectValue placeholder="All Projects" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Projects</SelectItem>
                      {projects?.map(project => (
                        <SelectItem key={project.id} value={project.id}>
                          {project.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">Date Range</label>
                  <Select value={dateRange} onValueChange={setDateRange}>
                    <SelectTrigger className="w-32">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="today">Today</SelectItem>
                      <SelectItem value="week">This Week</SelectItem>
                      <SelectItem value="month">This Month</SelectItem>
                      <SelectItem value="quarter">This Quarter</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Button variant="outline" size="sm">
                  <Download className="w-4 h-4 mr-2" />
                  Export
                </Button>
                <Link href="/time-entry">
                  <Button size="sm">
                    <Plus className="w-4 h-4 mr-2" />
                    Add Entry
                  </Button>
                </Link>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Time Entries Table */}
        <Card>
          <CardContent className="p-0">
            {entriesLoading ? (
              <div className="p-8 text-center">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
                <p className="text-muted-foreground">Loading time entries...</p>
              </div>
            ) : !timeEntries || timeEntries.length === 0 ? (
              <div className="p-8 text-center">
                <p className="text-muted-foreground mb-4">No time entries found for the selected filters.</p>
                <Link href="/time-entry">
                  <Button>
                    <Plus className="w-4 h-4 mr-2" />
                    Add Your First Entry
                  </Button>
                </Link>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50 border-b border-gray-200">
                    <tr>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Project #</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Task</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Start Time</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">End Time</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Duration</th>
                      <th className="px-6 py-4 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-200">
                    {timeEntries.map((entry) => (
                      <tr key={entry.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {formatDate(entry.date)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <Badge className={getProjectColor(entry.project)}>
                            {entry.project.name}
                          </Badge>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                          {entry.project.projectNumber ? (
                            <Badge variant="outline" className="bg-gray-50 text-gray-700">
                              {entry.project.projectNumber}
                            </Badge>
                          ) : (
                            <span className="text-gray-400 text-xs">—</span>
                          )}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-600">
                          {entry.task?.name || "—"}
                        </td>
                        <td className="px-6 py-4 text-sm text-gray-900 max-w-xs truncate">
                          {entry.description || "No description"}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {formatTime(entry.startTime)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                          {formatTime(entry.endTime)}
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">
                          {entry.duration}h
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                          <div className="flex space-x-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setEditingEntry(entry)}
                              className="text-primary hover:text-primary/80"
                            >
                              <Pencil className="w-4 h-4" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => handleDeleteEntry(entry.id)}
                              className="text-destructive hover:text-destructive/80"
                            >
                              <Trash2 className="w-4 h-4" />
                            </Button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Edit Modal */}
        {editingEntry && (
          <EnhancedTimeEntryModal
            entry={editingEntry}
            onClose={() => setEditingEntry(null)}
            onSuccess={() => {
              setEditingEntry(null);
              refetch();
            }}
          />
        )}
      </main>
    </div>
  );
}
