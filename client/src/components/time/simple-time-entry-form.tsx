import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Clock, Timer, Save, X } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { apiRequest } from "@/lib/queryClient";

interface Project {
  id: string;
  name: string;
  color: string;
  startDate: string;
  endDate: string;
}

interface Task {
  id: string;
  name: string;
  projectId: string;
  status: string;
}

// Simple unified schema
const timeEntrySchema = z.object({
  projectId: z.string().min(1, "Project is required"),
  taskId: z.string().min(1, "Task is required"),
  description: z.string().optional(),
  date: z.string().min(1, "Date is required"),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  duration: z.string().optional(),
});

type TimeEntryForm = z.infer<typeof timeEntrySchema>;
type TimeEntryFormData = TimeEntryForm;

function getCurrentLocalDate(): string {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function getActiveProjects(projects: Project[]): Project[] {
  const now = new Date().toISOString().split('T')[0];
  return projects.filter(project => {
    const startDate = project.startDate || '1900-01-01';
    const endDate = project.endDate || '2100-12-31';
    return now >= startDate && now <= endDate;
  });
}

export default function SimpleTimeEntryForm() {
  const [inputMode, setInputMode] = React.useState<"timeRange" | "manualDuration">("timeRange");
  const [calculatedDuration, setCalculatedDuration] = React.useState("");
  const { toast } = useToast();
  const queryClient = useQueryClient();

  const form = useForm<TimeEntryForm>({
    resolver: zodResolver(timeEntrySchema),
    defaultValues: {
      projectId: "",
      taskId: "",
      description: "",
      date: getCurrentLocalDate(),
      startTime: "",
      endTime: "",
      duration: "",
    },
  });

  // Fetch projects
  const { data: allProjects, isLoading: projectsLoading } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
  });
  
  const projects = allProjects ? getActiveProjects(allProjects) : [];

  // Watch project selection
  const selectedProjectId = form.watch("projectId");

  // Fetch tasks for selected project
  const { data: tasks, isLoading: tasksLoading } = useQuery<Task[]>({
    queryKey: ["/api/projects", selectedProjectId, "tasks"],
    enabled: !!selectedProjectId,
  });

  const activeTasks = tasks?.filter(task => task.status === "active") || [];

  // Calculate duration for time range mode
  const calculateDuration = (startTime: string | undefined, endTime: string | undefined) => {
    if (!startTime || !endTime) {
      setCalculatedDuration("");
      return;
    }

    const start = new Date(`2000-01-01T${startTime}:00`);
    const end = new Date(`2000-01-01T${endTime}:00`);
    
    if (end <= start) {
      setCalculatedDuration("Invalid time range");
      return;
    }

    const diffMs = end.getTime() - start.getTime();
    const hours = diffMs / (1000 * 60 * 60);
    setCalculatedDuration(`${hours.toFixed(1)} hours`);
  };

  // Watch time changes
  const startTime = form.watch("startTime");
  const endTime = form.watch("endTime");

  React.useEffect(() => {
    if (inputMode === "timeRange") {
      calculateDuration(startTime, endTime);
    }
  }, [startTime, endTime, inputMode]);

  // Create time entry mutation
  const createTimeEntry = useMutation({
    mutationFn: async (data: TimeEntryFormData) => {
      return apiRequest("/api/time-entries", "POST", data);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Time entry saved successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/time-entries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard"] });
      form.reset({
        projectId: "",
        taskId: "",
        description: "",
        date: getCurrentLocalDate(),
        startTime: "",
        endTime: "",
        duration: "",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message || "Failed to save time entry",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: TimeEntryForm) => {
    let submissionData: TimeEntryFormData;
    
    if (inputMode === "timeRange") {
      // Validate time range inputs
      if (!data.startTime || !data.endTime) {
        toast({
          title: "Error",
          description: "Please enter both start and end times",
          variant: "destructive",
        });
        return;
      }
      
      // Calculate duration from start/end times
      const start = new Date(`2000-01-01T${data.startTime}:00`);
      const end = new Date(`2000-01-01T${data.endTime}:00`);
      
      if (end <= start) {
        toast({
          title: "Error",
          description: "End time must be after start time",
          variant: "destructive",
        });
        return;
      }
      
      const diffMs = end.getTime() - start.getTime();
      const hours = diffMs / (1000 * 60 * 60);
      
      submissionData = {
        projectId: data.projectId,
        taskId: data.taskId,
        description: data.description || "",
        date: data.date,
        startTime: data.startTime,
        endTime: data.endTime,
        duration: hours.toFixed(2),
      };
    } else {
      // Validate manual duration input
      if (!data.duration) {
        toast({
          title: "Error",
          description: "Please enter a duration",
          variant: "destructive",
        });
        return;
      }
      
      // Use manual duration
      submissionData = {
        projectId: data.projectId,
        taskId: data.taskId,
        description: data.description || "",
        date: data.date,
        duration: data.duration,
      };
    }

    createTimeEntry.mutate(submissionData);
  };

  const handleModeSwitch = (newMode: "timeRange" | "manualDuration") => {
    setInputMode(newMode);
    // Clear mode-specific fields when switching
    if (newMode === "timeRange") {
      form.setValue("duration", "");
    } else {
      form.setValue("startTime", "");
      form.setValue("endTime", "");
    }
  };

  const handleClearForm = () => {
    form.reset({
      projectId: "",
      taskId: "",
      description: "",
      date: getCurrentLocalDate(),
      startTime: "",
      endTime: "",
      duration: "",
    });
    setCalculatedDuration("");
  };

  return (
    <div className="max-w-2xl">
      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xl font-semibold">Log Time Entry</CardTitle>
            <div className="flex items-center gap-2">
              <Button
                type="button"
                variant={inputMode === "timeRange" ? "default" : "outline"}
                size="sm"
                onClick={() => handleModeSwitch("timeRange")}
                className="flex items-center gap-2"
              >
                <Clock className="w-4 h-4" />
                Start/End Time
              </Button>
              <Button
                type="button"
                variant={inputMode === "manualDuration" ? "default" : "outline"}
                size="sm"
                onClick={() => handleModeSwitch("manualDuration")}
                className="flex items-center gap-2"
              >
                <Timer className="w-4 h-4" />
                Manual Duration
              </Button>
            </div>
          </div>
          <div className="flex items-center gap-2 mt-2">
            <Badge variant="outline" className="text-xs">
              {inputMode === "timeRange" ? "Calculate duration automatically" : "Enter duration directly"}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Project Selection */}
                <FormField
                  control={form.control}
                  name="projectId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Project *</FormLabel>
                      <Select 
                        onValueChange={(value) => {
                          field.onChange(value);
                          form.setValue("taskId", ""); // Reset task when project changes
                        }} 
                        value={field.value}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select a project" />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {projectsLoading ? (
                            <div className="p-2 text-sm text-muted-foreground">
                              Loading projects...
                            </div>
                          ) : projects.length === 0 ? (
                            <div className="p-2 text-sm text-muted-foreground">
                              No active projects available
                            </div>
                          ) : (
                            projects.map((project) => (
                              <SelectItem key={project.id} value={project.id}>
                                <div className="flex items-center gap-2">
                                  <div 
                                    className="w-3 h-3 rounded-full" 
                                    style={{ backgroundColor: project.color || "#1976D2" }}
                                  />
                                  {project.name}
                                </div>
                              </SelectItem>
                            ))
                          )}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                {/* Task Selection */}
                <FormField
                  control={form.control}
                  name="taskId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Task *</FormLabel>
                      <Select 
                        onValueChange={field.onChange} 
                        value={field.value}
                        disabled={!selectedProjectId || activeTasks.length === 0}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder={
                              !selectedProjectId 
                                ? "Select a project first" 
                                : activeTasks.length === 0 
                                  ? "No tasks available" 
                                  : "Select a task"
                            } />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {tasksLoading ? (
                            <div className="p-2 text-sm text-muted-foreground">
                              Loading tasks...
                            </div>
                          ) : activeTasks.length === 0 ? (
                            <div className="p-2 text-sm text-muted-foreground">
                              No active tasks available
                            </div>
                          ) : (
                            activeTasks.map((task) => (
                              <SelectItem key={task.id} value={task.id}>
                                {task.name}
                              </SelectItem>
                            ))
                          )}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* Date */}
              <FormField
                control={form.control}
                name="date"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Date *</FormLabel>
                    <FormControl>
                      <Input type="date" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Time Range Mode */}
              {inputMode === "timeRange" && (
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <FormField
                    control={form.control}
                    name="startTime"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Start Time *</FormLabel>
                        <FormControl>
                          <Input type="time" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="endTime"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>End Time *</FormLabel>
                        <FormControl>
                          <Input type="time" {...field} />
                        </FormControl>
                        <FormMessage />
                        {calculatedDuration && (
                          <p className="text-sm text-muted-foreground mt-1">
                            Duration: {calculatedDuration}
                          </p>
                        )}
                      </FormItem>
                    )}
                  />
                </div>
              )}

              {/* Manual Duration Mode */}
              {inputMode === "manualDuration" && (
                <FormField
                  control={form.control}
                  name="duration"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Duration (hours) *</FormLabel>
                      <FormControl>
                        <Input 
                          type="number" 
                          step="0.01" 
                          placeholder="e.g., 2.5 for 2 hours 30 minutes"
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}

              {/* Description */}
              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description (optional)</FormLabel>
                    <FormControl>
                      <Textarea
                        {...field}
                        rows={4}
                        placeholder="Describe what you worked on..."
                        className="resize-none"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Submit Buttons */}
              <div className="flex flex-col sm:flex-row gap-4 pt-4">
                <Button
                  type="submit"
                  className="flex-1"
                  disabled={createTimeEntry.isPending}
                >
                  <Save className="w-4 h-4 mr-2" />
                  {createTimeEntry.isPending ? "Saving..." : "Save Time Entry"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={handleClearForm}
                >
                  <X className="w-4 h-4 mr-2" />
                  Clear Form
                </Button>
              </div>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  );
}