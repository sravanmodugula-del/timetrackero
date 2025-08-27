import { useState } from "react";
import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { insertTimeEntrySchema, type Project, type Task, type TimeEntryWithProject } from "@shared/schema";
import { getActiveProjects } from "@/lib/projectUtils";
import { z } from "zod";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Clock, Timer, Save, X, Calendar, ArrowLeftRight } from "lucide-react";

// Enhanced schema that supports both input modes
const enhancedTimeEntrySchema = z.object({
  projectId: z.string().min(1, "Project is required"),
  taskId: z.string().min(1, "Task is required"),
  description: z.string().optional(),
  date: z.string().min(1, "Date is required"),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  duration: z.string().optional(),
});

type EnhancedTimeEntryFormData = z.infer<typeof enhancedTimeEntrySchema>;
type TimeEntryFormData = EnhancedTimeEntryFormData;

interface EnhancedTimeEntryModalProps {
  entry: TimeEntryWithProject;
  onClose: () => void;
  onSuccess: () => void;
}

function getCurrentLocalDate(): string {
  const now = new Date();
  return now.toLocaleDateString('en-CA', { 
    timeZone: 'America/Los_Angeles' 
  });
}

export default function EnhancedTimeEntryModal({ entry, onClose, onSuccess }: EnhancedTimeEntryModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  
  // State for input mode switching
  const [inputMode, setInputMode] = useState<"timeRange" | "manualDuration">(
    entry.startTime && entry.endTime ? "timeRange" : "manualDuration"
  );
  const [calculatedDuration, setCalculatedDuration] = useState<string>("");

  const form = useForm<EnhancedTimeEntryFormData>({
    resolver: zodResolver(enhancedTimeEntrySchema),
    defaultValues: {
      projectId: entry.projectId,
      taskId: entry.taskId || "",
      description: entry.description || "",
      date: entry.date,
      startTime: entry.startTime || "",
      endTime: entry.endTime || "",
      duration: entry.duration || "",
    },
  });

  // Fetch projects and filter for active ones only
  const { data: allProjects, isLoading: projectsLoading } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
  });
  
  const projects = allProjects ? getActiveProjects(allProjects) : [];

  // Watch project selection for task loading
  const selectedProjectId = form.watch("projectId");

  // Fetch tasks for selected project
  const { data: tasks, isLoading: tasksLoading } = useQuery<Task[]>({
    queryKey: ["/api/projects", selectedProjectId, "tasks"],
    enabled: !!selectedProjectId,
  });

  const activeTasks = tasks?.filter(task => task.status === "active") || [];

  // Calculate duration when start/end times change
  const calculateDuration = (startTime?: string, endTime?: string) => {
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

  // Watch time changes for auto-calculation
  const startTime = form.watch("startTime");
  const endTime = form.watch("endTime");

  React.useEffect(() => {
    if (inputMode === "timeRange") {
      calculateDuration(startTime, endTime);
    }
  }, [startTime, endTime, inputMode]);

  // Update time entry mutation
  const updateTimeEntry = useMutation({
    mutationFn: async (data: TimeEntryFormData) => {
      return apiRequest(`/api/time-entries/${entry.id}`, "PUT", data);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Time entry updated successfully",
      });
      queryClient.invalidateQueries({ queryKey: ["/api/time-entries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard"] });
      onSuccess();
    },
    onError: (error: Error) => {
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
      
      console.error("Update time entry error:", error);
      toast({
        title: "Error",
        description: error.message || "Failed to update time entry",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: EnhancedTimeEntryFormData) => {
    if (inputMode === "timeRange") {
      if (!data.startTime || !data.endTime) {
        toast({
          title: "Error",
          description: "Please enter both start and end times",
          variant: "destructive",
        });
        return;
      }
      
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
      
      const submissionData = {
        projectId: data.projectId,
        taskId: data.taskId,
        description: data.description || "",
        date: data.date,
        startTime: data.startTime,
        endTime: data.endTime,
        duration: hours.toFixed(2),
      };
      
      updateTimeEntry.mutate(submissionData);
    } else {
      if (!data.duration) {
        toast({
          title: "Error",
          description: "Please enter a duration",
          variant: "destructive",
        });
        return;
      }
      
      const durationNum = parseFloat(data.duration);
      if (isNaN(durationNum) || durationNum <= 0 || durationNum > 24) {
        toast({
          title: "Error",
          description: "Duration must be between 0.1 and 24 hours",
          variant: "destructive",
        });
        return;
      }
      
      const submissionData = {
        projectId: data.projectId,
        taskId: data.taskId,
        description: data.description || "",
        date: data.date,
        duration: data.duration,
      };
      
      updateTimeEntry.mutate(submissionData);
    }
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
    setCalculatedDuration("");
  };

  // Quick date selection handlers (PST timezone)
  const handleQuickDateSelect = (daysAgo: number) => {
    const now = new Date();
    const pstDate = now.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
    const today = new Date(pstDate + 'T00:00:00');
    const targetDate = new Date(today);
    targetDate.setDate(today.getDate() - daysAgo);
    const formattedDate = targetDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
    form.setValue("date", formattedDate);
  };

  return (
    <Dialog open={true} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ArrowLeftRight className="w-5 h-5" />
            Edit Time Entry
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-6">
          {/* Input Mode Toggle */}
          <div className="flex items-center justify-between">
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
            <Badge variant="outline" className="text-xs">
              {inputMode === "timeRange" ? "Calculate duration automatically" : "Enter duration directly"}
            </Badge>
          </div>

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
                          form.setValue("taskId", "");
                        }} 
                        value={field.value}
                        disabled={projectsLoading}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder={
                              projectsLoading 
                                ? "Loading projects..." 
                                : projects.length === 0 
                                  ? "No active projects" 
                                  : "Select a project"
                            } />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {projects.map((project) => (
                            <SelectItem key={project.id} value={project.id}>
                              <div className="flex items-center gap-2">
                                <div 
                                  className="w-3 h-3 rounded-full" 
                                  style={{ backgroundColor: project.color || "#1976D2" }}
                                />
                                {project.name}
                              </div>
                            </SelectItem>
                          ))}
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
                        disabled={!selectedProjectId || tasksLoading}
                      >
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder={
                              !selectedProjectId 
                                ? "Select a project first" 
                                : tasksLoading
                                  ? "Loading tasks..."
                                  : activeTasks.length === 0 
                                    ? "No tasks available" 
                                    : "Select a task"
                            } />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {activeTasks.map((task) => (
                            <SelectItem key={task.id} value={task.id}>
                              {task.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* Date with Quick Select */}
              <FormField
                control={form.control}
                name="date"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel className="flex items-center gap-2">
                      <Calendar className="w-4 h-4" />
                      Date *
                    </FormLabel>
                    <FormControl>
                      <Input 
                        type="date" 
                        {...field}
                        max={getCurrentLocalDate()}
                        className="w-full"
                      />
                    </FormControl>
                    <FormMessage />
                    <div className="flex items-center gap-2 mt-2">
                      <p className="text-xs text-muted-foreground">Quick select:</p>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-6 px-2 text-xs"
                        onClick={() => handleQuickDateSelect(0)}
                      >
                        Today
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-6 px-2 text-xs"
                        onClick={() => handleQuickDateSelect(1)}
                      >
                        Yesterday
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-6 px-2 text-xs"
                        onClick={() => handleQuickDateSelect(2)}
                      >
                        2 days ago
                      </Button>
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">
                      You can select any past date to edit historical time entries
                    </p>
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
                          min="0.01"
                          max="24"
                          placeholder="e.g., 2.5 for 2 hours 30 minutes"
                          {...field} 
                        />
                      </FormControl>
                      <FormMessage />
                      <p className="text-xs text-muted-foreground mt-1">
                        Enter duration as decimal hours (0.01 to 24.00)
                      </p>
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
                  disabled={updateTimeEntry.isPending}
                >
                  <Save className="w-4 h-4 mr-2" />
                  {updateTimeEntry.isPending ? "Updating..." : "Update Time Entry"}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  className="flex-1"
                  onClick={onClose}
                >
                  <X className="w-4 h-4 mr-2" />
                  Cancel
                </Button>
              </div>
            </form>
          </Form>
        </div>
      </DialogContent>
    </Dialog>
  );
}