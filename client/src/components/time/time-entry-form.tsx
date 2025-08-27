import { useState } from "react";
import * as React from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import { apiRequest } from "@/lib/queryClient";
import { insertTimeEntrySchema, type Project, type Task } from "@shared/schema";
import { getActiveProjects } from "@/lib/projectUtils";
import { z } from "zod";
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
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Save, X, Clock, Timer } from "lucide-react";

// Schema for start/end time mode
const timeRangeSchema = insertTimeEntrySchema.extend({
  date: z.string().min(1, "Date is required"),
  startTime: z.string().min(1, "Start time is required"),
  endTime: z.string().min(1, "End time is required"),
  taskId: z.string().min(1, "Task is required"),
}).omit({ userId: true, duration: true });

// Schema for manual duration mode
const manualDurationSchema = insertTimeEntrySchema.extend({
  date: z.string().min(1, "Date is required"),
  taskId: z.string().min(1, "Task is required"),
  duration: z.string().min(1, "Duration is required").refine(
    (val) => {
      const num = parseFloat(val);
      return !isNaN(num) && num > 0 && num <= 24;
    },
    "Duration must be a number between 0.1 and 24 hours"
  ),
}).omit({ userId: true });

type TimeRangeFormData = z.infer<typeof timeRangeSchema>;
type ManualDurationFormData = z.infer<typeof manualDurationSchema>;

// Input mode type
type InputMode = "timeRange" | "manualDuration";

export default function TimeEntryForm() {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [inputMode, setInputMode] = useState<InputMode>("timeRange");
  const [calculatedDuration, setCalculatedDuration] = useState<string>("");

  // Get current local date (not UTC)
  const getCurrentLocalDate = () => {
    const now = new Date();
    const year = now.getFullYear();
    const month = String(now.getMonth() + 1).padStart(2, '0');
    const day = String(now.getDate()).padStart(2, '0');
    return `${year}-${month}-${day}`;
  };

  // Time range form
  const timeRangeForm = useForm<TimeRangeFormData>({
    resolver: zodResolver(timeRangeSchema),
    defaultValues: {
      projectId: "",
      taskId: "",
      description: "",
      date: getCurrentLocalDate(),
      startTime: "",
      endTime: "",
    },
  });

  // Manual duration form
  const manualDurationForm = useForm<ManualDurationFormData>({
    resolver: zodResolver(manualDurationSchema),
    defaultValues: {
      projectId: "",
      taskId: "",
      description: "",
      date: getCurrentLocalDate(),
      duration: "",
    },
  });



  // Fetch projects and filter for active ones only
  const { data: allProjects, isLoading: projectsLoading } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
  });
  
  const projects = allProjects ? getActiveProjects(allProjects) : [];

  // Watch project selection for task loading (properly watching both forms)
  const timeRangeProjectId = timeRangeForm.watch("projectId");
  const manualDurationProjectId = manualDurationForm.watch("projectId");
  const selectedProjectId = inputMode === "timeRange" ? timeRangeProjectId : manualDurationProjectId;

  // Fetch tasks for selected project
  const { data: tasks, isLoading: tasksLoading } = useQuery<Task[]>({
    queryKey: ["/api/projects", selectedProjectId, "tasks"],
    enabled: !!selectedProjectId,
  });

  // Filter only active tasks
  const activeTasks = tasks?.filter(task => task.status === "active") || [];
  
  // Debug logging
  React.useEffect(() => {
    if (selectedProjectId && tasks) {
      console.log("🔍 Tasks for project:", selectedProjectId, tasks);
      console.log("✅ Active tasks:", activeTasks);
    }
  }, [selectedProjectId, tasks, activeTasks]);

  // Debug form states
  React.useEffect(() => {
    console.log("🔧 Debug - Input Mode:", inputMode);
    console.log("🔧 Debug - Projects Loading:", projectsLoading);
    console.log("🔧 Debug - Projects Count:", projects.length);
    console.log("🔧 Debug - Selected Project ID:", selectedProjectId);
  }, [inputMode, projectsLoading, projects.length, selectedProjectId]);

  // Calculate duration when start/end times change
  const calculateDuration = (startTime: string, endTime: string) => {
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

  // Watch for time changes in time range mode
  const startTime = timeRangeForm.watch("startTime");
  const endTime = timeRangeForm.watch("endTime");

  React.useEffect(() => {
    if (inputMode === "timeRange") {
      calculateDuration(startTime, endTime);
    }
  }, [startTime, endTime, inputMode]);

  const createTimeEntry = useMutation({
    mutationFn: async (data: TimeRangeFormData | ManualDurationFormData) => {
      let entryData: {
        projectId: string;
        taskId: string;
        description?: string;
        date: string;
        duration: string;
      };

      if (inputMode === "timeRange") {
        const timeData = data as TimeRangeFormData;
        const start = new Date(`2000-01-01T${timeData.startTime}:00`);
        const end = new Date(`2000-01-01T${timeData.endTime}:00`);
        const duration = (end.getTime() - start.getTime()) / (1000 * 60 * 60);

        entryData = {
          projectId: timeData.projectId,
          taskId: timeData.taskId,
          description: timeData.description,
          date: timeData.date,
          duration: duration.toFixed(2),
        };
      } else {
        const manualData = data as ManualDurationFormData;
        entryData = {
          projectId: manualData.projectId,
          taskId: manualData.taskId,
          description: manualData.description,
          date: manualData.date,
          duration: manualData.duration,
        };
      }

      return await apiRequest("/api/time-entries", "POST", entryData);
    },
    onSuccess: () => {
      toast({
        title: "Success",
        description: "Time entry created successfully",
      });
      
      // Reset both forms
      timeRangeForm.reset({
        projectId: "",
        taskId: "",
        description: "",
        date: getCurrentLocalDate(),
        startTime: "",
        endTime: "",
      });
      
      manualDurationForm.reset({
        projectId: "",
        taskId: "",
        description: "",
        date: getCurrentLocalDate(),
        duration: "",
      });
      
      setCalculatedDuration("");
      queryClient.invalidateQueries({ queryKey: ["/api/time-entries"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/stats"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/recent-activity"] });
      queryClient.invalidateQueries({ queryKey: ["/api/dashboard/project-breakdown"] });
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
        description: "Failed to create time entry",
        variant: "destructive",
      });
    },
  });

  // Chrome time input compatibility fix
  React.useEffect(() => {
    const timeInputs = document.querySelectorAll('input[type="time"]');
    timeInputs.forEach((input: any) => {
      // Force Chrome to recognize time inputs properly
      input.addEventListener('focus', (e: any) => {
        if (e.target.type === 'time' && !e.target.value) {
          // Set a default time format for Chrome
          const now = new Date();
          const defaultTime = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}`;
          e.target.setAttribute('placeholder', defaultTime);
        }
      });
      
      // Ensure proper validation
      input.addEventListener('blur', (e: any) => {
        if (e.target.value && !/^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/.test(e.target.value)) {
          e.target.setCustomValidity('Please enter a valid time in HH:MM format');
        } else {
          e.target.setCustomValidity('');
        }
      });
    });
  }, []);

  const onSubmitTimeRange = (data: TimeRangeFormData) => {
    const start = new Date(`2000-01-01T${data.startTime}:00`);
    const end = new Date(`2000-01-01T${data.endTime}:00`);
    
    if (end <= start) {
      toast({
        title: "Invalid Time Range",
        description: "End time must be after start time",
        variant: "destructive",
      });
      return;
    }

    createTimeEntry.mutate(data);
  };

  const onSubmitManualDuration = (data: ManualDurationFormData) => {
    createTimeEntry.mutate(data);
  };

  const handleClearForm = () => {
    if (inputMode === "timeRange") {
      timeRangeForm.reset({
        projectId: "",
        taskId: "",
        description: "",
        date: getCurrentLocalDate(),
        startTime: "",
        endTime: "",
      });
    } else {
      manualDurationForm.reset({
        projectId: "",
        taskId: "",
        description: "",
        date: getCurrentLocalDate(),
        duration: "",
      });
    }
    setCalculatedDuration("");
  };

  const handleQuickEntry = (minutes: number) => {
    if (inputMode === "timeRange") {
      const now = new Date();
      const startTime = new Date(now.getTime() - minutes * 60 * 1000);
      
      timeRangeForm.setValue("startTime", startTime.toTimeString().slice(0, 5));
      timeRangeForm.setValue("endTime", now.toTimeString().slice(0, 5));
    } else {
      const hours = minutes / 60;
      manualDurationForm.setValue("duration", hours.toString());
    }
  };

  const handleModeSwitch = (newMode: InputMode) => {
    setInputMode(newMode);
    setCalculatedDuration("");
    
    // Copy common fields between forms
    const currentForm = inputMode === "timeRange" ? timeRangeForm : manualDurationForm;
    const currentData = currentForm.getValues();
    
    if (newMode === "timeRange") {
      timeRangeForm.setValue("projectId", currentData.projectId || "");
      timeRangeForm.setValue("taskId", currentData.taskId || "");
      timeRangeForm.setValue("description", currentData.description || "");
      timeRangeForm.setValue("date", currentData.date || getCurrentLocalDate());
    } else {
      manualDurationForm.setValue("projectId", currentData.projectId || "");
      manualDurationForm.setValue("taskId", currentData.taskId || "");
      manualDurationForm.setValue("description", currentData.description || "");
      manualDurationForm.setValue("date", currentData.date || getCurrentLocalDate());
    }
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
          {inputMode === "timeRange" ? (
            <Form {...timeRangeForm}>
              <form onSubmit={timeRangeForm.handleSubmit(onSubmitTimeRange)} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <FormField
                    control={timeRangeForm.control}
                    name="projectId"
                    render={({ field }) => (
                    <FormItem>
                      <FormLabel htmlFor="project-select-timerange">Project *</FormLabel>
                      <Select 
                        onValueChange={(value) => {
                          field.onChange(value);
                          // Reset task when project changes
                          timeRangeForm.setValue("taskId", "");
                        }} 
                        value={field.value || ""}
                      >
                        <FormControl>
                          <SelectTrigger id="project-select-timerange">
                            <SelectValue placeholder={projects.length === 0 ? "No active projects available" : "Select a project"} />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          {projectsLoading ? (
                            <div className="p-2 text-sm text-muted-foreground">
                              Loading projects...
                            </div>
                          ) : projects.length === 0 ? (
                            <div className="p-2 text-sm text-muted-foreground">
                              No active projects available for time entry.
                              Projects must be within their start and end date range.
                            </div>
                          ) : (
                            projects.map((project) => (
                              <SelectItem key={project.id} value={project.id}>
                                <div className="flex items-center gap-2">
                                  <div 
                                    className={`w-3 h-3 rounded-full`} 
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

                  <FormField
                    control={timeRangeForm.control}
                    name="taskId"
                    render={({ field }) => (
                    <FormItem>
                      <FormLabel>Task *</FormLabel>
                      <Select 
                        onValueChange={field.onChange} 
                        value={field.value || ""}
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
                              No tasks available for this project.
                              Please select a different project or contact your project manager to add tasks.
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

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <FormField
                    control={timeRangeForm.control}
                    name="date"
                    render={({ field }) => (
                    <FormItem>
                      <FormLabel>Date</FormLabel>
                      <FormControl>
                        <Input type="date" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                    )}
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <FormField
                    control={timeRangeForm.control}
                    name="startTime"
                    render={({ field }) => (
                    <FormItem>
                      <FormLabel>Start Time</FormLabel>
                      <FormControl>
                        <Input 
                          type="time" 
                          {...field} 
                          placeholder="09:00"
                          step="300"
                          className="time-input"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                    )}
                  />

                  <FormField
                    control={timeRangeForm.control}
                    name="endTime"
                    render={({ field }) => (
                    <FormItem>
                      <FormLabel>End Time</FormLabel>
                      <FormControl>
                        <Input 
                          type="time" 
                          {...field} 
                          placeholder="17:00"
                          step="300"
                          className="time-input"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                    )}
                  />
                </div>

                <div>
                  <FormLabel>Duration (calculated automatically)</FormLabel>
                  <Input
                    value={calculatedDuration}
                    placeholder="0.0 hours"
                    className="bg-muted"
                    readOnly
                  />
                </div>

                <FormField
                  control={timeRangeForm.control}
                  name="description"
                  render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description (optional)</FormLabel>
                    <FormControl>
                      <Textarea
                        {...field}
                        value={field.value || ""}
                        rows={4}
                        placeholder="Describe what you worked on..."
                        className="resize-none"
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                  )}
                />

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
          ) : (
            <Form {...manualDurationForm}>
              <form onSubmit={manualDurationForm.handleSubmit(onSubmitManualDuration)} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <FormField
                    control={manualDurationForm.control}
                    name="projectId"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel htmlFor={`project-select-${inputMode}`}>Project *</FormLabel>
                        <Select 
                          onValueChange={(value) => {
                            console.log("🔧 Manual Duration - Project Selected:", value);
                            field.onChange(value);
                            // Reset task when project changes
                            manualDurationForm.setValue("taskId", "");
                          }} 
                          value={field.value}
                        >
                          <FormControl>
                            <SelectTrigger id={`project-select-${inputMode}`}>
                              <SelectValue placeholder={projects.length === 0 ? "No active projects available" : "Select a project"} />
                            </SelectTrigger>
                          </FormControl>
                          <SelectContent>
                            {projectsLoading ? (
                              <div className="p-2 text-sm text-muted-foreground">
                                Loading projects...
                              </div>
                            ) : projects.length === 0 ? (
                              <div className="p-2 text-sm text-muted-foreground">
                                No active projects available for time entry.
                                Projects must be within their start and end date range.
                              </div>
                            ) : (
                              projects.map((project) => (
                                <SelectItem key={project.id} value={project.id}>
                                  <div className="flex items-center gap-2">
                                    <div 
                                      className={`w-3 h-3 rounded-full`} 
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

                  <FormField
                    control={manualDurationForm.control}
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
                                No tasks available for this project.
                                Please select a different project or contact your project manager to add tasks.
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

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <FormField
                    control={manualDurationForm.control}
                    name="date"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Date</FormLabel>
                        <FormControl>
                          <Input type="date" {...field} />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={manualDurationForm.control}
                    name="duration"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Duration (hours)</FormLabel>
                        <FormControl>
                          <Input 
                            type="number" 
                            step="0.25" 
                            min="0.1" 
                            max="24" 
                            placeholder="8.5" 
                            {...field} 
                          />
                        </FormControl>
                        <FormMessage />
                        <div className="text-xs text-muted-foreground">
                          Enter hours in decimal format (e.g., 1.5 for 1 hour 30 minutes)
                        </div>
                      </FormItem>
                    )}
                  />
                </div>

                <FormField
                  control={manualDurationForm.control}
                  name="description"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Description (optional)</FormLabel>
                      <FormControl>
                        <Textarea
                          {...field}
                          value={field.value || ""}
                          rows={4}
                          placeholder="Describe what you worked on..."
                          className="resize-none"
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />

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
          )}
        </CardContent>
      </Card>

      {/* Quick Entry Buttons */}
      <Card className="mt-6">
        <CardContent className="p-6">
          <h3 className="text-lg font-semibold text-foreground mb-4">Quick Entry</h3>
          <p className="text-sm text-muted-foreground mb-4">
            {inputMode === "timeRange" 
              ? "Quickly set start and end times based on current time" 
              : "Quickly set duration in hours"
            }
          </p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Button
              type="button"
              variant="outline"
              onClick={() => handleQuickEntry(15)}
              className="p-3 h-auto flex-col"
            >
              <div className="text-lg font-semibold">
                {inputMode === "timeRange" ? "15min" : "0.25h"}
              </div>
              <div className="text-xs text-muted-foreground">Quick task</div>
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleQuickEntry(30)}
              className="p-3 h-auto flex-col"
            >
              <div className="text-lg font-semibold">
                {inputMode === "timeRange" ? "30min" : "0.5h"}
              </div>
              <div className="text-xs text-muted-foreground">Short task</div>
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleQuickEntry(60)}
              className="p-3 h-auto flex-col"
            >
              <div className="text-lg font-semibold">
                {inputMode === "timeRange" ? "1hr" : "1h"}
              </div>
              <div className="text-xs text-muted-foreground">Standard</div>
            </Button>
            <Button
              type="button"
              variant="outline"
              onClick={() => handleQuickEntry(120)}
              className="p-3 h-auto flex-col"
            >
              <div className="text-lg font-semibold">
                {inputMode === "timeRange" ? "2hr" : "2h"}
              </div>
              <div className="text-xs text-muted-foreground">Long task</div>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}