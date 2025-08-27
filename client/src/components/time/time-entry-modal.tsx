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

const timeEntryFormSchema = insertTimeEntrySchema.extend({
  date: z.string().min(1, "Date is required"),
  startTime: z.string().min(1, "Start time is required"),
  endTime: z.string().min(1, "End time is required"),
  taskId: z.string().min(1, "Task is required"),
}).omit({ userId: true, duration: true });

type TimeEntryFormData = z.infer<typeof timeEntryFormSchema>;

interface TimeEntryModalProps {
  entry: TimeEntryWithProject;
  onClose: () => void;
  onSuccess: () => void;
}

export default function TimeEntryModal({ entry, onClose, onSuccess }: TimeEntryModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [calculatedDuration, setCalculatedDuration] = useState<string>("");

  const form = useForm<TimeEntryFormData>({
    resolver: zodResolver(timeEntryFormSchema),
    defaultValues: {
      projectId: entry.projectId,
      taskId: entry.taskId || undefined,
      description: entry.description || undefined,
      date: entry.date,
      startTime: entry.startTime,
      endTime: entry.endTime,
    },
  });

  // Fetch projects and filter for active ones only
  const { data: allProjects } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
  });
  
  const projects = allProjects ? getActiveProjects(allProjects) : [];

  // Watch project selection for task loading
  const selectedProjectId = form.watch("projectId");

  // Fetch tasks for selected project
  const { data: tasks } = useQuery<Task[]>({
    queryKey: ["/api/projects", selectedProjectId, "tasks"],
    enabled: !!selectedProjectId,
  });

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

  // Watch for time changes
  const startTime = form.watch("startTime");
  const endTime = form.watch("endTime");

  React.useEffect(() => {
    calculateDuration(startTime, endTime);
  }, [startTime, endTime]);

  const updateTimeEntry = useMutation({
    mutationFn: async (data: TimeEntryFormData) => {
      const start = new Date(`2000-01-01T${data.startTime}:00`);
      const end = new Date(`2000-01-01T${data.endTime}:00`);
      const duration = (end.getTime() - start.getTime()) / (1000 * 60 * 60);

      const entryData = {
        ...data,
        duration: duration.toFixed(2),
      };

      return await apiRequest(`/api/time-entries/${entry.id}`, "PUT", entryData);
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
        description: "Failed to update time entry",
        variant: "destructive",
      });
    },
  });

  const onSubmit = (data: TimeEntryFormData) => {
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

    updateTimeEntry.mutate(data);
  };

  return (
    <Dialog open={true} onOpenChange={onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Time Entry</DialogTitle>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <FormField
              control={form.control}
              name="projectId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Project</FormLabel>
                  <Select onValueChange={field.onChange} value={field.value}>
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {projects.length === 0 ? (
                        <div className="p-2 text-sm text-muted-foreground">
                          No active projects available for time entry.
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
              control={form.control}
              name="taskId"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Task *</FormLabel>
                  <Select 
                    onValueChange={field.onChange} 
                    value={field.value || ""}
                    disabled={!selectedProjectId}
                  >
                    <FormControl>
                      <SelectTrigger>
                        <SelectValue placeholder={selectedProjectId ? "Select a task" : "Select a project first"} />
                      </SelectTrigger>
                    </FormControl>
                    <SelectContent>
                      {tasks?.filter(task => task.status !== "archived").map((task) => (
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

            <FormField
              control={form.control}
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

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
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
                control={form.control}
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
              <FormLabel>Duration</FormLabel>
              <Input
                value={calculatedDuration}
                className="bg-gray-50"
                readOnly
              />
            </div>

            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Textarea
                      {...field}
                      value={field.value || ""}
                      rows={3}
                      className="resize-none"
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="flex space-x-3 pt-4">
              <Button
                type="submit"
                className="flex-1"
                disabled={updateTimeEntry.isPending}
              >
                {updateTimeEntry.isPending ? "Saving..." : "Save Changes"}
              </Button>
              <Button
                type="button"
                variant="outline"
                className="flex-1"
                onClick={onClose}
              >
                Cancel
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
