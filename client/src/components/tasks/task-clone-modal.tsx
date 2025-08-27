import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import { isUnauthorizedError } from "@/lib/authUtils";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Copy, Search, CheckSquare, Square } from "lucide-react";
import { Input } from "@/components/ui/input";
import type { Project, Task, TaskWithProject } from "@shared/schema";

interface TaskCloneModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: () => void;
  targetProjectId?: string;
}

const cloneFormSchema = z.object({
  taskIds: z.array(z.string()).min(1, "Please select at least one task to clone"),
  targetProjectId: z.string().min(1, "Please select a target project"),
});

type CloneFormData = z.infer<typeof cloneFormSchema>;

export default function TaskCloneModal({ isOpen, onClose, onSuccess, targetProjectId }: TaskCloneModalProps) {
  const { toast } = useToast();
  const queryClient = useQueryClient();
  const [searchTerm, setSearchTerm] = useState("");

  const form = useForm<CloneFormData>({
    resolver: zodResolver(cloneFormSchema),
    defaultValues: {
      taskIds: [],
      targetProjectId: targetProjectId || "",
    },
  });

  // Fetch all projects
  const { data: projects } = useQuery<Project[]>({
    queryKey: ["/api/projects"],
    enabled: isOpen,
  });

  // Fetch all tasks for cloning
  const { data: tasks, isLoading: tasksLoading } = useQuery<TaskWithProject[]>({
    queryKey: ["/api/tasks/all"],
    enabled: isOpen,
  });

  // Fetch target project tasks to filter out duplicates
  const targetProject = form.watch("targetProjectId");
  const { data: targetProjectTasks } = useQuery<Task[]>({
    queryKey: ["/api/projects", targetProject, "tasks"],
    enabled: isOpen && !!targetProject,
  });

  // Create a set of existing task names in the target project for fast lookup
  const existingTaskNames = new Set(
    targetProjectTasks?.map(task => task.name.toLowerCase()) || []
  );

  // Remove duplicate tasks based on task name to show only distinct task names
  const uniqueTasks = tasks?.reduce<TaskWithProject[]>((acc, task) => {
    const taskName = task.name.trim().toUpperCase();
    
    // Check if this exact task name already exists in our unique list
    const isDuplicateName = acc.some(existing => {
      const existingName = existing.name.trim().toUpperCase();
      return existingName === taskName;
    });
    
    if (!isDuplicateName) {
      acc.push(task);
    }
    
    return acc;
  }, []) || [];

  // Filter unique tasks based on search term and exclude duplicates by name
  const filteredTasks = uniqueTasks.filter(task => {
    const matchesSearch = task.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      task.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      task.project.name.toLowerCase().includes(searchTerm.toLowerCase());
    
    const isDuplicate = existingTaskNames.has(task.name.toLowerCase());
    const isFromTargetProject = task.projectId === targetProject;
    
    return matchesSearch && !isDuplicate && !isFromTargetProject;
  });

  // Count filtered out duplicates for user feedback
  const duplicatesCount = uniqueTasks.filter(task => {
    const matchesSearch = task.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      task.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      task.project.name.toLowerCase().includes(searchTerm.toLowerCase());
    
    const isDuplicate = existingTaskNames.has(task.name.toLowerCase());
    const isFromTargetProject = task.projectId === targetProject;
    
    return matchesSearch && (isDuplicate || isFromTargetProject);
  }).length;

  // Clone tasks mutation
  const cloneTasks = useMutation({
    mutationFn: async (data: CloneFormData) => {
      // Clone all selected tasks
      const clonePromises = data.taskIds.map(taskId => 
        apiRequest(`/api/tasks/${taskId}/clone`, "POST", {
          targetProjectId: data.targetProjectId,
        })
      );
      await Promise.all(clonePromises);
    },
    onSuccess: () => {
      const taskCount = form.getValues("taskIds").length;
      toast({
        title: "Success",
        description: `${taskCount} task${taskCount > 1 ? 's' : ''} cloned successfully`,
      });
      queryClient.invalidateQueries({ queryKey: ["/api/projects"] });
      form.reset();
      onSuccess();
      onClose();
    },
    onError: (error) => {
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
        description: "Failed to clone tasks",
        variant: "destructive",
      });
    },
  });

  const handleSubmit = (data: CloneFormData) => {
    cloneTasks.mutate(data);
  };

  const toggleTaskSelection = (taskId: string) => {
    const currentSelection = form.getValues("taskIds");
    const newSelection = currentSelection.includes(taskId)
      ? currentSelection.filter(id => id !== taskId)
      : [...currentSelection, taskId];
    form.setValue("taskIds", newSelection);
  };

  const selectAllVisible = () => {
    const allVisibleTaskIds = filteredTasks.map(task => task.id);
    form.setValue("taskIds", allVisibleTaskIds);
  };

  const clearSelection = () => {
    form.setValue("taskIds", []);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "bg-green-100 text-green-700";
      case "archived":
        return "bg-gray-100 text-gray-700";
      default:
        return "bg-blue-100 text-blue-700";
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Copy className="h-5 w-5" />
            Clone Tasks to Project
          </DialogTitle>
          <DialogDescription>
            Select tasks to clone and choose the target project. Duplicate task names are automatically filtered out.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(handleSubmit)} className="flex flex-col flex-1 overflow-hidden">
            <div className="space-y-4 flex-1 overflow-hidden flex flex-col">
              {/* Target Project Selection */}
              <FormField
                control={form.control}
                name="targetProjectId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Target Project</FormLabel>
                    <Select onValueChange={field.onChange} value={field.value}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Select target project" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {projects?.map((project) => (
                          <SelectItem key={project.id} value={project.id}>
                            {project.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {/* Task Search */}
              <div className="space-y-2">
                <FormLabel>Search Tasks</FormLabel>
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search by task name, description, or project..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="pl-10"
                  />
                </div>
              </div>

              {/* Selection Controls */}
              <div className="flex items-center justify-between">
                <div className="flex flex-col">
                  <FormLabel>Select Tasks to Clone</FormLabel>
                  {targetProject && duplicatesCount > 0 && (
                    <p className="text-xs text-muted-foreground mt-1">
                      {duplicatesCount} duplicate{duplicatesCount > 1 ? 's' : ''} filtered out
                    </p>
                  )}
                </div>
                <div className="flex gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={selectAllVisible}
                    disabled={filteredTasks.length === 0}
                  >
                    Select All Visible ({filteredTasks.length})
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    onClick={clearSelection}
                    disabled={form.watch("taskIds").length === 0}
                  >
                    Clear ({form.watch("taskIds").length})
                  </Button>
                </div>
              </div>

              {/* Task Selection */}
              <FormField
                control={form.control}
                name="taskIds"
                render={({ field }) => (
                  <FormItem className="flex-1 overflow-hidden flex flex-col">
                    <div className="flex-1 overflow-y-auto space-y-2 border rounded-md p-2">
                      {tasksLoading ? (
                        <div className="flex items-center justify-center p-4">
                          <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
                        </div>
                      ) : filteredTasks.length === 0 ? (
                        <div className="text-center p-4 text-muted-foreground">
                          {searchTerm 
                            ? "No unique tasks found matching your search" 
                            : targetProject 
                              ? "No unique tasks available to clone (duplicates filtered out)"
                              : "No tasks available to clone"
                          }
                        </div>
                      ) : (
                        filteredTasks.map((task) => {
                          const isSelected = field.value.includes(task.id);
                          return (
                            <Card
                              key={task.id}
                              className={`cursor-pointer transition-colors hover:bg-accent ${
                                isSelected ? "ring-2 ring-primary bg-accent" : ""
                              }`}
                              onClick={() => toggleTaskSelection(task.id)}
                            >
                              <CardContent className="p-3">
                                <div className="flex items-start gap-3">
                                  <div className="flex-shrink-0 mt-0.5">
                                    {isSelected ? (
                                      <CheckSquare className="h-5 w-5 text-primary" />
                                    ) : (
                                      <Square className="h-5 w-5 text-muted-foreground" />
                                    )}
                                  </div>
                                  <div className="flex-1">
                                    <div className="flex items-center gap-2 mb-1">
                                      <h4 className="font-medium text-sm">{task.name}</h4>
                                      <Badge className={getStatusColor(task.status)} variant="secondary">
                                        {task.status}
                                      </Badge>
                                    </div>
                                    {task.description && (
                                      <p className="text-xs text-muted-foreground mb-2 line-clamp-2">
                                        {task.description}
                                      </p>
                                    )}
                                    <div className="flex items-center gap-2">
                                      <div
                                        className="w-3 h-3 rounded-full"
                                        style={{ backgroundColor: task.project.color || '#1976D2' }}
                                      />
                                      <span className="text-xs text-muted-foreground">
                                        {task.project.name}
                                      </span>
                                    </div>
                                  </div>
                                </div>
                              </CardContent>
                            </Card>
                          );
                        })
                      )}
                    </div>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <DialogFooter className="mt-4">
              <Button
                type="button"
                variant="outline"
                onClick={onClose}
                disabled={cloneTasks.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={cloneTasks.isPending || form.watch("taskIds").length === 0}>
                {cloneTasks.isPending 
                  ? "Cloning..." 
                  : `Clone ${form.watch("taskIds").length} Task${form.watch("taskIds").length === 1 ? '' : 's'}`
                }
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}