import type { Express } from "express";
import { createServer, type Server } from "http";
import { storage } from "./storage";
import { setupAuth, isAuthenticated } from "./replitAuth";

// Role-based permissions helper
function getRolePermissions(role: string) {
  const permissions = {
    admin: [
      'manage_users', 'manage_system', 'view_all_projects', 'manage_all_departments',
      'generate_all_reports', 'system_configuration'
    ],
    manager: [
      'manage_department', 'view_department_projects', 'manage_employees',
      'generate_department_reports', 'view_department_analytics'
    ],
    project_manager: [
      'create_projects', 'manage_projects', 'view_project_analytics',
      'generate_project_reports', 'manage_tasks', 'assign_team_members'
    ],
    employee: [
      'log_time', 'view_assigned_projects', 'view_own_reports',
      'manage_profile', 'complete_tasks'
    ],
    viewer: [
      'view_assigned_projects', 'view_own_time_entries', 'view_basic_reports'
    ]
  };
  
  return permissions[role as keyof typeof permissions] || permissions.employee;
}
// Remove unused auth imports - using isAuthenticated consistently
import { insertProjectSchema, insertTaskSchema, insertTimeEntrySchema, insertEmployeeSchema } from "@shared/schema";
import { z } from "zod";

export async function registerRoutes(app: Express): Promise<Server> {
  // Auth middleware
  await setupAuth(app);

  // Auth routes
  app.get('/api/auth/user', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      // Include role-based auth context 
      const response = {
        ...user,
        authContext: {
          role: user?.role || 'employee',
          permissions: getRolePermissions(user?.role || 'employee')
        }
      };
      
      res.json(response);
    } catch (error) {
      console.error("Error fetching user:", error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  });

  // Project routes
  app.get('/api/projects', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const projects = await storage.getProjects();
      res.json(projects);
    } catch (error) {
      console.error("Error fetching projects:", error);
      res.status(500).json({ message: "Failed to fetch projects" });
    }
  });

  app.get('/api/projects/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const project = await storage.getProject(id, userId);
      
      if (!project) {
        return res.status(404).json({ message: "Project not found" });
      }
      
      res.json(project);
    } catch (error) {
      console.error("Error fetching project:", error);
      res.status(500).json({ message: "Failed to fetch project" });
    }
  });

  app.post('/api/projects', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only project managers and admins can create projects
      if (!['admin', 'project_manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to create projects" });
      }

      const projectData = insertProjectSchema.parse({ ...req.body, userId });
      const project = await storage.createProject(projectData, userId);
      res.status(201).json(project);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid project data", errors: error.errors });
      }
      console.error("Error creating project:", error);
      res.status(500).json({ message: "Failed to create project" });
    }
  });

  app.patch('/api/projects/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      console.log("Received project update data:", req.body);
      const projectData = insertProjectSchema.partial().parse(req.body);
      const project = await storage.updateProject(id, projectData, userId);
      
      if (!project) {
        return res.status(404).json({ message: "Project not found" });
      }
      
      res.json(project);
    } catch (error) {
      if (error instanceof z.ZodError) {
        console.error("Project validation error:", error.errors);
        return res.status(400).json({ message: "Invalid project data", errors: error.errors });
      }
      if (error instanceof Error && error.message.includes('Insufficient permissions')) {
        return res.status(403).json({ message: error.message });
      }
      console.error("Error updating project:", error);
      res.status(500).json({ message: "Failed to update project" });
    }
  });

  app.put('/api/projects/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      console.log("Received project PUT update data:", req.body);
      const projectData = insertProjectSchema.partial().parse(req.body);
      const project = await storage.updateProject(id, projectData, userId);
      
      if (!project) {
        return res.status(404).json({ message: "Project not found" });
      }
      
      res.json(project);
    } catch (error) {
      if (error instanceof z.ZodError) {
        console.error("Project validation error:", error.errors);
        return res.status(400).json({ message: "Invalid project data", errors: error.errors });
      }
      console.error("Error updating project:", error);
      res.status(500).json({ message: "Failed to update project" });
    }
  });

  app.delete('/api/projects/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const deleted = await storage.deleteProject(id, userId);
      
      if (!deleted) {
        return res.status(404).json({ message: "Project not found" });
      }
      
      res.status(204).send();
    } catch (error) {
      if (error instanceof Error && error.message.includes('Insufficient permissions')) {
        return res.status(403).json({ message: error.message });
      }
      console.error("Error deleting project:", error);
      res.status(500).json({ message: "Failed to delete project" });
    }
  });

  // Project access control routes
  app.get('/api/projects/:id/employees', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only admins and project managers can view project employee assignments
      if (!['admin', 'project_manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to view project employee assignments" });
      }
      
      const { id } = req.params;
      const employees = await storage.getProjectEmployees(id, userId);
      res.json(employees);
    } catch (error) {
      console.error("Error fetching project employees:", error);
      res.status(500).json({ message: "Failed to fetch project employees" });
    }
  });

  app.post('/api/projects/:id/employees', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only admins and project managers can assign employees to projects
      if (!['admin', 'project_manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to assign employees to projects" });
      }
      
      const { id } = req.params;
      const { employeeIds } = req.body;
      
      if (!Array.isArray(employeeIds)) {
        return res.status(400).json({ message: "employeeIds must be an array" });
      }
      
      await storage.assignEmployeesToProject(id, employeeIds, userId);
      res.status(200).json({ message: "Employees assigned successfully" });
    } catch (error) {
      console.error("Error assigning employees to project:", error);
      res.status(500).json({ message: "Failed to assign employees to project" });
    }
  });

  app.delete('/api/projects/:id/employees/:employeeId', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only admins and project managers can remove employees from projects
      if (!['admin', 'project_manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to remove employees from projects" });
      }
      
      const { id, employeeId } = req.params;
      const removed = await storage.removeEmployeeFromProject(id, employeeId, userId);
      
      if (!removed) {
        return res.status(404).json({ message: "Employee assignment not found" });
      }
      
      res.status(204).send();
    } catch (error) {
      console.error("Error removing employee from project:", error);
      res.status(500).json({ message: "Failed to remove employee from project" });
    }
  });

  // Task routes
  app.get('/api/projects/:projectId/tasks', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { projectId } = req.params;
      const tasks = await storage.getTasks(projectId, userId);
      res.json(tasks);
    } catch (error) {
      console.error("Error fetching tasks:", error);
      res.status(500).json({ message: "Failed to fetch tasks" });
    }
  });

  // Get all tasks across projects for cloning (must be before /api/tasks/:id)
  app.get('/api/tasks/all', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const tasks = await storage.getAllUserTasks(userId);
      res.json(tasks);
    } catch (error) {
      console.error("Error fetching all tasks:", error);
      res.status(500).json({ message: "Failed to fetch tasks" });
    }
  });

  app.get('/api/tasks/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const task = await storage.getTask(id, userId);
      
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }
      
      res.json(task);
    } catch (error) {
      console.error("Error fetching task:", error);
      res.status(500).json({ message: "Failed to fetch task" });
    }
  });

  app.post('/api/tasks', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only project managers and admins can create tasks
      if (!['admin', 'project_manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to create tasks" });
      }

      const taskData = insertTaskSchema.parse(req.body);
      
      // Verify project exists (project access is now enterprise-wide)
      const project = await storage.getProject(taskData.projectId, userId);
      if (!project) {
        return res.status(404).json({ message: "Project not found" });
      }
      
      const task = await storage.createTask(taskData);
      res.status(201).json(task);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid task data", errors: error.errors });
      }
      console.error("Error creating task:", error);
      res.status(500).json({ message: "Failed to create task" });
    }
  });

  app.put('/api/tasks/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only project managers and admins can edit tasks
      if (!['admin', 'project_manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to edit tasks" });
      }

      const { id } = req.params;
      const taskData = insertTaskSchema.partial().parse(req.body);
      const task = await storage.updateTask(id, taskData, userId);
      
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }
      
      res.json(task);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid task data", errors: error.errors });
      }
      console.error("Error updating task:", error);
      res.status(500).json({ message: "Failed to update task" });
    }
  });

  app.delete('/api/tasks/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const deleted = await storage.deleteTask(id, userId);
      
      if (!deleted) {
        return res.status(404).json({ message: "Task not found" });
      }
      
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting task:", error);
      res.status(500).json({ message: "Failed to delete task" });
    }
  });

  // Clone task to another project
  app.post('/api/tasks/:id/clone', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const { targetProjectId } = req.body;
      
      if (!targetProjectId) {
        return res.status(400).json({ message: "Target project ID is required" });
      }
      
      // Get the original task
      const originalTask = await storage.getTask(id, userId);
      if (!originalTask) {
        return res.status(404).json({ message: "Task not found" });
      }
      
      // Verify user owns the target project
      const targetProject = await storage.getProject(targetProjectId, userId);
      if (!targetProject) {
        return res.status(403).json({ message: "Access denied to target project" });
      }
      
      // Clone the task
      const clonedTask = await storage.createTask({
        projectId: targetProjectId,
        name: originalTask.name,
        description: originalTask.description,
        status: "active", // Reset status to active for cloned tasks
      });
      
      res.status(201).json(clonedTask);
    } catch (error) {
      console.error("Error cloning task:", error);
      res.status(500).json({ message: "Failed to clone task" });
    }
  });



  // Time entry routes
  app.get('/api/time-entries', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { projectId, startDate, endDate, limit, offset } = req.query;
      
      const filters = {
        projectId: (projectId === "all" || !projectId) ? undefined : projectId as string,
        startDate: startDate as string,
        endDate: endDate as string,
        limit: limit ? parseInt(limit as string) : undefined,
        offset: offset ? parseInt(offset as string) : undefined,
      };
      
      const timeEntries = await storage.getTimeEntries(userId, filters);
      res.json(timeEntries);
    } catch (error) {
      console.error("Error fetching time entries:", error);
      res.status(500).json({ message: "Failed to fetch time entries" });
    }
  });

  app.get('/api/time-entries/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const timeEntry = await storage.getTimeEntry(id, userId);
      
      if (!timeEntry) {
        return res.status(404).json({ message: "Time entry not found" });
      }
      
      res.json(timeEntry);
    } catch (error) {
      console.error("Error fetching time entry:", error);
      res.status(500).json({ message: "Failed to fetch time entry" });
    }
  });

  app.post('/api/time-entries', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      
      console.log("📝 Time Entry Request Body:", JSON.stringify(req.body, null, 2));
      
      // Handle manual duration mode by providing default start/end times
      let processedData = { ...req.body, userId };
      if (processedData.duration && !processedData.startTime && !processedData.endTime) {
        // For manual duration, set dummy start/end times that match the duration
        processedData.startTime = "09:00";
        const durationHours = parseFloat(processedData.duration);
        const endHour = 9 + Math.floor(durationHours);
        const endMinute = Math.round((durationHours % 1) * 60);
        processedData.endTime = `${endHour.toString().padStart(2, '0')}:${endMinute.toString().padStart(2, '0')}`;
      }
      
      const entryData = insertTimeEntrySchema.parse(processedData);
      
      console.log("✅ Parsed Entry Data:", JSON.stringify(entryData, null, 2));
      
      const timeEntry = await storage.createTimeEntry(entryData);
      res.status(201).json(timeEntry);
    } catch (error) {
      if (error instanceof z.ZodError) {
        console.error("❌ Validation Error:", error.errors);
        return res.status(400).json({ message: "Invalid time entry data", errors: error.errors });
      }
      console.error("Error creating time entry:", error);
      res.status(500).json({ message: "Failed to create time entry" });
    }
  });

  app.put('/api/time-entries/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      // Handle partial updates for time entries
      const partialSchema = insertTimeEntrySchema.deepPartial();
      const entryData = partialSchema.parse(req.body);
      const timeEntry = await storage.updateTimeEntry(id, entryData, userId);
      
      if (!timeEntry) {
        return res.status(404).json({ message: "Time entry not found" });
      }
      
      res.json(timeEntry);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid time entry data", errors: error.errors });
      }
      console.error("Error updating time entry:", error);
      res.status(500).json({ message: "Failed to update time entry" });
    }
  });

  app.delete('/api/time-entries/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const deleted = await storage.deleteTimeEntry(id, userId);
      
      if (!deleted) {
        return res.status(404).json({ message: "Time entry not found" });
      }
      
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting time entry:", error);
      res.status(500).json({ message: "Failed to delete time entry" });
    }
  });

  // Dashboard routes - require authentication
  app.get('/api/dashboard/stats', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { startDate, endDate } = req.query;
      const stats = await storage.getDashboardStats(
        userId,
        startDate as string,
        endDate as string
      );
      res.json(stats);
    } catch (error) {
      console.error("Error fetching dashboard stats:", error);
      res.status(500).json({ message: "Failed to fetch dashboard stats" });
    }
  });

  app.get('/api/dashboard/project-breakdown', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { startDate, endDate } = req.query;
      const breakdown = await storage.getProjectTimeBreakdown(
        userId,
        startDate as string,
        endDate as string
      );
      res.json(breakdown);
    } catch (error) {
      console.error("Error fetching project breakdown:", error);
      res.status(500).json({ message: "Failed to fetch project breakdown" });
    }
  });

  app.get('/api/dashboard/recent-activity', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { limit, startDate, endDate } = req.query;
      const activity = await storage.getRecentActivity(
        userId,
        limit ? parseInt(limit as string) : undefined,
        startDate as string,
        endDate as string
      );
      res.json(activity);
    } catch (error) {
      console.error("Error fetching recent activity:", error);
      res.status(500).json({ message: "Failed to fetch recent activity" });
    }
  });



  app.get('/api/dashboard/department-hours', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { startDate, endDate } = req.query;
      console.log("🏢 Fetching department hours for user:", userId, "dates:", startDate, endDate);
      const departmentHours = await storage.getDepartmentHoursSummary(userId, startDate as string, endDate as string);
      console.log("📊 Department hours result:", JSON.stringify(departmentHours, null, 2));
      res.json(departmentHours);
    } catch (error) {
      console.error("❌ Error fetching department hours:", error);
      res.status(500).json({ message: "Failed to fetch department hours" });
    }
  });



  // User role management routes
  app.get('/api/users/current-role', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      res.json({ 
        role: user?.role || 'employee',
        permissions: getRolePermissions(user?.role || 'employee')
      });
    } catch (error) {
      console.error("Error fetching user role:", error);
      res.status(500).json({ message: "Failed to fetch user role" });
    }
  });

  app.post('/api/users/change-role', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { role } = req.body;
      
      const validRoles = ['admin', 'manager', 'project_manager', 'employee', 'viewer'];
      if (!validRoles.includes(role)) {
        return res.status(400).json({ message: "Invalid role" });
      }

      await storage.updateUserRole(userId, role);
      res.json({ message: "Role updated successfully", role });
    } catch (error) {
      console.error("Error changing user role:", error);
      res.status(500).json({ message: "Failed to change user role" });
    }
  });

  // Admin role testing - allows temporary role switching for testing purposes
  app.post('/api/admin/test-role', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { testRole } = req.body;
      const currentUser = await storage.getUser(userId);
      
      // Only allow admin users to use role testing
      if (!currentUser || currentUser.role !== 'admin') {
        return res.status(403).json({ message: "Only administrators can use role testing" });
      }
      
      const validRoles = ['admin', 'manager', 'project_manager', 'employee', 'viewer'];
      if (!validRoles.includes(testRole)) {
        return res.status(400).json({ message: "Invalid test role" });
      }

      // Store original role in session for restoration
      req.session.originalRole = currentUser.role;
      req.session.testingRole = true;
      
      // Temporarily change role for testing
      await storage.updateUserRole(userId, testRole);
      
      console.log(`🧪 [ROLE-TEST] Admin ${currentUser.email} testing role: ${testRole} (original: ${req.session.originalRole})`);
      
      res.json({ 
        message: `Now testing as ${testRole}. Use restore-admin-role to return to admin.`,
        testRole,
        originalRole: req.session.originalRole,
        testing: true
      });
    } catch (error) {
      console.error("Error changing to test role:", error);
      res.status(500).json({ message: "Failed to change to test role" });
    }
  });

  // Restore admin role after testing
  app.post('/api/admin/restore-role', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const currentUser = await storage.getUser(userId);
      
      if (!req.session.originalRole || !req.session.testingRole) {
        return res.status(400).json({ message: "No role testing session found" });
      }
      
      // Restore original admin role
      await storage.updateUserRole(userId, req.session.originalRole);
      
      console.log(`🧪 [ROLE-TEST] Restored ${currentUser?.email} to original role: ${req.session.originalRole}`);
      
      // Clear testing session data
      const originalRole = req.session.originalRole;
      delete req.session.originalRole;
      delete req.session.testingRole;
      
      res.json({ 
        message: `Role restored to ${originalRole}`,
        role: originalRole,
        testing: false
      });
    } catch (error) {
      console.error("Error restoring admin role:", error);
      res.status(500).json({ message: "Failed to restore admin role" });
    }
  });

  // Get current testing status
  app.get('/api/admin/test-status', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const currentUser = await storage.getUser(userId);
      
      res.json({
        currentRole: currentUser?.role || 'employee',
        originalRole: req.session.originalRole || null,
        testing: !!req.session.testingRole,
        canTest: currentUser?.role === 'admin' || !!req.session.originalRole
      });
    } catch (error) {
      console.error("Error getting test status:", error);
      res.status(500).json({ message: "Failed to get test status" });
    }
  });

  app.post('/api/admin/create-test-users', isAuthenticated, async (req: any, res) => {
    try {
      const currentUserId = req.user.claims.sub;
      const currentUser = await storage.getUser(currentUserId);
      
      // Only admin or manager can create test users
      if (!currentUser || !['admin', 'manager'].includes(currentUser.role || 'employee')) {
        return res.status(403).json({ message: "Insufficient permissions" });
      }

      const testUsers = await storage.createTestUsers();
      res.json({ message: "Test users created successfully", users: testUsers });
    } catch (error) {
      console.error("Error creating test users:", error);
      res.status(500).json({ message: "Failed to create test users" });
    }
  });

  app.get('/api/admin/test-users', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      if (!user || !['admin', 'manager'].includes(user.role || 'employee')) {
        return res.status(403).json({ message: "Insufficient permissions" });
      }

      const testUsers = await storage.getTestUsers();
      res.json(testUsers);
    } catch (error) {
      console.error("Error fetching test users:", error);
      res.status(500).json({ message: "Failed to fetch test users" });
    }
  });

  // Reports routes
  app.get('/api/reports/project-time-entries/:projectId', isAuthenticated, async (req: any, res) => {
    try {
      const { projectId } = req.params;
      const userId = req.user.claims.sub;
      
      if (!userId) {
        return res.status(401).json({ message: "User not authenticated" });
      }
      
      const currentUser = await storage.getUser(userId);
      
      // Check if user has permission to view reports
      const allowedRoles = ['project_manager', 'admin', 'manager'];
      if (!currentUser || !allowedRoles.includes(currentUser.role || 'employee')) {
        return res.status(403).json({ message: "Insufficient permissions to view reports" });
      }
      
      // Get time entries for the project with employee information
      const timeEntries = await storage.getTimeEntriesForProject(projectId);
      
      res.json(timeEntries);
    } catch (error) {
      console.error("Error fetching project time entries:", error);
      res.status(500).json({ message: "Failed to fetch project time entries" });
    }
  });

  // Employee routes
  app.get('/api/employees', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const employees = await storage.getEmployees(userId);
      res.json(employees);
    } catch (error) {
      console.error("Error fetching employees:", error);
      res.status(500).json({ message: "Failed to fetch employees" });
    }
  });

  app.get('/api/employees/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const { id } = req.params;
      const employee = await storage.getEmployee(id, userId);
      
      if (!employee) {
        return res.status(404).json({ message: "Employee not found" });
      }
      
      res.json(employee);
    } catch (error) {
      console.error("Error fetching employee:", error);
      res.status(500).json({ message: "Failed to fetch employee" });
    }
  });

  app.post('/api/employees', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only admins and department managers can create employees
      if (!['admin', 'manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to create employees" });
      }

      const employeeData = insertEmployeeSchema.parse({ ...req.body, userId });
      
      const employee = await storage.createEmployee(employeeData);
      res.status(201).json(employee);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid employee data", errors: error.errors });
      }
      console.error("Error creating employee:", error);
      res.status(500).json({ message: "Failed to create employee" });
    }
  });

  app.put('/api/employees/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only admins and department managers can update employees
      if (!['admin', 'manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to update employees" });
      }

      const { id } = req.params;
      const employeeData = insertEmployeeSchema.partial().parse(req.body);
      const employee = await storage.updateEmployee(id, employeeData, userId);
      
      if (!employee) {
        return res.status(404).json({ message: "Employee not found" });
      }
      
      res.json(employee);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return res.status(400).json({ message: "Invalid employee data", errors: error.errors });
      }
      console.error("Error updating employee:", error);
      res.status(500).json({ message: "Failed to update employee" });
    }
  });

  app.delete('/api/employees/:id', isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only admins and department managers can delete employees
      if (!['admin', 'manager'].includes(userRole)) {
        return res.status(403).json({ message: "Insufficient permissions to delete employees" });
      }

      const { id } = req.params;
      const deleted = await storage.deleteEmployee(id, userId);
      
      if (!deleted) {
        return res.status(404).json({ message: "Employee not found" });
      }
      
      res.status(204).send();
    } catch (error) {
      console.error("Error deleting employee:", error);
      res.status(500).json({ message: "Failed to delete employee" });
    }
  });

  // Department routes
  app.get("/api/departments", isAuthenticated, async (req: any, res) => {
    try {
      const departments = await storage.getDepartments();
      console.log(`📋 Departments API: Found ${departments.length} departments`);
      res.json(departments);
    } catch (error) {
      console.error("❌ Error fetching departments:", error);
      res.status(500).json({ message: "Failed to fetch departments" });
    }
  });

  app.get("/api/departments/:id", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const department = await storage.getDepartment(id);
      
      if (!department) {
        return res.status(404).json({ message: "Department not found" });
      }
      
      res.json(department);
    } catch (error) {
      console.error("Error fetching department:", error);
      res.status(500).json({ message: "Failed to fetch department" });
    }
  });

  app.post("/api/departments", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only system administrators can create departments
      if (userRole !== 'admin') {
        return res.status(403).json({ message: "Insufficient permissions to create departments" });
      }
      
      const departmentData = { ...req.body, userId };
      
      const department = await storage.createDepartment(departmentData);
      res.status(201).json(department);
    } catch (error) {
      console.error("Error creating department:", error);
      res.status(500).json({ message: "Failed to create department" });
    }
  });

  app.put("/api/departments/:id", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only system administrators can update departments
      if (userRole !== 'admin') {
        return res.status(403).json({ message: "Insufficient permissions to update departments" });
      }
      
      const department = await storage.updateDepartment(id, req.body, userId);
      
      if (!department) {
        return res.status(404).json({ message: "Department not found" });
      }
      
      res.json(department);
    } catch (error) {
      console.error("Error updating department:", error);
      res.status(500).json({ message: "Failed to update department" });
    }
  });

  app.delete("/api/departments/:id", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only system administrators can delete departments
      if (userRole !== 'admin') {
        return res.status(403).json({ message: "Insufficient permissions to delete departments" });
      }
      
      const success = await storage.deleteDepartment(id, userId);
      
      if (!success) {
        return res.status(404).json({ message: "Department not found" });
      }
      
      res.json({ message: "Department deleted successfully" });
    } catch (error) {
      console.error("Error deleting department:", error);
      res.status(500).json({ message: "Failed to delete department" });
    }
  });

  app.post("/api/departments/:id/manager", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const { managerId } = req.body;
      const userId = req.user.claims.sub;
      
      await storage.assignManagerToDepartment(id, managerId, userId);
      res.json({ message: "Manager assigned successfully" });
    } catch (error) {
      console.error("Error assigning manager:", error);
      res.status(500).json({ message: "Failed to assign manager" });
    }
  });

  // User Management routes (Admin only)
  app.get("/api/admin/users", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      if (user?.role !== 'admin') {
        return res.status(403).json({ message: "Only System Administrators can view all users" });
      }
      
      const users = await storage.getAllUsers();
      res.json(users);
    } catch (error) {
      console.error("Error fetching users:", error);
      res.status(500).json({ message: "Failed to fetch users" });
    }
  });

  app.get("/api/admin/users/without-employee", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      if (user?.role !== 'admin') {
        return res.status(403).json({ message: "Only System Administrators can view unlinked users" });
      }
      
      const users = await storage.getUsersWithoutEmployeeProfile();
      res.json(users);
    } catch (error) {
      console.error("Error fetching unlinked users:", error);
      res.status(500).json({ message: "Failed to fetch unlinked users" });
    }
  });

  app.post("/api/admin/employees/:employeeId/link-user", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      
      if (user?.role !== 'admin') {
        return res.status(403).json({ message: "Only System Administrators can link users to employees" });
      }
      
      const { employeeId } = req.params;
      const { userId: targetUserId } = req.body;
      
      const linkedEmployee = await storage.linkUserToEmployee(targetUserId, employeeId);
      
      if (!linkedEmployee) {
        return res.status(404).json({ message: "Employee not found" });
      }
      
      res.json({ message: "User successfully linked to employee", employee: linkedEmployee });
    } catch (error) {
      console.error("Error linking user to employee:", error);
      res.status(500).json({ message: "Failed to link user to employee" });
    }
  });

  // Admin: Update user role
  app.post("/api/admin/users/:userId/role", isAuthenticated, async (req: any, res) => {
    try {
      console.log("👤 Role update request - User:", req.user?.claims?.sub);
      console.log("🎯 Target user ID:", req.params.userId);
      console.log("🔄 New role:", req.body.role);
      
      const currentUserId = req.user.claims.sub;
      console.log("🔍 Fetching current user...");
      const currentUser = await storage.getUser(currentUserId);
      console.log("📋 Current user role:", currentUser?.role);
      
      if (currentUser?.role !== 'admin') {
        console.log("❌ Access denied - user is not admin");
        return res.status(403).json({ message: "Only System Administrators can change user roles" });
      }
      
      const { userId: targetUserId } = req.params;
      const { role } = req.body;
      
      if (!role) {
        console.log("❌ No role provided in request body");
        return res.status(400).json({ message: "Role is required" });
      }
      
      const validRoles = ['admin', 'manager', 'project_manager', 'employee', 'viewer'];
      if (!validRoles.includes(role)) {
        console.log("❌ Invalid role:", role);
        return res.status(400).json({ message: `Invalid role specified. Valid roles: ${validRoles.join(', ')}` });
      }

      // Prevent users from removing their own admin role
      if (currentUserId === targetUserId && role !== 'admin') {
        console.log("❌ User trying to remove their own admin privileges");
        return res.status(400).json({ message: "Cannot remove your own admin privileges" });
      }
      
      console.log("🔄 Updating user role in database...");
      const updatedUser = await storage.updateUserRole(targetUserId, role);
      console.log("✅ Role update result:", !!updatedUser);
      
      if (!updatedUser) {
        console.log("❌ User not found for ID:", targetUserId);
        return res.status(404).json({ message: "User not found" });
      }
      
      console.log("✅ Role updated successfully");
      res.json({ message: "User role updated successfully", user: updatedUser });
    } catch (error) {
      console.error("💥 Error updating user role:", error);
      console.error("Error details:", {
        message: (error as Error).message,
        stack: (error as Error).stack,
        name: (error as Error).name
      });
      res.status(500).json({ 
        message: "Failed to update user role",
        error: process.env.NODE_ENV === 'production' ? 'Internal server error' : (error as Error).message
      });
    }
  });

  // Organization routes
  app.get("/api/organizations", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const organizations = await storage.getOrganizations();
      res.json(organizations);
    } catch (error) {
      console.error("Error fetching organizations:", error);
      res.status(500).json({ message: "Failed to fetch organizations" });
    }
  });

  app.get("/api/organizations/:id", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const organization = await storage.getOrganization(id);
      
      if (!organization) {
        return res.status(404).json({ message: "Organization not found" });
      }
      
      res.json(organization);
    } catch (error) {
      console.error("Error fetching organization:", error);
      res.status(500).json({ message: "Failed to fetch organization" });
    }
  });

  app.post("/api/organizations", isAuthenticated, async (req: any, res) => {
    try {
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only system administrators can create organizations
      if (userRole !== 'admin') {
        return res.status(403).json({ message: "Insufficient permissions to create organizations" });
      }
      
      const organizationData = { ...req.body, userId };
      
      const organization = await storage.createOrganization(organizationData);
      res.status(201).json(organization);
    } catch (error) {
      console.error("Error creating organization:", error);
      res.status(500).json({ message: "Failed to create organization" });
    }
  });

  app.put("/api/organizations/:id", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only system administrators can update organizations
      if (userRole !== 'admin') {
        return res.status(403).json({ message: "Insufficient permissions to update organizations" });
      }
      
      const organization = await storage.updateOrganization(id, req.body, userId);
      
      if (!organization) {
        return res.status(404).json({ message: "Organization not found" });
      }
      
      res.json(organization);
    } catch (error) {
      console.error("Error updating organization:", error);
      res.status(500).json({ message: "Failed to update organization" });
    }
  });

  app.delete("/api/organizations/:id", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const userId = req.user.claims.sub;
      const user = await storage.getUser(userId);
      const userRole = user?.role || 'employee';
      
      // Only system administrators can delete organizations
      if (userRole !== 'admin') {
        return res.status(403).json({ message: "Insufficient permissions to delete organizations" });
      }
      
      const success = await storage.deleteOrganization(id, userId);
      
      if (!success) {
        return res.status(404).json({ message: "Organization not found" });
      }
      
      res.json({ message: "Organization deleted successfully" });
    } catch (error) {
      console.error("Error deleting organization:", error);
      res.status(500).json({ message: "Failed to delete organization" });
    }
  });

  app.get("/api/organizations/:id/departments", isAuthenticated, async (req: any, res) => {
    try {
      const { id } = req.params;
      const departments = await storage.getDepartmentsByOrganization(id);
      res.json(departments);
    } catch (error) {
      console.error("Error fetching organization departments:", error);
      res.status(500).json({ message: "Failed to fetch organization departments" });
    }
  });

  // Frontend error logging endpoint
  app.post('/api/log/frontend-error', async (req, res) => {
    try {
      const { timestamp, level, category, message, data, url, userAgent } = req.body;
      
      // Enhanced frontend error logging to server console
      const logMessage = `${timestamp} 🔴 [FRONTEND-${category}] ${message}`;
      console.log(logMessage, {
        data,
        url,
        userAgent,
        ip: req.ip,
        sessionId: req.sessionID
      });
      
      res.json({ success: true });
    } catch (error) {
      console.error('Failed to log frontend error:', error);
      res.status(500).json({ message: 'Logging failed' });
    }
  });

  // Health check endpoint
  app.get('/api/health', (req, res) => {
    res.status(200).json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    });
  });

  const httpServer = createServer(app);
  return httpServer;
}
