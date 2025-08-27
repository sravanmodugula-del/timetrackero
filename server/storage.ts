import {
  users,
  projects,
  tasks,
  timeEntries,
  employees,
  projectEmployees,
  departments,
  organizations,
  type User,
  type UpsertUser,
  type InsertProject,
  type Project,
  type InsertTask,
  type Task,
  type InsertTimeEntry,
  type TimeEntry,
  type TimeEntryWithProject,
  type ProjectWithTimeEntries,
  type TaskWithProject,
  type InsertEmployee,
  type Employee,
  type InsertProjectEmployee,
  type ProjectEmployee,
  type ProjectWithEmployees,
  type Department,
  type InsertDepartment,
  type DepartmentWithManager,
  type Organization,
  type InsertOrganization,
  type OrganizationWithDepartments,
} from "@shared/schema";
import { db, withDatabaseRetry } from "./db";
import { eq, and, or, desc, asc, gte, lte, sql, notInArray } from "drizzle-orm";

// Enhanced logging utility
function storageLog(operation: string, message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logMessage = `${timestamp} 🗄️ [STORAGE] ${operation}: ${message}`;
  
  if (data) {
    console.log(logMessage, typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
  } else {
    console.log(logMessage);
  }
}

// Interface for storage operations
export interface IStorage {
  // User operations
  // (IMPORTANT) these user operations are mandatory for Replit Auth.
  getUser(id: string): Promise<User | undefined>;
  upsertUser(user: UpsertUser): Promise<User>;
  getAllUsers(): Promise<User[]>;
  getUsersWithoutEmployeeProfile(): Promise<User[]>;
  
  // Project operations
  getProjects(): Promise<Project[]>;
  getEmployeeProjects(userId: string): Promise<Project[]>;
  getProject(id: string, userId: string): Promise<Project | undefined>;
  createProject(project: InsertProject, userId?: string): Promise<Project>;
  updateProject(id: string, project: Partial<InsertProject>, userId: string): Promise<Project | undefined>;
  deleteProject(id: string, userId: string): Promise<boolean>;
  
  // Task operations
  getTasks(projectId: string, userId: string): Promise<Task[]>;
  getTask(id: string, userId: string): Promise<Task | undefined>;
  getAllUserTasks(userId: string): Promise<TaskWithProject[]>;
  createTask(task: InsertTask): Promise<Task>;
  updateTask(id: string, task: Partial<InsertTask>, userId: string): Promise<Task | undefined>;
  deleteTask(id: string, userId: string): Promise<boolean>;
  
  // Time entry operations
  getTimeEntries(userId: string, filters?: {
    projectId?: string;
    taskId?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
    offset?: number;
  }): Promise<TimeEntryWithProject[]>;
  getTimeEntry(id: string, userId: string): Promise<TimeEntryWithProject | undefined>;
  createTimeEntry(entry: InsertTimeEntry): Promise<TimeEntry>;
  updateTimeEntry(id: string, entry: Partial<InsertTimeEntry>, userId: string): Promise<TimeEntry | undefined>;
  deleteTimeEntry(id: string, userId: string): Promise<boolean>;
  
  // Reports operations
  getTimeEntriesForProject(projectId: string): Promise<any[]>;
  
  // Dashboard stats
  getDashboardStats(userId: string, startDate?: string, endDate?: string): Promise<{
    todayHours: number;
    weekHours: number;
    monthHours: number;
    activeProjects: number;
  }>;
  
  getProjectTimeBreakdown(userId: string, startDate?: string, endDate?: string): Promise<Array<{
    project: Project;
    totalHours: number;
    percentage: number;
  }>>;
  
  getRecentActivity(userId: string, limit?: number, startDate?: string, endDate?: string): Promise<TimeEntryWithProject[]>;
  
  getProjectTaskBreakdown(userId: string, startDate?: string, endDate?: string): Promise<Array<{
    project: Project;
    tasks: Array<{
      task: Task | null;
      totalHours: number;
    }>;
    totalHours: number;
  }>>;
  
  getDepartmentHoursSummary(userId: string, startDate?: string, endDate?: string): Promise<Array<{
    departmentId: string;
    departmentName: string;
    totalHours: number;
    employeeCount: number;
  }>>;
  
  // Employee operations
  getEmployees(userId: string): Promise<Employee[]>;
  getEmployee(id: string, userId: string): Promise<Employee | undefined>;
  createEmployee(employee: InsertEmployee): Promise<Employee>;
  updateEmployee(id: string, employee: Partial<InsertEmployee>, userId: string): Promise<Employee | undefined>;
  deleteEmployee(id: string, userId: string): Promise<boolean>;
  linkUserToEmployee(userId: string, employeeId: string): Promise<Employee | undefined>;
  
  // Project access control operations
  getProjectWithEmployees(id: string, userId: string): Promise<ProjectWithEmployees | undefined>;
  assignEmployeesToProject(projectId: string, employeeIds: string[], userId: string): Promise<void>;
  getProjectEmployees(projectId: string, userId: string): Promise<Employee[]>;
  removeEmployeeFromProject(projectId: string, employeeId: string, userId: string): Promise<boolean>;
  
  // Organization operations
  getOrganizations(): Promise<Organization[]>;
  getOrganization(id: string): Promise<OrganizationWithDepartments | undefined>;
  createOrganization(organization: InsertOrganization): Promise<Organization>;
  updateOrganization(id: string, organization: Partial<InsertOrganization>, userId: string): Promise<Organization | undefined>;
  deleteOrganization(id: string, userId: string): Promise<boolean>;

  // Department operations
  getDepartments(): Promise<DepartmentWithManager[]>;
  getDepartmentsByOrganization(organizationId: string): Promise<DepartmentWithManager[]>;
  getDepartment(id: string): Promise<DepartmentWithManager | undefined>;
  createDepartment(department: InsertDepartment): Promise<Department>;
  updateDepartment(id: string, department: Partial<InsertDepartment>, userId: string): Promise<Department | undefined>;
  deleteDepartment(id: string, userId: string): Promise<boolean>;
  assignManagerToDepartment(departmentId: string, managerId: string | null, userId: string): Promise<void>;

  // Role management operations
  updateUserRole(userId: string, role: string): Promise<User>;
  createTestUsers(): Promise<User[]>;
  getTestUsers(): Promise<User[]>;
}

export class DatabaseStorage implements IStorage {
  // User operations
  // (IMPORTANT) these user operations are mandatory for Replit Auth.

  async getUser(id: string): Promise<User | undefined> {
    try {
      storageLog('GET_USER', `Fetching user with id: ${id}`);
      const [user] = await db.select().from(users).where(eq(users.id, id));
      storageLog('GET_USER', `Found user: ${user ? user.email : 'not found'}`);
      return user;
    } catch (error) {
      storageLog('GET_USER', `Error fetching user ${id}:`, error);
      throw error;
    }
  }

  async upsertUser(userData: UpsertUser): Promise<User> {
    try {
      storageLog('UPSERT_USER', `Upserting user: ${userData.email} (${userData.id})`);
      const [user] = await db
        .insert(users)
        .values({
          ...userData,
          lastLoginAt: new Date(),
        })
        .onConflictDoUpdate({
          target: users.id,
          set: {
            ...userData,
            lastLoginAt: new Date(),
            updatedAt: new Date(),
          },
        })
        .returning();
      
      storageLog('UPSERT_USER', `Successfully upserted user ${user.email}`, {
        userId: user.id,
        email: user.email,
        role: user.role,
        isNewUser: !userData.id
      });
      return user;
    } catch (error) {
      storageLog('UPSERT_USER', `Failed to upsert user ${userData.email}:`, {
        userData,
        error: error instanceof Error ? {
          message: error.message,
          stack: error.stack
        } : error
      });
      throw error;
    }
  }

  async getAllUsers(): Promise<User[]> {
    return await db
      .select()
      .from(users)
      .orderBy(asc(users.createdAt));
  }

  async getUsersWithoutEmployeeProfile(): Promise<User[]> {
    const usersWithEmployees = await db
      .select({ userId: employees.userId })
      .from(employees)
      .where(sql`${employees.userId} IS NOT NULL`);
    
    const userIdsWithEmployees = usersWithEmployees.map(row => row.userId).filter(id => id !== null);
    
    if (userIdsWithEmployees.length === 0) {
      return await this.getAllUsers();
    }
    
    return await db
      .select()
      .from(users)
      .where(notInArray(users.id, userIdsWithEmployees))
      .orderBy(asc(users.createdAt));
  }

  async getEmployeeByUserId(userId: string): Promise<Employee | undefined> {
    const [employee] = await db
      .select()
      .from(employees)
      .where(eq(employees.userId, userId));
    return employee;
  }

  async updateUserRole(userId: string, role: string): Promise<User> {
    storageLog('UPDATE_USER_ROLE', `Updating role for user ${userId} to ${role}`);
    
    try {
      const [user] = await db
        .update(users)
        .set({ 
          role, 
          updatedAt: new Date() 
        })
        .where(eq(users.id, userId))
        .returning();
      
      storageLog('UPDATE_USER_ROLE', `Successfully updated role for ${user?.email}`, {
        userId,
        newRole: role,
        userEmail: user?.email
      });
      return user;
    } catch (error) {
      storageLog('UPDATE_USER_ROLE', `Failed to update role for user ${userId}:`, {
        userId,
        role,
        error: error instanceof Error ? {
          message: error.message,
          stack: error.stack
        } : error
      });
      throw error;
    }
  }

  async deactivateUser(userId: string): Promise<User> {
    const [user] = await db
      .update(users)
      .set({ 
        isActive: false,
        updatedAt: new Date() 
      })
      .where(eq(users.id, userId))
      .returning();
    return user;
  }

  async createTestUsers(): Promise<User[]> {
    const testUsersData = [
      {
        id: 'test-admin-001',
        email: 'admin@timetracker.test',
        firstName: 'Admin',
        lastName: 'User',
        role: 'admin',
        profileImageUrl: null
      },
      {
        id: 'test-manager-001', 
        email: 'manager@timetracker.test',
        firstName: 'Department',
        lastName: 'Manager',
        role: 'manager',
        profileImageUrl: null
      },
      {
        id: 'test-pm-001',
        email: 'pm@timetracker.test', 
        firstName: 'Project',
        lastName: 'Manager',
        role: 'project_manager',
        profileImageUrl: null
      },
      {
        id: 'test-employee-001',
        email: 'employee@timetracker.test',
        firstName: 'Regular',
        lastName: 'Employee', 
        role: 'employee',
        profileImageUrl: null
      },
      {
        id: 'test-viewer-001',
        email: 'viewer@timetracker.test',
        firstName: 'Viewer',
        lastName: 'User',
        role: 'viewer',
        profileImageUrl: null
      }
    ];

    const createdUsers = [];
    for (const userData of testUsersData) {
      try {
        const [user] = await db
          .insert(users)
          .values(userData)
          .onConflictDoUpdate({
            target: users.id,
            set: {
              ...userData,
              updatedAt: new Date(),
            },
          })
          .returning();
        createdUsers.push(user);
      } catch (error) {
        console.error(`Error creating test user ${userData.email}:`, error);
      }
    }

    return createdUsers;
  }

  async getTestUsers(): Promise<User[]> {
    return await db
      .select()
      .from(users)
      .where(sql`${users.email} LIKE '%timetracker.test'`);
  }

  // Project operations
  async getProjects(): Promise<Project[]> {
    return await withDatabaseRetry(async () => {
      // Show all projects - access control is handled by project assignment and enterprise-wide flag
      return await db
        .select()
        .from(projects)
        .orderBy(asc(projects.name));
    });
  }

  async getEmployeeProjects(userId: string): Promise<Project[]> {
    return await withDatabaseRetry(async () => {
      // Get enterprise-wide projects and projects assigned to this employee
      const enterpriseProjects = await db
        .select()
        .from(projects)
        .where(eq(projects.isEnterpriseWide, true))
        .orderBy(asc(projects.name));

      // For now, return enterprise-wide projects only
      // In a full implementation, you'd also query project assignments
      return enterpriseProjects;
    });
  }

  async getProject(id: string, userId: string): Promise<Project | undefined> {
    return await withDatabaseRetry(async () => {
      // Pure RBAC - no user ownership restrictions for viewing projects
      const [project] = await db
        .select()
        .from(projects)
        .where(eq(projects.id, id));
      return project;
    });
  }

  async createProject(project: InsertProject, userId: string): Promise<Project> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('CREATE_PROJECT', `Creating project by user with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can create projects
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to create projects");
      }

      const [newProject] = await db
        .insert(projects)
        .values(project)
        .returning();
        
      storageLog('CREATE_PROJECT', `Successfully created project: ${newProject.name}`);
      return newProject;
    });
  }

  async updateProject(id: string, project: Partial<InsertProject>, userId: string): Promise<Project | undefined> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('UPDATE_PROJECT', `Updating project ${id} by user ${userId} with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can update projects
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to update projects");
      }

      storageLog('UPDATE_PROJECT', `Role ${userRole} authorized - proceeding with update`);
      
      // Pure RBAC - no user ownership restrictions
      const [updatedProject] = await db
        .update(projects)
        .set({ ...project, updatedAt: new Date() })
        .where(eq(projects.id, id))
        .returning();
        
      if (updatedProject) {
        storageLog('UPDATE_PROJECT', `Successfully updated project: ${updatedProject.name}`);
      } else {
        storageLog('UPDATE_PROJECT', `Project ${id} not found`);
      }
      
      return updatedProject;
    });
  }

  async deleteProject(id: string, userId: string): Promise<boolean> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('DELETE_PROJECT', `Deleting project by user with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can delete projects
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to delete projects");
      }

      // Pure RBAC - no user ownership restrictions
      const result = await db
        .delete(projects)
        .where(eq(projects.id, id));
        
      const success = (result.rowCount ?? 0) > 0;
      if (success) {
        storageLog('DELETE_PROJECT', `Successfully deleted project ${id}`);
      } else {
        storageLog('DELETE_PROJECT', `Project ${id} not found or already deleted`);
      }
      
      return success;
    });
  }

  // Task operations
  async getTasks(projectId: string, userId: string): Promise<Task[]> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_TASKS', `Getting tasks for project ${projectId} by user with role ${userRole}`);
      
      // Pure RBAC - all authenticated users can view tasks for projects they can access
      // Project access is controlled at the project level
      return await db
        .select()
        .from(tasks)
        .where(eq(tasks.projectId, projectId))
        .orderBy(asc(tasks.createdAt));
    });
  }

  async getTask(id: string, userId: string): Promise<Task | undefined> {
    const [task] = await db
      .select({
        id: tasks.id,
        projectId: tasks.projectId,
        name: tasks.name,
        description: tasks.description,
        status: tasks.status,
        createdAt: tasks.createdAt,
        updatedAt: tasks.updatedAt,
      })
      .from(tasks)
      .where(eq(tasks.id, id));
    
    return task || undefined;
  }

  async createTask(task: InsertTask, userId?: string): Promise<Task> {
    return await withDatabaseRetry(async () => {
      if (userId) {
        // Get user role for RBAC check
        const user = await this.getUser(userId);
        const userRole = user?.role || 'employee';
        
        storageLog('CREATE_TASK', `Creating task by user with role ${userRole}`);
        
        // RBAC: Only admins and project_managers can create tasks
        if (!['admin', 'project_manager'].includes(userRole)) {
          throw new Error("Insufficient permissions to create tasks");
        }
      }

      const [newTask] = await db.insert(tasks).values(task).returning();
      storageLog('CREATE_TASK', `Successfully created task: ${newTask.name}`);
      return newTask;
    });
  }

  async updateTask(id: string, taskData: Partial<InsertTask>, userId: string): Promise<Task | undefined> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('UPDATE_TASK', `Updating task ${id} by user with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can update tasks
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to update tasks");
      }

      // Verify task exists
      const existingTask = await this.getTask(id, userId);
      if (!existingTask) {
        return undefined;
      }

      const [updatedTask] = await db
        .update(tasks)
        .set({ ...taskData, updatedAt: new Date() })
        .where(eq(tasks.id, id))
        .returning();
      
      if (updatedTask) {
        storageLog('UPDATE_TASK', `Successfully updated task: ${updatedTask.name}`);
      }
      
      return updatedTask || undefined;
    });
  }

  async deleteTask(id: string, userId: string): Promise<boolean> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('DELETE_TASK', `Deleting task ${id} by user with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can delete tasks
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to delete tasks");
      }

      // Verify task exists
      const existingTask = await this.getTask(id, userId);
      if (!existingTask) {
        return false;
      }

      const result = await db
        .delete(tasks)
        .where(eq(tasks.id, id))
        .returning();
        
      const success = result.length > 0;
      if (success) {
        storageLog('DELETE_TASK', `Successfully deleted task ${id}`);
      }
      
      return success;
    });
  }

  async getAllUserTasks(userId: string): Promise<TaskWithProject[]> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC-based data scoping
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_ALL_TASKS', `Getting all tasks for user with role ${userRole}`);
      
      // RBAC-based data scoping:
      // - Admin: See all tasks from all projects
      // - Project Manager: See all tasks (they can manage any project)
      // - Manager/Employee: See tasks from enterprise-wide projects + assigned projects
      
      let whereCondition;
      if (['admin', 'project_manager'].includes(userRole)) {
        whereCondition = undefined; // No restriction
        storageLog('GET_ALL_TASKS', `${userRole} role - showing all tasks`);
      } else {
        // For managers/employees, show enterprise-wide project tasks
        whereCondition = eq(projects.isEnterpriseWide, true);
        storageLog('GET_ALL_TASKS', `${userRole} role - showing enterprise-wide project tasks only`);
      }

      const results = await db
        .select({
          id: tasks.id,
          projectId: tasks.projectId,
          name: tasks.name,
          description: tasks.description,
          status: tasks.status,
          createdAt: tasks.createdAt,
          updatedAt: tasks.updatedAt,
          project: projects,
        })
        .from(tasks)
        .innerJoin(projects, eq(tasks.projectId, projects.id))
        .where(whereCondition)
        .orderBy(desc(tasks.createdAt));

      return results.map(row => ({
        ...row,
        project: row.project,
      }));
    });
  }

  // Time entry operations
  async getTimeEntries(userId: string, filters?: {
    projectId?: string;
    taskId?: string;
    startDate?: string;
    endDate?: string;
    limit?: number;
    offset?: number;
  }): Promise<TimeEntryWithProject[]> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC-based data scoping
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_TIME_ENTRIES', `Getting time entries for user with role ${userRole}`);
      
      // RBAC-based data scoping:
      // - Admin: See all time entries from all users
      // - Project Manager: See all time entries (they can manage projects)
      // - Manager: See time entries from their department/assigned employees
      // - Employee: See only their own time entries
      
      let whereConditions = [];
      if (userRole === 'admin') {
        // Admin sees all time entries - no user restriction
        storageLog('GET_TIME_ENTRIES', 'Admin role - showing all time entries');
      } else if (userRole === 'project_manager') {
        // Project managers see all time entries for project management purposes
        storageLog('GET_TIME_ENTRIES', 'Project Manager role - showing all time entries');
      } else {
        // Managers and employees see only their own entries
        whereConditions.push(eq(timeEntries.userId, userId));
        storageLog('GET_TIME_ENTRIES', `${userRole} role - showing own time entries only`);
      }

      if (filters?.projectId) {
        whereConditions.push(eq(timeEntries.projectId, filters.projectId));
      }

      if (filters?.taskId) {
        whereConditions.push(eq(timeEntries.taskId, filters.taskId));
      }

      if (filters?.startDate) {
        whereConditions.push(gte(timeEntries.date, filters.startDate));
      }

      if (filters?.endDate) {
        whereConditions.push(lte(timeEntries.date, filters.endDate));
      }

      let query = db
        .select({
          id: timeEntries.id,
          userId: timeEntries.userId,
          projectId: timeEntries.projectId,
          taskId: timeEntries.taskId,
          description: timeEntries.description,
          date: timeEntries.date,
          startTime: timeEntries.startTime,
          endTime: timeEntries.endTime,
          duration: timeEntries.duration,
          createdAt: timeEntries.createdAt,
          updatedAt: timeEntries.updatedAt,
          project: projects,
          task: tasks,
        })
        .from(timeEntries)
        .innerJoin(projects, eq(timeEntries.projectId, projects.id))
        .leftJoin(tasks, eq(timeEntries.taskId, tasks.id))
        .where(whereConditions.length > 0 ? and(...whereConditions) : undefined)
        .orderBy(desc(timeEntries.date), desc(timeEntries.startTime));

      if (filters?.limit) {
        query = query.limit(filters.limit);
      }

      if (filters?.offset) {
        query = query.offset(filters.offset);
      }

      const results = await query;

      return results.map(row => ({
        ...row,
        taskId: row.taskId || null,
        project: row.project,
        task: row.task || null,
      }));
    });
  }

  async getTimeEntry(id: string, userId: string): Promise<TimeEntryWithProject | undefined> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_TIME_ENTRY', `Getting time entry ${id} for user with role ${userRole}`);
      
      // RBAC-based access:
      // - Admin/Project Manager: Can see any time entry
      // - Manager/Employee: Can only see their own time entries
      let whereConditions = [eq(timeEntries.id, id)];
      if (!['admin', 'project_manager'].includes(userRole)) {
        whereConditions.push(eq(timeEntries.userId, userId));
        storageLog('GET_TIME_ENTRY', `${userRole} role - restricting to own time entries`);
      } else {
        storageLog('GET_TIME_ENTRY', `${userRole} role - can view any time entry`);
      }
      
      const [result] = await db
        .select({
          id: timeEntries.id,
          userId: timeEntries.userId,
          projectId: timeEntries.projectId,
          taskId: timeEntries.taskId,
          description: timeEntries.description,
          date: timeEntries.date,
          startTime: timeEntries.startTime,
          endTime: timeEntries.endTime,
          duration: timeEntries.duration,
          createdAt: timeEntries.createdAt,
          updatedAt: timeEntries.updatedAt,
          project: projects,
          task: tasks,
        })
        .from(timeEntries)
        .innerJoin(projects, eq(timeEntries.projectId, projects.id))
        .leftJoin(tasks, eq(timeEntries.taskId, tasks.id))
        .where(and(...whereConditions));

      if (!result) return undefined;

      return {
        ...result,
        taskId: result.taskId || null,
        project: result.project,
        task: result.task || null,
      };
    });
  }

  async createTimeEntry(entry: InsertTimeEntry): Promise<TimeEntry> {
    return await withDatabaseRetry(async () => {
      storageLog('CREATE_TIME_ENTRY', `Creating time entry for project ${entry.projectId}`);
      
      const [newEntry] = await db
        .insert(timeEntries)
        .values(entry)
        .returning();
        
      storageLog('CREATE_TIME_ENTRY', `Successfully created time entry ${newEntry.id}`);
      return newEntry;
    });
  }

  async updateTimeEntry(id: string, entry: Partial<InsertTimeEntry>, userId: string): Promise<TimeEntry | undefined> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('UPDATE_TIME_ENTRY', `Updating time entry ${id} by user with role ${userRole}`);
      
      // RBAC-based access:
      // - Admin/Project Manager: Can update any time entry
      // - Manager/Employee: Can only update their own time entries
      let whereConditions = [eq(timeEntries.id, id)];
      if (!['admin', 'project_manager'].includes(userRole)) {
        whereConditions.push(eq(timeEntries.userId, userId));
        storageLog('UPDATE_TIME_ENTRY', `${userRole} role - restricting to own time entries`);
      } else {
        storageLog('UPDATE_TIME_ENTRY', `${userRole} role - can update any time entry`);
      }
      
      const [updatedEntry] = await db
        .update(timeEntries)
        .set({ ...entry, updatedAt: new Date() })
        .where(and(...whereConditions))
        .returning();
        
      if (updatedEntry) {
        storageLog('UPDATE_TIME_ENTRY', `Successfully updated time entry ${updatedEntry.id}`);
      }
      
      return updatedEntry;
    });
  }

  async deleteTimeEntry(id: string, userId: string): Promise<boolean> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('DELETE_TIME_ENTRY', `Deleting time entry ${id} by user with role ${userRole}`);
      
      // RBAC-based access:
      // - Admin/Project Manager: Can delete any time entry
      // - Manager/Employee: Can only delete their own time entries
      let whereConditions = [eq(timeEntries.id, id)];
      if (!['admin', 'project_manager'].includes(userRole)) {
        whereConditions.push(eq(timeEntries.userId, userId));
        storageLog('DELETE_TIME_ENTRY', `${userRole} role - restricting to own time entries`);
      } else {
        storageLog('DELETE_TIME_ENTRY', `${userRole} role - can delete any time entry`);
      }
      
      const result = await db
        .delete(timeEntries)
        .where(and(...whereConditions));
        
      const success = (result.rowCount ?? 0) > 0;
      if (success) {
        storageLog('DELETE_TIME_ENTRY', `Successfully deleted time entry ${id}`);
      }
      
      return success;
    });
  }

  // Dashboard stats
  async getDashboardStats(userId: string, startDate?: string, endDate?: string): Promise<{
    todayHours: number;
    weekHours: number;
    monthHours: number;
    activeProjects: number;
  }> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC-based data scoping
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_DASHBOARD_STATS', `Getting dashboard stats for user with role ${userRole}`);
      
      // Use PST timezone for all calculations
      const now = new Date();
      const todayPST = now.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
      const start = startDate || new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
      const end = endDate || todayPST;

      console.log(`📊 Dashboard Stats Debug - userId: ${userId}, role: ${userRole}`);
      console.log(`📅 Date Info PST: today: ${todayPST}, start: ${start}, end: ${end}`);
      
      const todayToUse = todayPST;

      // RBAC-based data scoping:
      // - Admin: See stats from all users across the organization
      // - Project Manager: See stats from all users (for project management)
      // - Manager/Employee: See only their own stats
      let userFilter;
      if (['admin', 'project_manager'].includes(userRole)) {
        userFilter = undefined; // No restriction - see all data
        storageLog('GET_DASHBOARD_STATS', `${userRole} role - showing organization-wide stats`);
      } else {
        userFilter = eq(timeEntries.userId, userId); // Only own data
        storageLog('GET_DASHBOARD_STATS', `${userRole} role - showing personal stats only`);
      }

      // Get today's hours
      const [todayResult] = await db
        .select({ total: sql<number>`COALESCE(SUM(${timeEntries.duration}), 0)` })
        .from(timeEntries)
        .where(userFilter ? and(userFilter, eq(timeEntries.date, todayToUse)) : eq(timeEntries.date, todayToUse));

      console.log(`⏰ Today's Hours Query Result (${todayToUse}):`, todayResult);

      // Get all time entries for today for debugging
      const todayEntries = await db
        .select()
        .from(timeEntries)
        .where(and(eq(timeEntries.userId, userId), eq(timeEntries.date, todayToUse)));

      console.log(`📋 Today's Time Entries (${todayEntries.length}):`, todayEntries);

      // Check recent entries to understand the data
      const recentEntries = await db
        .select()
        .from(timeEntries)
        .where(userFilter)
        .orderBy(sql`${timeEntries.date} DESC`)
        .limit(5);

      console.log(`📋 Recent 5 Time Entries (role: ${userRole}):`, recentEntries);

      // Get this week's hours
      const [weekResult] = await db
        .select({ total: sql<number>`COALESCE(SUM(${timeEntries.duration}), 0)` })
        .from(timeEntries)
        .where(userFilter ? 
          and(userFilter, gte(timeEntries.date, start), lte(timeEntries.date, end)) : 
          and(gte(timeEntries.date, start), lte(timeEntries.date, end))
        );

      // Get this month's hours (from first day of month)
      const monthStart = new Date(now.getFullYear(), now.getMonth(), 1).toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
      const [monthResult] = await db
        .select({ total: sql<number>`COALESCE(SUM(${timeEntries.duration}), 0)` })
        .from(timeEntries)
        .where(userFilter ? 
          and(userFilter, gte(timeEntries.date, monthStart), lte(timeEntries.date, todayToUse)) : 
          and(gte(timeEntries.date, monthStart), lte(timeEntries.date, todayToUse))
        );

      // Get active projects count (projects with time entries in the last 30 days)
      const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
      const activeProjects = await db
        .select({ projectId: timeEntries.projectId })
        .from(timeEntries)
        .where(userFilter ? 
          and(userFilter, gte(timeEntries.date, thirtyDaysAgo)) : 
          gte(timeEntries.date, thirtyDaysAgo)
        )
        .groupBy(timeEntries.projectId);

      const stats = {
        todayHours: parseFloat(todayResult?.total?.toString() || '0'),
        weekHours: parseFloat(weekResult?.total?.toString() || '0'),
        monthHours: parseFloat(monthResult?.total?.toString() || '0'),
        activeProjects: activeProjects.length,
      };

      console.log(`📊 Final Dashboard Stats:`, stats);
      
      return stats;
    });
  }

  async getProjectTimeBreakdown(userId: string, startDate?: string, endDate?: string): Promise<Array<{
    project: Project;
    totalHours: number;
    percentage: number;
  }>> {
    // Get user role to determine access level
    const user = await this.getUser(userId);
    const userRole = user?.role || 'employee';
    
    // Role-based access control for projects
    let projectConditions = [];
    let timeEntryConditions = [];
    
    if (userRole === 'admin') {
      // Admin sees everything (no restrictions)
    } else if (userRole === 'project_manager') {
      // Project managers see enterprise-wide projects and their own projects
      projectConditions.push(or(
        eq(projects.isEnterpriseWide, true),
        eq(projects.userId, userId)
      ));
    } else if (userRole === 'manager') {
      // Managers see enterprise-wide projects (department-level access)
      projectConditions.push(eq(projects.isEnterpriseWide, true));
    } else {
      // Employees see projects they're assigned to (for demo: enterprise-wide projects)
      // In production, this would check project_employees table for assignments
      projectConditions.push(eq(projects.isEnterpriseWide, true));
    }

    if (startDate) {
      timeEntryConditions.push(gte(timeEntries.date, startDate));
    }

    if (endDate) {
      timeEntryConditions.push(lte(timeEntries.date, endDate));
    }

    // Combine conditions properly
    let whereConditions = [];
    if (projectConditions.length > 0) {
      whereConditions.push(...projectConditions);
    }
    if (timeEntryConditions.length > 0) {
      whereConditions.push(...timeEntryConditions);
    }

    console.log(`📊 Project Breakdown - userId: ${userId}, role: ${userRole}, conditions: ${whereConditions.length}`);
    console.log(`📊 Conditions array:`, whereConditions);
    
    try {
      const results = await db
        .select({
          project: projects,
          totalHours: sql<number>`COALESCE(SUM(CAST(${timeEntries.duration} AS DECIMAL)), 0)`,
        })
        .from(projects)
        .leftJoin(timeEntries, eq(projects.id, timeEntries.projectId))
        .where(whereConditions.length > 0 ? and(...whereConditions) : undefined)
        .groupBy(projects.id)
        .orderBy(desc(sql`SUM(CAST(${timeEntries.duration} AS DECIMAL))`));

      console.log(`📊 Project breakdown found ${results.length} projects`);

      const totalHours = results.reduce((sum, row) => sum + Number(row.totalHours), 0);

      return results
        .filter(row => Number(row.totalHours) > 0)
        .map(row => ({
          project: row.project,
          totalHours: Number(row.totalHours),
          percentage: totalHours > 0 ? Math.round((Number(row.totalHours) / totalHours) * 100) : 0,
        }));
    } catch (error) {
      console.error(`📊 Error in getProjectTimeBreakdown:`, error);
      return [];
    }
  }

  async getRecentActivity(userId: string, limit = 10, startDate?: string, endDate?: string): Promise<TimeEntryWithProject[]> {
    return this.getTimeEntries(userId, { 
      limit, 
      startDate: startDate || undefined, 
      endDate: endDate || undefined 
    });
  }

  async getProjectTaskBreakdown(userId: string, startDate?: string, endDate?: string): Promise<Array<{
    project: Project;
    tasks: Array<{
      task: Task | null;
      totalHours: number;
    }>;
    totalHours: number;
  }>> {
    // For now, return an empty array since this feature was removed from production
    // due to instability issues as mentioned in replit.md
    return [];
  }

  // Employee operations
  async getEmployees(userId: string): Promise<Employee[]> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC-based data scoping
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_EMPLOYEES', `Getting employees for user with role ${userRole}`);
      
      // RBAC-based data scoping:
      // - Admin: See all employees
      // - Manager: See all employees (for department management)
      // - Project Manager/Employee: See all employees (for project assignment)
      
      let whereCondition;
      if (userRole === 'admin') {
        whereCondition = undefined; // No restrictions
        storageLog('GET_EMPLOYEES', 'Admin role - showing all employees');
      } else {
        // For enterprise environments, all roles can see employee list for project management
        whereCondition = undefined; // Enterprise-wide employee visibility
        storageLog('GET_EMPLOYEES', `${userRole} role - showing all employees for project management`);
      }
      
      return await db
        .select()
        .from(employees)
        .where(whereCondition)
        .orderBy(asc(employees.firstName), asc(employees.lastName));
    });
  }

  async getEmployee(id: string, userId: string): Promise<Employee | undefined> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC-based data scoping
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_EMPLOYEE', `Getting employee ${id} for user with role ${userRole}`);
      
      // RBAC-based data scoping:
      // - Admin/Manager: Can see any employee
      // - Project Manager/Employee: Can see enterprise-wide employee data
      let whereConditions = [eq(employees.id, id)];
      
      if (!['admin', 'manager'].includes(userRole)) {
        // For non-admin/manager roles, you could implement more restrictive access here
        // For now, allowing all authenticated users to view employee data for project assignment
        storageLog('GET_EMPLOYEE', `${userRole} role - allowing employee access for project management`);
      } else {
        storageLog('GET_EMPLOYEE', `${userRole} role - full employee access`);
      }
      
      const [employee] = await db
        .select()
        .from(employees)
        .where(and(...whereConditions));
        
      return employee;
    });
  }

  async createEmployee(employee: InsertEmployee): Promise<Employee> {
    const [newEmployee] = await db
      .insert(employees)
      .values(employee)
      .returning();
    return newEmployee;
  }

  async updateEmployee(id: string, employeeData: Partial<InsertEmployee>, userId: string): Promise<Employee | undefined> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('UPDATE_EMPLOYEE', `Updating employee ${id} by user with role ${userRole}`);
      
      // RBAC: Only admins and managers can update employee information
      if (!['admin', 'manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to update employee information");
      }

      // Pure RBAC - no user ownership restrictions
      const [updatedEmployee] = await db
        .update(employees)
        .set({ ...employeeData, updatedAt: new Date() })
        .where(eq(employees.id, id))
        .returning();
        
      if (updatedEmployee) {
        storageLog('UPDATE_EMPLOYEE', `Successfully updated employee: ${updatedEmployee.firstName} ${updatedEmployee.lastName}`);
      }
      
      return updatedEmployee;
    });
  }

  async deleteEmployee(id: string, userId: string): Promise<boolean> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('DELETE_EMPLOYEE', `Deleting employee ${id} by user with role ${userRole}`);
      
      // RBAC: Only admins can delete employees (critical HR operation)
      if (userRole !== 'admin') {
        throw new Error("Insufficient permissions to delete employees");
      }

      // Pure RBAC - no user ownership restrictions
      const result = await db
        .delete(employees)
        .where(eq(employees.id, id));
        
      const success = (result.rowCount ?? 0) > 0;
      if (success) {
        storageLog('DELETE_EMPLOYEE', `Successfully deleted employee ${id}`);
      }
      
      return success;
    });
  }

  async linkUserToEmployee(userId: string, employeeId: string): Promise<Employee | undefined> {
    const [updatedEmployee] = await db
      .update(employees)
      .set({ userId, updatedAt: new Date() })
      .where(eq(employees.id, employeeId))
      .returning();
    return updatedEmployee;
  }

  // Project access control operations
  async getProjectWithEmployees(id: string, userId: string): Promise<ProjectWithEmployees | undefined> {
    const project = await this.getProject(id, userId);
    if (!project) return undefined;

    if (project.isEnterpriseWide) {
      // Enterprise-wide projects don't have assigned employees
      return { ...project, assignedEmployees: [] };
    }

    // Get assigned employees for restricted projects
    const assignedEmployees = await db
      .select({
        id: employees.id,
        employeeId: employees.employeeId,
        firstName: employees.firstName,
        lastName: employees.lastName,
        department: employees.department,
        userId: employees.userId,
        createdAt: employees.createdAt,
        updatedAt: employees.updatedAt,
      })
      .from(projectEmployees)
      .innerJoin(employees, eq(projectEmployees.employeeId, employees.id))
      .where(and(
        eq(projectEmployees.projectId, id),
        eq(projectEmployees.userId, userId)
      ));

    return { ...project, assignedEmployees };
  }

  async assignEmployeesToProject(projectId: string, employeeIds: string[], userId: string): Promise<void> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('ASSIGN_EMPLOYEES', `Assigning employees to project ${projectId} by user ${userId} with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can assign employees
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to assign employees to projects");
      }

      // Verify project exists (no ownership restriction - pure RBAC)
      const project = await db.select().from(projects).where(eq(projects.id, projectId)).limit(1);
      if (project.length === 0) {
        throw new Error("Project not found");
      }

      storageLog('ASSIGN_EMPLOYEES', `Role ${userRole} authorized - proceeding with assignment`);

      // Remove existing assignments for this project
      await db
        .delete(projectEmployees)
        .where(eq(projectEmployees.projectId, projectId));

      // Add new assignments
      if (employeeIds.length > 0) {
        await db.insert(projectEmployees).values(
          employeeIds.map(employeeId => ({
            projectId,
            employeeId,
            userId: userId, // For audit trail only
          }))
        );
        storageLog('ASSIGN_EMPLOYEES', `Successfully assigned ${employeeIds.length} employees to project`);
      } else {
        storageLog('ASSIGN_EMPLOYEES', `Cleared all employee assignments for project`);
      }
    });
  }

  async getProjectEmployees(projectId: string, userId: string): Promise<Employee[]> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('GET_PROJECT_EMPLOYEES', `Fetching project employees for user with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can view project employee assignments
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to view project employee assignments");
      }

      // Pure RBAC - no user ownership restrictions
      const result = await db
        .select({
          id: employees.id,
          employeeId: employees.employeeId,
          firstName: employees.firstName,
          lastName: employees.lastName,
          department: employees.department,
          userId: employees.userId,
          createdAt: employees.createdAt,
          updatedAt: employees.updatedAt,
        })
        .from(projectEmployees)
        .innerJoin(employees, eq(projectEmployees.employeeId, employees.id))
        .where(eq(projectEmployees.projectId, projectId));

      storageLog('GET_PROJECT_EMPLOYEES', `Retrieved ${result.length} assigned employees`);
      return result;
    });
  }

  async removeEmployeeFromProject(projectId: string, employeeId: string, userId: string): Promise<boolean> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('REMOVE_EMPLOYEE', `Removing employee from project by user with role ${userRole}`);
      
      // RBAC: Only admins and project_managers can remove employee assignments
      if (!['admin', 'project_manager'].includes(userRole)) {
        throw new Error("Insufficient permissions to remove employees from projects");
      }

      // Pure RBAC - no user ownership restrictions
      const result = await db
        .delete(projectEmployees)
        .where(and(
          eq(projectEmployees.projectId, projectId),
          eq(projectEmployees.employeeId, employeeId)
        ))
        .returning();

      const success = result.length > 0;
      if (success) {
        storageLog('REMOVE_EMPLOYEE', `Successfully removed employee ${employeeId} from project ${projectId}`);
      } else {
        storageLog('REMOVE_EMPLOYEE', `No employee assignment found to remove`);
      }

      return success;
    });
  }

  // Department operations
  async getDepartments(): Promise<DepartmentWithManager[]> {
    const result = await db
      .select({
        id: departments.id,
        name: departments.name,
        organizationId: departments.organizationId,
        managerId: departments.managerId,
        description: departments.description,
        userId: departments.userId,
        createdAt: departments.createdAt,
        updatedAt: departments.updatedAt,
        manager: {
          id: employees.id,
          employeeId: employees.employeeId,
          firstName: employees.firstName,
          lastName: employees.lastName,
          department: employees.department,
          userId: employees.userId,
          createdAt: employees.createdAt,
          updatedAt: employees.updatedAt,
        },
        organization: {
          id: organizations.id,
          name: organizations.name,
          description: organizations.description,
          userId: organizations.userId,
          createdAt: organizations.createdAt,
          updatedAt: organizations.updatedAt,
        }
      })
      .from(departments)
      .leftJoin(employees, eq(departments.managerId, employees.id))
      .leftJoin(organizations, eq(departments.organizationId, organizations.id))
      .orderBy(asc(departments.name));

    return result.map(row => ({
      ...row,
      manager: row.manager && row.manager.id ? row.manager : null,
      organization: row.organization || null
    }));
  }

  async getDepartment(id: string): Promise<DepartmentWithManager | undefined> {
    const [result] = await db
      .select({
        id: departments.id,
        name: departments.name,
        organizationId: departments.organizationId,
        managerId: departments.managerId,
        description: departments.description,
        userId: departments.userId,
        createdAt: departments.createdAt,
        updatedAt: departments.updatedAt,
        manager: {
          id: employees.id,
          employeeId: employees.employeeId,
          firstName: employees.firstName,
          lastName: employees.lastName,
          department: employees.department,
          userId: employees.userId,
          createdAt: employees.createdAt,
          updatedAt: employees.updatedAt,
        },
        organization: {
          id: organizations.id,
          name: organizations.name,
          description: organizations.description,
          userId: organizations.userId,
          createdAt: organizations.createdAt,
          updatedAt: organizations.updatedAt,
        }
      })
      .from(departments)
      .leftJoin(employees, eq(departments.managerId, employees.id))
      .leftJoin(organizations, eq(departments.organizationId, organizations.id))
      .where(eq(departments.id, id));

    if (!result) return undefined;

    return {
      ...result,
      manager: result.manager && result.manager.id ? result.manager : null,
      organization: result.organization || null
    };
  }

  async createDepartment(department: InsertDepartment): Promise<Department> {
    const [newDepartment] = await db
      .insert(departments)
      .values(department)
      .returning();
    return newDepartment;
  }

  async updateDepartment(id: string, department: Partial<InsertDepartment>, userId: string): Promise<Department | undefined> {
    const [updatedDepartment] = await db
      .update(departments)
      .set({ ...department, updatedAt: new Date() })
      .where(eq(departments.id, id))
      .returning();
    return updatedDepartment;
  }

  async deleteDepartment(id: string, userId: string): Promise<boolean> {
    const result = await db
      .delete(departments)
      .where(eq(departments.id, id));
    return (result.rowCount || 0) > 0;
  }

  async assignManagerToDepartment(departmentId: string, managerId: string | null, userId: string): Promise<void> {
    await db
      .update(departments)
      .set({ managerId, updatedAt: new Date() })
      .where(eq(departments.id, departmentId));
  }

  // Organization operations
  async getOrganizations(): Promise<Organization[]> {
    // Show all organizations - users belong to organizations, not create them
    return await db
      .select()
      .from(organizations)
      .orderBy(asc(organizations.name));
  }

  async getOrganization(id: string): Promise<OrganizationWithDepartments | undefined> {
    const [org] = await db
      .select()
      .from(organizations)
      .where(eq(organizations.id, id));

    if (!org) return undefined;

    // Get departments for this organization
    const deps = await this.getDepartmentsByOrganization(id);

    return {
      ...org,
      departments: deps,
    };
  }

  async createOrganization(organization: InsertOrganization): Promise<Organization> {
    const [newOrganization] = await db
      .insert(organizations)
      .values(organization)
      .returning();
    return newOrganization;
  }

  async updateOrganization(id: string, organization: Partial<InsertOrganization>, userId: string): Promise<Organization | undefined> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('UPDATE_ORGANIZATION', `Updating organization ${id} by user with role ${userRole}`);
      
      // RBAC: Only admins can update organizations
      if (userRole !== 'admin') {
        throw new Error("Insufficient permissions to update organizations");
      }

      // Pure RBAC - no user ownership restrictions
      const [updatedOrganization] = await db
        .update(organizations)
        .set({ ...organization, updatedAt: new Date() })
        .where(eq(organizations.id, id))
        .returning();
        
      if (updatedOrganization) {
        storageLog('UPDATE_ORGANIZATION', `Successfully updated organization: ${updatedOrganization.name}`);
      }
      
      return updatedOrganization;
    });
  }

  async deleteOrganization(id: string, userId: string): Promise<boolean> {
    return await withDatabaseRetry(async () => {
      // Get user role for RBAC check
      const user = await this.getUser(userId);
      const userRole = user?.role || 'employee';
      
      storageLog('DELETE_ORGANIZATION', `Deleting organization ${id} by user with role ${userRole}`);
      
      // RBAC: Only admins can delete organizations
      if (userRole !== 'admin') {
        throw new Error("Insufficient permissions to delete organizations");
      }

      // Pure RBAC - no user ownership restrictions
      const result = await db
        .delete(organizations)
        .where(eq(organizations.id, id));
        
      const success = (result.rowCount || 0) > 0;
      if (success) {
        storageLog('DELETE_ORGANIZATION', `Successfully deleted organization ${id}`);
      }
      
      return success;
    });
  }

  async getDepartmentsByOrganization(organizationId: string): Promise<DepartmentWithManager[]> {
    const result = await db
      .select({
        id: departments.id,
        name: departments.name,
        organizationId: departments.organizationId,
        managerId: departments.managerId,
        description: departments.description,
        userId: departments.userId,
        createdAt: departments.createdAt,
        updatedAt: departments.updatedAt,
        manager: {
          id: employees.id,
          employeeId: employees.employeeId,
          firstName: employees.firstName,
          lastName: employees.lastName,
          department: employees.department,
          userId: employees.userId,
          createdAt: employees.createdAt,
          updatedAt: employees.updatedAt,
        },
        organization: {
          id: organizations.id,
          name: organizations.name,
          description: organizations.description,
          userId: organizations.userId,
          createdAt: organizations.createdAt,
          updatedAt: organizations.updatedAt,
        }
      })
      .from(departments)
      .leftJoin(employees, eq(departments.managerId, employees.id))
      .leftJoin(organizations, eq(departments.organizationId, organizations.id))
      .where(eq(departments.organizationId, organizationId))
      .orderBy(asc(departments.name));

    return result.map(row => ({
      ...row,
      manager: row.manager && row.manager.id ? row.manager : null,
      organization: row.organization || null
    }));
  }



  async getDepartmentHoursSummary(userId: string, startDate?: string, endDate?: string): Promise<Array<{
    departmentId: string;
    departmentName: string;
    totalHours: number;
    employeeCount: number;
  }>> {
    // Get user role to determine department access
    const user = await this.getUser(userId);
    const userRole = user?.role || 'employee';
    
    const dateFilter = startDate && endDate 
      ? and(
          gte(timeEntries.date, startDate),
          lte(timeEntries.date, endDate)
        )
      : undefined;

    // For now, return department hours based on employee department names
    // Since employees.department contains department names, not IDs
    const result = await db
      .select({
        departmentId: sql<string>`${employees.department}`,
        departmentName: sql<string>`${employees.department}`,
        totalHours: sql<number>`COALESCE(SUM(CAST(${timeEntries.duration} AS DECIMAL)), 0)`,
        employeeCount: sql<number>`COUNT(DISTINCT ${employees.id})`,
      })
      .from(employees)
      .leftJoin(timeEntries, 
        dateFilter 
          ? and(
              eq(employees.userId, timeEntries.userId),
              dateFilter
            )
          : eq(employees.userId, timeEntries.userId)
      )
      .where(
        userRole === 'admin' 
          ? undefined 
          : eq(employees.userId, userId)
      )
      .groupBy(employees.department)
      .having(sql`${employees.department} IS NOT NULL AND ${employees.department} != ''`)
      .orderBy(sql`SUM(CAST(${timeEntries.duration} AS DECIMAL)) DESC`);

    return result.filter(r => r.departmentName && r.totalHours > 0);
  }

  // Reports operations
  async getTimeEntriesForProject(projectId: string): Promise<any[]> {
    const result = await db
      .select({
        id: timeEntries.id,
        duration: sql<number>`CAST(${timeEntries.duration} AS NUMERIC)`,
        description: timeEntries.description,
        date: timeEntries.date,
        createdAt: timeEntries.createdAt,
        userId: timeEntries.userId,
        taskId: timeEntries.taskId,
        employee: {
          id: users.id,
          firstName: users.firstName,
          lastName: users.lastName,
          email: users.email,
        },
        task: {
          id: tasks.id,
          name: tasks.name,
          description: tasks.description,
          status: tasks.status,
        }
      })
      .from(timeEntries)
      .leftJoin(users, eq(timeEntries.userId, users.id))
      .leftJoin(tasks, eq(timeEntries.taskId, tasks.id))
      .where(eq(timeEntries.projectId, projectId))
      .orderBy(desc(timeEntries.date), desc(timeEntries.createdAt));

    return result;
  }
}

export const storage = new DatabaseStorage();
