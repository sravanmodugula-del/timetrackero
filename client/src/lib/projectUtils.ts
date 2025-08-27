import type { Project } from "@shared/schema";

/**
 * Determines if a project is currently active based on its start and end dates
 */
export function isProjectActive(project: Project): boolean {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()); // Start of today
  
  // If no dates are set, consider project as active
  if (!project.startDate && !project.endDate) {
    return true;
  }
  
  // Check start date
  if (project.startDate) {
    const startDate = new Date(project.startDate);
    const startDateOnly = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate());
    if (today < startDateOnly) {
      return false; // Project hasn't started yet
    }
  }
  
  // Check end date
  if (project.endDate) {
    const endDate = new Date(project.endDate);
    const endDateOnly = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDate());
    if (today > endDateOnly) {
      return false; // Project has ended
    }
  }
  
  return true;
}

/**
 * Gets the status of a project based on its dates
 */
export function getProjectStatus(project: Project): 'upcoming' | 'active' | 'ended' {
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  
  // Check start date
  if (project.startDate) {
    const startDate = new Date(project.startDate);
    const startDateOnly = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate());
    if (today < startDateOnly) {
      return 'upcoming';
    }
  }
  
  // Check end date
  if (project.endDate) {
    const endDate = new Date(project.endDate);
    const endDateOnly = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDate());
    if (today > endDateOnly) {
      return 'ended';
    }
  }
  
  return 'active';
}

/**
 * Filters projects to only include active ones
 */
export function getActiveProjects(projects: Project[]): Project[] {
  return projects.filter(isProjectActive);
}