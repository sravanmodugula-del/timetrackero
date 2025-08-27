# Overview
TimeTracker Pro is a comprehensive time tracking application for employees to log time entries, view analytics, and manage work hours. It aims to be a stable, production-ready solution for enterprise time management, focusing on robust role-based access control (RBAC), cross-browser compatibility, and detailed logging. The project envisions significant market potential by providing a reliable and scalable solution for organizational time management.

# User Preferences
Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
The frontend is built with React 18, TypeScript, and Vite, utilizing shadcn/ui components (built on Radix UI) for consistent design, Wouter for routing, and TanStack Query for server state management. Tailwind CSS handles styling. It employs a page-based routing structure with dedicated sections for Dashboard, Time Entry, Time Log, Projects, Tasks, Employees, Departments, and Organizations. A robust RBAC system is implemented using `useAuth`, `usePermissions`, `useRole` hooks, `ProtectedRoute`, `RoleGuard` components, and a role-aware `UserMenu`.

## Backend Architecture
The backend uses Express.js with a RESTful API design, featuring enhanced database resilience and connection management. It has a modular structure with separate files for route handlers, database operations (abstracted via a storage interface), and authentication middleware. API endpoints cover user management, project CRUD, time entry management, and dashboard analytics, all protected by authentication middleware with comprehensive error handling.

## Database Schema & Resilience
The application uses PostgreSQL with Drizzle ORM and enhanced connection pooling. The schema includes tables for Users, Projects, Time Entries, and Sessions, designed with cascading deletes and indexing for performance. Key resilience features include connection retry mechanisms with exponential backoff, database health monitoring, circuit breaker patterns, and enhanced error handling to prevent server crashes from database connection issues.

## Authentication & Authorization System
The system integrates enterprise authentication via Passport.js, utilizing PostgreSQL-backed session storage with a 7-day TTL and automatic user profile synchronization. Authorization is handled through a four-tier Role-Based Access Control (RBAC) system:
- **Admin**: Superuser with unrestricted access to all application data.
- **Project Manager**: Project-level management, including employee assignments.
- **Manager**: Department-level management with employee and project oversight.
- **Employee**: Basic project access with personal time tracking capabilities.
- **Viewer**: Read-only access to assigned projects and own time entries.
Access control is context-aware, supporting department and organization-scoped access, enforced by a comprehensive middleware stack.

## State Management
Client-side state is managed using TanStack Query for server state and React's built-in state for UI. It employs optimistic updates and cache invalidation. Form state is handled by React Hook Form with Zod for validation.

## Testing Infrastructure
The project has comprehensive test coverage, including dedicated admin superuser tests, automated CI/CD with GitHub Actions, and various test categories covering authentication, API endpoints, component rendering, and role-based access.

# External Dependencies

## Core Framework Dependencies
- **React 18**
- **Express.js**
- **Vite**
- **Node.js**

## Database & ORM
- **PostgreSQL** (configured for Neon Database)
- **Drizzle ORM**
- **Drizzle-Kit**

## Authentication & Session Management
- **Passport.js**
- **OpenID Client**
- **Connect-PG-Simple**
- **Express-Session**

## UI & Styling
- **shadcn/ui**
- **Radix UI**
- **Tailwind CSS**
- **Lucide React**
- **Class Variance Authority**

## State Management & Data Fetching
- **TanStack Query**
- **React Hook Form**
- **Zod**

## Development & Build Tools
- **TypeScript**
- **ESBuild**
- **PostCSS**
- **TSX**