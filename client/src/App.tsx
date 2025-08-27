import { Switch, Route } from "wouter";
import { queryClient } from "./lib/queryClient";
import { QueryClientProvider } from "@tanstack/react-query";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import { useAuth } from "@/hooks/useAuth";
import NotFound from "@/pages/not-found";
import Landing from "@/pages/landing";
import Dashboard from "@/pages/dashboard";
import TimeEntry from "@/pages/time-entry";
import TimeLog from "@/pages/time-log";
import Projects from "@/pages/projects";
import Tasks from "@/pages/tasks";
import Employees from "@/pages/employees";
import Organizations from "@/pages/organizations";
import Departments from "@/pages/departments";
import UserManagement from "@/pages/user-management";
import RoleTesting from "@/pages/role-testing";
import Reports from "@/pages/reports";
import Navigation from "@/components/navigation";
import { ProtectedRoute } from "@/components/ProtectedRoute";

function Router() {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <Switch>
      {!isAuthenticated ? (
        <>
          <Route path="/" component={Landing} />
          <Route component={Landing} />
        </>
      ) : (
        <div className="flex min-h-screen bg-background">
          <Navigation />
          <div className="flex-1">
            <Switch>
              <Route path="/" component={Dashboard} />
              <Route path="/time-entry" component={TimeEntry} />
              <Route path="/time-log" component={TimeLog} />
              <Route path="/projects" component={Projects} />
              <Route path="/tasks" component={Tasks} />
              <Route path="/reports" component={Reports} />
              <Route path="/employees" component={Employees} />
              <Route path="/organizations" component={Organizations} />
              <Route path="/departments" component={Departments} />
              <Route path="/role-testing" component={RoleTesting} />
              <Route path="/admin/users" component={UserManagement} />
              <Route component={NotFound} />
            </Switch>
          </div>
        </div>
      )}
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <Toaster />
        <Router />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
