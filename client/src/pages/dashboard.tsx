import { useEffect, useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { usePermissions } from "@/hooks/usePermissions";
import { useToast } from "@/hooks/use-toast";
import Header from "@/components/layout/header";
import StatsCards from "@/components/dashboard/stats-cards";
import ProjectBreakdown from "@/components/dashboard/project-breakdown";

import DepartmentHours from "@/components/dashboard/department-hours";
import RecentActivity from "@/components/dashboard/recent-activity";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Calendar, TrendingUp, Clock } from "lucide-react";

export default function Dashboard() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading } = useAuth();
  const permissions = usePermissions();
  const [dateRange, setDateRange] = useState<string>("week");

  // Calculate date filters
  const getDateFilters = () => {
    const now = new Date();
    const todayPST = now.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });
    const today = new Date(todayPST + 'T00:00:00');
    
    switch (dateRange) {
      case "today":
        return {
          startDate: todayPST,
          endDate: todayPST,
        };
      case "week": {
        const startDate = new Date(today);
        startDate.setDate(today.getDate() - 7);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
      case "month": {
        const startDate = new Date(today);
        startDate.setMonth(today.getMonth() - 1);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
      case "quarter": {
        const startDate = new Date(today);
        startDate.setMonth(today.getMonth() - 3);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
      case "year": {
        const startDate = new Date(today);
        startDate.setFullYear(today.getFullYear() - 1);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
      default: {
        const startDate = new Date(today);
        startDate.setDate(today.getDate() - 7);
        return {
          startDate: startDate.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' }),
          endDate: todayPST,
        };
      }
    }
  };

  // Redirect to home if not authenticated
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
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
  }, [isAuthenticated, isLoading, toast]);

  if (isLoading || !isAuthenticated) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <div>
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Time Dashboard</h2>
              <p className="text-gray-600">Overview of your time tracking activities</p>
            </div>
            
            <Card className="w-full sm:w-auto">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <Calendar className="h-4 w-4 text-muted-foreground" />
                  <Select value={dateRange} onValueChange={setDateRange}>
                    <SelectTrigger className="w-40">
                      <SelectValue placeholder="Select period" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="today">Today</SelectItem>
                      <SelectItem value="week">Last 7 days</SelectItem>
                      <SelectItem value="month">Last 30 days</SelectItem>
                      <SelectItem value="quarter">Last 3 months</SelectItem>
                      <SelectItem value="year">Last 12 months</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        <StatsCards dateRange={getDateFilters()} />
        
        {/* Enhanced Analytics */}
        <div className={`grid gap-8 mt-8 ${permissions.canViewDepartmentData ? 'grid-cols-1 lg:grid-cols-2' : 'grid-cols-1'}`}>
          <ProjectBreakdown dateRange={getDateFilters()} />
          {permissions.canViewDepartmentData && <DepartmentHours {...getDateFilters()} />}
        </div>
        
        {/* Recent Activity */}
        <div className="mt-8">
          <RecentActivity dateRange={getDateFilters()} />
        </div>
      </main>
    </div>
  );
}
