import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PieChart } from "lucide-react";
import type { Project } from "@shared/schema";

interface ProjectBreakdownItem {
  project: Project;
  totalHours: number;
  percentage: number;
}

interface ProjectBreakdownProps {
  dateRange: {
    startDate: string;
    endDate: string;
  };
}

export default function ProjectBreakdown({ dateRange }: ProjectBreakdownProps) {
  const { data: breakdown, isLoading } = useQuery<ProjectBreakdownItem[]>({
    queryKey: ["/api/dashboard/project-breakdown", dateRange],
    queryFn: async () => {
      const params = new URLSearchParams({
        startDate: dateRange.startDate,
        endDate: dateRange.endDate,
      });
      const response = await fetch(`/api/dashboard/project-breakdown?${params}`);
      if (!response.ok) {
        throw new Error(`${response.status}: ${response.statusText}`);
      }
      return response.json();
    },
  });

  const getProjectColor = (project: Project) => {
    const colors = {
      '#1976D2': { bg: 'bg-primary', border: 'border-primary' },
      '#388E3C': { bg: 'bg-green-500', border: 'border-green-500' },
      '#F57C00': { bg: 'bg-orange-500', border: 'border-orange-500' },
      '#D32F2F': { bg: 'bg-red-500', border: 'border-red-500' },
    };
    return colors[project.color as keyof typeof colors] || { bg: 'bg-gray-500', border: 'border-gray-500' };
  };

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <PieChart className="w-5 h-5 mr-2 text-primary" />
            Project Time Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center">
                    <div className="w-3 h-3 bg-gray-200 rounded-full mr-3"></div>
                    <div className="h-4 w-32 bg-gray-200 rounded"></div>
                  </div>
                  <div className="h-4 w-16 bg-gray-200 rounded"></div>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2"></div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!breakdown || breakdown.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <PieChart className="w-5 h-5 mr-2 text-primary" />
            Project Time Breakdown
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <p className="text-muted-foreground">No time entries found</p>
            <p className="text-sm text-muted-foreground mt-1">Start logging time to see project breakdown</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center">
          <PieChart className="w-5 h-5 mr-2 text-primary" />
          Project Time Breakdown
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {breakdown.map((item, index) => {
            const colors = getProjectColor(item.project);
            return (
              <div key={index}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center">
                    <div className={`w-3 h-3 ${colors.bg} rounded-full mr-3`}></div>
                    <span className="font-medium text-gray-900">{item.project.name}</span>
                  </div>
                  <div className="text-right">
                    <span className="font-semibold text-gray-900">{item.totalHours.toFixed(1)}h</span>
                    <span className="text-sm text-gray-500 ml-2">{item.percentage}%</span>
                  </div>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className={`${colors.bg} h-2 rounded-full transition-all duration-300`}
                    style={{ width: `${item.percentage}%` }}
                  ></div>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}