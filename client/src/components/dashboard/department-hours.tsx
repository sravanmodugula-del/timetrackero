import { useQuery } from "@tanstack/react-query";
import { Building2, Users, Clock, TrendingUp } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { isUnauthorizedError } from "@/lib/authUtils";
import { useToast } from "@/hooks/use-toast";

interface DepartmentHours {
  departmentId: string;
  departmentName: string;
  totalHours: number;
  employeeCount: number;
}

interface DepartmentHoursProps {
  startDate?: string;
  endDate?: string;
}

export default function DepartmentHours({ startDate, endDate }: DepartmentHoursProps) {
  const { toast } = useToast();

  const url = `/api/dashboard/department-hours?startDate=${startDate}&endDate=${endDate}`;
  const { data: departmentHoursRaw = [], isLoading, error } = useQuery<any[]>({
    queryKey: [url],
    retry: false,
  });

  // Convert string hours to numbers for proper calculations
  const departmentHours: DepartmentHours[] = departmentHoursRaw.map(dept => ({
    ...dept,
    totalHours: typeof dept.totalHours === 'string' ? parseFloat(dept.totalHours) : dept.totalHours,
    employeeCount: typeof dept.employeeCount === 'string' ? parseInt(dept.employeeCount) : dept.employeeCount,
  }));

  const formatHours = (hours: number) => {
    return hours.toFixed(1);
  };

  // Component is working correctly - debug logging can be removed in production

  const totalHours = departmentHours.reduce((sum, dept) => sum + dept.totalHours, 0);
  const totalEmployees = departmentHours.reduce((sum, dept) => sum + dept.employeeCount, 0);

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Building2 className="w-5 h-5 mr-2" />
            Department Hours Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="flex items-center justify-between mb-2">
                  <div className="h-4 bg-gray-200 rounded w-1/3"></div>
                  <div className="h-4 bg-gray-200 rounded w-16"></div>
                </div>
                <div className="h-2 bg-gray-200 rounded"></div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (departmentHours.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Building2 className="w-5 h-5 mr-2" />
            Department Hours Summary
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-gray-500">
            <Building2 className="w-12 h-12 mx-auto mb-3 text-gray-300" />
            <p>No department data available</p>
            <p className="text-sm">
              {error ? `Error: ${error.message}` : 'No employee assignments found for this period'}
            </p>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center">
          <Building2 className="w-5 h-5 mr-2" />
          Department Hours Summary
        </CardTitle>
      </CardHeader>
      <CardContent>
        {/* Summary Stats */}
        <div className="grid grid-cols-2 gap-4 mb-6">
          <div className="bg-blue-50 p-4 rounded-lg">
            <div className="flex items-center text-blue-600 mb-2">
              <Clock className="w-4 h-4 mr-2" />
              <span className="text-sm font-medium">Total Hours</span>
            </div>
            <div className="text-2xl font-bold text-blue-900">
              {formatHours(totalHours)}
            </div>
          </div>
          <div className="bg-green-50 p-4 rounded-lg">
            <div className="flex items-center text-green-600 mb-2">
              <Users className="w-4 h-4 mr-2" />
              <span className="text-sm font-medium">Active Employees</span>
            </div>
            <div className="text-2xl font-bold text-green-900">
              {totalEmployees}
            </div>
          </div>
        </div>

        {/* Department Breakdown */}
        <div className="space-y-4">
          {departmentHours
            .filter(dept => dept.totalHours > 0)
            .sort((a, b) => b.totalHours - a.totalHours)
            .map((department, index) => {
              const percentage = totalHours > 0 ? (department.totalHours / totalHours) * 100 : 0;
              const avgHoursPerEmployee = department.employeeCount > 0 
                ? department.totalHours / department.employeeCount 
                : 0;

              return (
                <div key={department.departmentId} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                      <div className="flex items-center justify-center w-6 h-6 bg-blue-100 text-blue-600 rounded-full text-xs font-semibold">
                        {index + 1}
                      </div>
                      <div>
                        <h3 className="font-medium text-gray-900">
                          {department.departmentName}
                        </h3>
                        <div className="flex items-center space-x-4 text-sm text-gray-500">
                          <span className="flex items-center">
                            <Users className="w-3 h-3 mr-1" />
                            {department.employeeCount} employee{department.employeeCount !== 1 ? 's' : ''}
                          </span>
                          {avgHoursPerEmployee > 0 && (
                            <span className="flex items-center">
                              <TrendingUp className="w-3 h-3 mr-1" />
                              {formatHours(avgHoursPerEmployee)}h avg
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="text-right">
                      <div className="font-semibold text-gray-900">
                        {formatHours(department.totalHours)}h
                      </div>
                      <Badge variant="outline" className="text-xs">
                        {percentage.toFixed(1)}%
                      </Badge>
                    </div>
                  </div>
                  <Progress 
                    value={percentage} 
                    className="h-2"
                  />
                </div>
              );
            })}
        </div>

        {/* Departments with no hours */}
        {departmentHours.filter(dept => dept.totalHours === 0).length > 0 && (
          <div className="mt-6 pt-4 border-t border-gray-200">
            <h4 className="text-sm font-medium text-gray-500 mb-3">
              Departments with no logged hours
            </h4>
            <div className="flex flex-wrap gap-2">
              {departmentHours
                .filter(dept => dept.totalHours === 0)
                .map((department) => (
                  <Badge key={department.departmentId} variant="outline" className="text-xs">
                    {department.departmentName}
                    {department.employeeCount > 0 && (
                      <span className="ml-1">({department.employeeCount})</span>
                    )}
                  </Badge>
                ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}