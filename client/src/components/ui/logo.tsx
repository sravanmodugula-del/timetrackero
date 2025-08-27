import { Clock } from "lucide-react";
import { getBranding } from "@/lib/branding";

interface LogoProps {
  className?: string;
  size?: "sm" | "md" | "lg";
  showText?: boolean;
}

export function Logo({ className = "", size = "md", showText = true }: LogoProps) {
  const branding = getBranding();
  
  const sizeClasses = {
    sm: "w-6 h-6",
    md: "w-8 h-8", 
    lg: "w-12 h-12",
  };
  
  const textSizeClasses = {
    sm: "text-lg",
    md: "text-xl",
    lg: "text-2xl",
  };

  return (
    <div className={`flex items-center space-x-3 ${className}`}>
      {branding.logo.url ? (
        <img 
          src={branding.logo.url} 
          alt={`${branding.companyName} Logo`}
          className={`${sizeClasses[size]} object-contain`}
        />
      ) : branding.logo.icon ? (
        <div className={`${sizeClasses[size]} bg-primary text-primary-foreground rounded-lg flex items-center justify-center`}>
          <branding.logo.icon />
        </div>
      ) : (
        <div className={`${sizeClasses[size]} bg-primary text-primary-foreground rounded-lg flex items-center justify-center`}>
          <Clock className="w-2/3 h-2/3" />
        </div>
      )}
      
      {showText && (
        <span className={`font-bold text-foreground ${textSizeClasses[size]}`}>
          {branding.logo.text || branding.appName}
        </span>
      )}
    </div>
  );
}