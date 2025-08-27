// Branding Configuration
// Customize these values to brand your TimeTracker Pro application

export interface BrandingConfig {
  // Company Information
  companyName: string;
  appName: string;
  tagline: string;
  
  // Visual Identity
  logo: {
    url?: string; // URL to your logo image
    text?: string; // Text logo fallback
    icon?: React.ComponentType; // Icon component
  };
  
  // Color Scheme
  colors: {
    primary: string;
    primaryForeground: string;
    secondary: string;
    accent: string;
    success: string;
    warning: string;
    error: string;
  };
  
  // Typography
  fonts: {
    heading: string;
    body: string;
  };
  
  // Contact & Links
  contact: {
    website?: string;
    email?: string;
    phone?: string;
    address?: string;
  };
  
  // Social Links
  social: {
    linkedin?: string;
    twitter?: string;
    facebook?: string;
    instagram?: string;
  };
  
  // Features to highlight
  features: Array<{
    title: string;
    description: string;
    icon: React.ComponentType;
  }>;
}

// Default branding - customize this for your organization
export const defaultBranding: BrandingConfig = {
  companyName: "Your Company",
  appName: "TimeTracker Pro",
  tagline: "Professional Time Management Solution",
  
  logo: {
    text: "TimeTracker Pro", // Will use this if no logo URL provided
  },
  
  colors: {
    primary: "hsl(207, 90%, 54%)", // Blue
    primaryForeground: "hsl(210, 40%, 98%)",
    secondary: "hsl(210, 40%, 96%)",
    accent: "hsl(210, 40%, 96%)",
    success: "hsl(142, 71%, 45%)",
    warning: "hsl(38, 92%, 50%)",
    error: "hsl(0, 84%, 60%)",
  },
  
  fonts: {
    heading: "system-ui, -apple-system, sans-serif",
    body: "system-ui, -apple-system, sans-serif",
  },
  
  contact: {
    website: "https://yourcompany.com",
    email: "contact@yourcompany.com",
    phone: "+1 (555) 123-4567",
  },
  
  social: {
    linkedin: "https://linkedin.com/company/yourcompany",
    twitter: "https://twitter.com/yourcompany",
  },
  
  features: [
    {
      title: "Time Tracking",
      description: "Log work hours with precision and ease across multiple projects",
      icon: () => null, // Will be replaced with actual icons
    },
    {
      title: "Analytics",
      description: "Comprehensive dashboards with insights into productivity patterns",
      icon: () => null,
    },
    {
      title: "Project Management",
      description: "Organize work into projects and tasks for better productivity",
      icon: () => null,
    },
    {
      title: "Team Collaboration",
      description: "Coordinate teams with role-based access and organizational structure",
      icon: () => null,
    },
  ],
};

// Custom branding configurations for different themes

export const brandingThemes = {
  // Corporate Blue Theme
  corporate: {
    ...defaultBranding,
    colors: {
      primary: "hsl(207, 90%, 54%)",
      primaryForeground: "hsl(210, 40%, 98%)",
      secondary: "hsl(210, 40%, 96%)",
      accent: "hsl(210, 40%, 96%)",
      success: "hsl(142, 71%, 45%)",
      warning: "hsl(38, 92%, 50%)",
      error: "hsl(0, 84%, 60%)",
    },
  },
  
  // Modern Green Theme
  eco: {
    ...defaultBranding,
    colors: {
      primary: "hsl(142, 71%, 45%)",
      primaryForeground: "hsl(0, 0%, 100%)",
      secondary: "hsl(142, 20%, 96%)",
      accent: "hsl(142, 20%, 96%)",
      success: "hsl(142, 71%, 45%)",
      warning: "hsl(38, 92%, 50%)",
      error: "hsl(0, 84%, 60%)",
    },
  },
  
  // Professional Purple Theme
  professional: {
    ...defaultBranding,
    colors: {
      primary: "hsl(262, 83%, 58%)",
      primaryForeground: "hsl(0, 0%, 100%)",
      secondary: "hsl(262, 20%, 96%)",
      accent: "hsl(262, 20%, 96%)",
      success: "hsl(142, 71%, 45%)",
      warning: "hsl(38, 92%, 50%)",
      error: "hsl(0, 84%, 60%)",
    },
  },
  
  // Tech Orange Theme
  tech: {
    ...defaultBranding,
    colors: {
      primary: "hsl(24, 95%, 53%)",
      primaryForeground: "hsl(0, 0%, 100%)",
      secondary: "hsl(24, 20%, 96%)",
      accent: "hsl(24, 20%, 96%)",
      success: "hsl(142, 71%, 45%)",
      warning: "hsl(38, 92%, 50%)",
      error: "hsl(0, 84%, 60%)",
    },
  },
};

// Get current branding configuration
export function getBranding(): BrandingConfig {
  // You can add logic here to load branding from environment variables,
  // database, or local storage for multi-tenant applications
  
  // For now, return the default branding
  // You can change this to any theme: corporate, eco, professional, tech
  return defaultBranding;
}

// Apply branding colors to CSS variables
export function applyBrandingColors(colors: BrandingConfig['colors']) {
  const root = document.documentElement;
  
  root.style.setProperty('--primary', colors.primary);
  root.style.setProperty('--primary-foreground', colors.primaryForeground);
  root.style.setProperty('--secondary', colors.secondary);
  root.style.setProperty('--accent', colors.accent);
  root.style.setProperty('--success', colors.success);
  root.style.setProperty('--warning', colors.warning);
  root.style.setProperty('--error', colors.error);
}