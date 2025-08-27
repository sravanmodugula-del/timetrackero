import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Clock, BarChart3, Calendar, Users, ExternalLink, Mail, Phone, MapPin } from "lucide-react";
import { Logo } from "@/components/ui/logo";
import { getBranding } from "@/lib/branding";
import { useEffect } from "react";

export default function Landing() {
  const branding = getBranding();
  
  useEffect(() => {
    // Apply branding colors when component mounts
    const root = document.documentElement;
    Object.entries(branding.colors).forEach(([key, value]) => {
      const cssVarName = key.replace(/([A-Z])/g, '-$1').toLowerCase();
      root.style.setProperty(`--${cssVarName}`, value);
    });
  }, [branding.colors]);

  const handleLogin = () => {
    window.location.href = "/api/login";
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-primary/10 to-primary/5">
      {/* Header */}
      <header className="container mx-auto px-4 py-6">
        <div className="flex items-center justify-between">
          <Logo size="md" />
          <div className="flex items-center space-x-4">
            {branding.contact.website && (
              <a 
                href={branding.contact.website} 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-muted-foreground hover:text-foreground transition-colors"
              >
                <ExternalLink className="w-5 h-5" />
              </a>
            )}
            <Button onClick={handleLogin} className="bg-primary hover:bg-primary/90">
              Sign In
            </Button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <main className="container mx-auto px-4 py-16">
        <div className="text-center max-w-4xl mx-auto">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-primary text-white rounded-full mb-8">
            <Clock className="w-10 h-10" />
          </div>
          
          <h2 className="text-5xl font-bold text-foreground mb-6">
            {branding.tagline}
          </h2>
          
          <p className="text-xl text-muted-foreground mb-12 leading-relaxed">
            Track your work hours, manage projects, and analyze productivity with our comprehensive time tracking solution designed for modern teams.
          </p>

          <Button 
            onClick={handleLogin}
            size="lg"
            className="bg-primary hover:bg-primary/90 text-lg px-8 py-6 mb-16"
          >
            Get Started - Sign In
          </Button>

          {/* Features Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 mt-16">
            <Card className="border-none shadow-lg">
              <CardContent className="p-8 text-center">
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <Clock className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-lg font-semibold text-foreground mb-2">Time Tracking</h3>
                <p className="text-muted-foreground text-sm">
                  Log work hours with precision and ease across multiple projects
                </p>
              </CardContent>
            </Card>

            <Card className="border-none shadow-lg">
              <CardContent className="p-8 text-center">
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <BarChart3 className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-lg font-semibold text-foreground mb-2">Analytics</h3>
                <p className="text-muted-foreground text-sm">
                  Comprehensive dashboards with insights into productivity patterns
                </p>
              </CardContent>
            </Card>

            <Card className="border-none shadow-lg">
              <CardContent className="p-8 text-center">
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <Calendar className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-lg font-semibold text-foreground mb-2">Project Management</h3>
                <p className="text-muted-foreground text-sm">
                  Organize work into projects and tasks for better productivity
                </p>
              </CardContent>
            </Card>

            <Card className="border-none shadow-lg">
              <CardContent className="p-8 text-center">
                <div className="w-12 h-12 bg-primary/10 rounded-lg flex items-center justify-center mx-auto mb-4">
                  <Users className="w-6 h-6 text-primary" />
                </div>
                <h3 className="text-lg font-semibold text-foreground mb-2">Team Collaboration</h3>
                <p className="text-muted-foreground text-sm">
                  Coordinate teams with role-based access and organizational structure
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Company Information Footer */}
          <div className="mt-24 pt-16 border-t border-border">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center md:text-left">
              {/* Contact Information */}
              <div>
                <h4 className="text-lg font-semibold text-foreground mb-4">Contact Us</h4>
                <div className="space-y-2">
                  {branding.contact.email && (
                    <div className="flex items-center justify-center md:justify-start space-x-2">
                      <Mail className="w-4 h-4 text-muted-foreground" />
                      <a href={`mailto:${branding.contact.email}`} className="text-muted-foreground hover:text-primary">
                        {branding.contact.email}
                      </a>
                    </div>
                  )}
                  {branding.contact.phone && (
                    <div className="flex items-center justify-center md:justify-start space-x-2">
                      <Phone className="w-4 h-4 text-muted-foreground" />
                      <a href={`tel:${branding.contact.phone}`} className="text-muted-foreground hover:text-primary">
                        {branding.contact.phone}
                      </a>
                    </div>
                  )}
                  {branding.contact.address && (
                    <div className="flex items-center justify-center md:justify-start space-x-2">
                      <MapPin className="w-4 h-4 text-muted-foreground" />
                      <span className="text-muted-foreground">{branding.contact.address}</span>
                    </div>
                  )}
                </div>
              </div>

              {/* Company Info */}
              <div>
                <h4 className="text-lg font-semibold text-foreground mb-4">About {branding.companyName}</h4>
                <p className="text-muted-foreground text-sm">
                  Professional time tracking and productivity management solutions for modern businesses.
                </p>
              </div>

              {/* Quick Links */}
              <div>
                <h4 className="text-lg font-semibold text-foreground mb-4">Quick Links</h4>
                <div className="space-y-2">
                  {branding.contact.website && (
                    <a href={branding.contact.website} target="_blank" rel="noopener noreferrer" 
                       className="block text-muted-foreground hover:text-primary">
                      Company Website
                    </a>
                  )}
                  <button onClick={handleLogin} className="block text-muted-foreground hover:text-primary">
                    Employee Login
                  </button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-muted/30 py-8">
        <div className="container mx-auto px-4 text-center">
          <div className="flex items-center justify-center space-x-3 mb-4">
            <Logo size="sm" />
          </div>
          <p className="text-muted-foreground text-sm">
            © 2024 {branding.companyName}. All rights reserved.
          </p>
        </div>
      </footer>
    </div>
  );
}