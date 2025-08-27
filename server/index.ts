import express, { type Request, Response, NextFunction } from "express";
import { registerRoutes } from "./routes";
import { setupVite, serveStatic, log } from "./vite";

// Enhanced logging utility
const LOG_LEVELS = {
  ERROR: '🔴 ERROR',
  WARN: '🟡 WARN',
  INFO: '🔵 INFO',
  DEBUG: '🟢 DEBUG'
};

export function enhancedLog(level: keyof typeof LOG_LEVELS, category: string, message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const logMessage = `${timestamp} ${LOG_LEVELS[level]} [${category}] ${message}`;
  
  if (data) {
    console.log(logMessage, typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
  } else {
    console.log(logMessage);
  }
}

// Enhanced global error handlers with database resilience
process.on('uncaughtException', (error) => {
  enhancedLog('ERROR', 'PROCESS', 'Uncaught Exception:', {
    message: error.message,
    stack: error.stack,
    name: error.name
  });
  
  // Check if it's a database connection error
  if (error.message.includes('terminating connection') || 
      error.message.includes('database') || 
      error.message.includes('connection')) {
    enhancedLog('WARN', 'DATABASE', 'Database connection error detected - attempting recovery...');
    
    // Don't exit immediately for database errors - let the connection pool recover
    setTimeout(() => {
      enhancedLog('INFO', 'PROCESS', 'Database error recovery timeout reached');
    }, 10000);
    
    return; // Don't exit for database connection errors
  }
  
  // For non-database critical errors, still exit
  enhancedLog('ERROR', 'PROCESS', 'Critical error - shutting down server');
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  const isDbError = reason instanceof Error && 
    (reason.message.includes('terminating connection') || 
     reason.message.includes('database') || 
     reason.message.includes('connection'));
     
  enhancedLog(isDbError ? 'WARN' : 'ERROR', 'PROCESS', 'Unhandled Rejection:', {
    reason: reason instanceof Error ? {
      message: reason.message,
      stack: reason.stack,
      name: reason.name
    } : reason,
    promise: promise.toString(),
    isDatabaseError: isDbError
  });
  
  if (!isDbError) {
    enhancedLog('ERROR', 'PROCESS', 'Critical unhandled rejection - shutting down server');
    process.exit(1);
  } else {
    enhancedLog('INFO', 'PROCESS', 'Database error - continuing operation with connection recovery');
  }
});

// Environment validation and setup
function validateProductionEnvironment() {
  const required = ['NODE_ENV', 'SESSION_SECRET', 'REPL_ID', 'REPLIT_DOMAINS', 'DATABASE_URL'];
  const missing = required.filter(varName => !process.env[varName]);
  
  if (missing.length > 0) {
    enhancedLog('ERROR', 'ENV', `Missing required environment variables: ${missing.join(', ')}`);
    enhancedLog('ERROR', 'ENV', 'Please check your environment configuration and .env.example file');
    process.exit(1);
  }
  
  // Validate NODE_ENV specifically
  if (!process.env.NODE_ENV) {
    enhancedLog('ERROR', 'ENV', 'NODE_ENV must be explicitly set to "production" or "development"');
    process.exit(1);
  }
  
  if (process.env.NODE_ENV !== 'production' && process.env.NODE_ENV !== 'development') {
    enhancedLog('WARN', 'ENV', `Unknown NODE_ENV: ${process.env.NODE_ENV}. Expected "production" or "development"`);
  }
  
  if (process.env.NODE_ENV !== 'production') {
    enhancedLog('WARN', 'ENV', '⚠️  WARNING: Running in non-production mode with authentication bypass enabled');
  } else {
    enhancedLog('INFO', 'ENV', '✅ Production mode enabled - authentication bypass disabled');
  }
  
  // Validate SESSION_SECRET strength for production
  if (process.env.NODE_ENV === 'production' && process.env.SESSION_SECRET && process.env.SESSION_SECRET.length < 32) {
    enhancedLog('WARN', 'ENV', '⚠️  WARNING: SESSION_SECRET should be at least 32 characters for production');
  }
  
  enhancedLog('INFO', 'ENV', 'Environment validation completed successfully');
}

// Set timezone
process.env.TZ = process.env.TZ || "America/Los_Angeles";
enhancedLog('INFO', 'TIMEZONE', `Set timezone to ${process.env.TZ}`);

// Validate environment before starting application
validateProductionEnvironment();

const app = express();

// Security middleware (production-ready)
if (process.env.NODE_ENV === 'production') {
  // Trust proxy for production load balancers
  app.set('trust proxy', 1);
  
  // Production security headers
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    next();
  });
}

// Enhanced middleware for better request handling
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use((req, res, next) => {
  const start = Date.now();
  const path = req.path;
  let capturedJsonResponse: Record<string, any> | undefined = undefined;

  // Enhanced request logging
  if (path.startsWith("/api")) {
    enhancedLog('DEBUG', 'REQUEST', `Incoming ${req.method} ${path}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      query: req.query,
      body: req.method !== 'GET' && req.body ? req.body : undefined,
      sessionId: req.sessionID,
      authenticated: req.isAuthenticated ? req.isAuthenticated() : false
    });
  }

  const originalResJson = res.json;
  res.json = function (bodyJson, ...args) {
    capturedJsonResponse = bodyJson;
    return originalResJson.apply(res, [bodyJson, ...args]);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    if (path.startsWith("/api")) {
      let logLine = `${req.method} ${path} ${res.statusCode} in ${duration}ms`;
      if (capturedJsonResponse) {
        logLine += ` :: ${JSON.stringify(capturedJsonResponse)}`;
      }

      if (logLine.length > 80) {
        logLine = logLine.slice(0, 79) + "…";
      }

      log(logLine);

      // Enhanced response logging for errors
      if (res.statusCode >= 400) {
        enhancedLog('ERROR', 'RESPONSE', `Error response for ${req.method} ${path}`, {
          status: res.statusCode,
          duration: `${duration}ms`,
          response: capturedJsonResponse,
          request: {
            query: req.query,
            body: req.body,
            ip: req.ip,
            userAgent: req.get('User-Agent')
          }
        });
      }
    }
  });

  next();
});

(async () => {
  const server = await registerRoutes(app);

  app.use((err: any, req: Request, res: Response, _next: NextFunction) => {
    const status = err.status || err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    // Enhanced error logging
    enhancedLog('ERROR', 'EXPRESS', 'Express error middleware triggered:', {
      error: {
        message: err.message,
        stack: err.stack,
        name: err.name,
        code: err.code,
        status: status
      },
      request: {
        method: req.method,
        path: req.path,
        query: req.query,
        body: req.body,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        sessionId: req.sessionID,
        authenticated: req.isAuthenticated ? req.isAuthenticated() : false
      }
    });

    res.status(status).json({ 
      message,
      error: process.env.NODE_ENV === 'development' ? {
        name: err.name,
        stack: err.stack
      } : undefined
    });
  });

  // importantly only setup vite in development and after
  // setting up all the other routes so the catch-all route
  // doesn't interfere with the other routes
  if (app.get("env") === "development") {
    await setupVite(app, server);
  } else {
    serveStatic(app);
  }

  // ALWAYS serve the app on the port specified in the environment variable PORT
  // Other ports are firewalled. Default to 5000 if not specified.
  // this serves both the API and the client.
  // It is the only port that is not firewalled.
  const port = parseInt(process.env.PORT || '5000', 10);
  server.listen({
    port,
    host: "0.0.0.0",
    reusePort: true,
  }, () => {
    enhancedLog('INFO', 'SERVER', `Server started successfully on port ${port}`, {
      port: port,
      environment: process.env.NODE_ENV,
      timezone: process.env.TZ,
      host: "0.0.0.0"
    });
    log(`serving on port ${port}`);
  });
})();
