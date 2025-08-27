import passport from "passport";
import session from "express-session";
import type { Express, RequestHandler, Request, Response } from "express";
// PostgreSQL session store not needed for MS SQL Server deployment
import { upsertUser, getUserById } from "./storage";
import { createSamlStrategy, generateSamlMetadata } from "./auth/saml";
import { config } from "dotenv";
import { prisma } from "./db";

// Load environment variables
config();

export function getSession() {
  const sessionTtl = 7 * 24 * 60 * 60 * 1000; // 1 week
  const isProduction = process.env.NODE_ENV === 'production';

  // Validate critical session environment variables
  if (!process.env.SESSION_SECRET) {
    throw new Error('SESSION_SECRET environment variable is required');
  }

  if (isProduction && process.env.SESSION_SECRET.length < 32) {
    console.warn('⚠️  WARNING: SESSION_SECRET should be at least 32 characters for production security');
  }

  // For MS SQL Server on-premises deployment, use memory session store
  // MS SQL Server session stores require additional configuration that's not needed for this deployment

  // Default to memory session store (development or when PostgreSQL is not available)
  const sessionConfig = {
    secret: process.env.SESSION_SECRET!,
    resave: true, // Enable for IIS compatibility
    saveUninitialized: true, // Enable for IIS compatibility
    rolling: false, // Disable rolling to prevent session ID changes
    cookie: {
      httpOnly: false, // Disable for IIS reverse proxy compatibility
      secure: false, // Disable for IIS reverse proxy compatibility
      maxAge: sessionTtl,
      sameSite: 'none' as const, // Use 'none' for cross-site requests
      domain: undefined, // Remove domain restriction
      path: '/', // Explicitly set path
    },
    name: 'connect.sid', // Use default Express session name
    proxy: true, // Always trust proxy for IIS
  };

  if (isProduction) {
    console.log('⚠️  Using memory session store in production - sessions will not persist across server restarts');
  } else {
    console.log('🔐 Using memory session store for development');
  }

  return session(sessionConfig);
}

export async function setupAuth(app: Express) {
  // Trust proxy for IIS reverse proxy setup
  app.set("trust proxy", true);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  // Setup SAML strategy if enabled
  if (process.env.SAML_ENABLED === 'true') {
    const samlStrategy = createSamlStrategy();
    if (samlStrategy) {
      passport.use('saml', samlStrategy);
      console.log('🔐 SAML authentication strategy configured');
    }
  }

  passport.serializeUser((user: Express.User, cb) => {
    console.log("🔐 Serializing user:", JSON.stringify(user, null, 2));
    cb(null, user);
  });
  
  passport.deserializeUser((user: Express.User, cb) => {
    console.log("🔐 Deserializing user:", JSON.stringify(user, null, 2));
    cb(null, user);
  });

  // SAML Login route
  app.get("/api/login", (req, res, next) => {
    console.log("🔐 ===== SAML LOGIN INITIATION =====");
    console.log("🔐 Request URL:", req.url);
    console.log("🔐 Request headers:", JSON.stringify(req.headers, null, 2));
    console.log("🔐 Session ID:", req.sessionID);
    console.log("🔐 SAML_ENABLED:", process.env.SAML_ENABLED);
    
    if (process.env.SAML_ENABLED === 'true') {
      console.log("🔐 Initiating SAML authentication...");
      passport.authenticate('saml', {
        successRedirect: '/',
        failureRedirect: '/login?error=saml_failed'
      })(req, res, next);
    } else {
      console.error("❌ SAML not enabled");
      res.status(503).json({ message: "Authentication not configured" });
    }
  });

  // SAML Callback route (ACS) - Updated to match IdP configuration
  app.post("/saml/acs", (req, res, next) => {
    console.log("🔗 ===== SAML CALLBACK (ACS) RECEIVED =====");
    console.log("🔗 Request method:", req.method);
    console.log("🔗 Request URL:", req.url);
    console.log("🔗 Request headers:", JSON.stringify(req.headers, null, 2));
    console.log("🔗 Request body keys:", Object.keys(req.body || {}));
    console.log("🔗 Session ID:", req.sessionID);
    
    // Log SAML Response if present
    if (req.body && req.body.SAMLResponse) {
      console.log("🔗 SAMLResponse received (base64):", req.body.SAMLResponse.substring(0, 100) + '...');
      try {
        const decoded = Buffer.from(req.body.SAMLResponse, 'base64').toString('utf8');
        console.log("🔗 SAMLResponse decoded (first 500 chars):", decoded.substring(0, 500) + '...');
      } catch (e) {
        console.error("❌ Failed to decode SAMLResponse:", e.message);
      }
    }
    
    if (req.body && req.body.RelayState) {
      console.log("🔗 RelayState:", req.body.RelayState);
    }
    
    passport.authenticate('saml', async (err: any, user: any, info: any) => {
      console.log("🔗 SAML authenticate callback executed");
      console.log("🔗 Error:", err);
      console.log("🔗 User:", user ? 'User object received' : 'No user');
      console.log("🔗 Info:", info);
      
      if (err) {
        console.error("❌ ===== SAML CALLBACK ERROR =====");
        console.error("❌ Error type:", err.constructor.name);
        console.error("❌ Error message:", err.message);
        console.error("❌ Error stack:", err.stack);
        console.error("❌ Error details:", JSON.stringify(err, null, 2));
        console.error("❌ ===== END SAML ERROR =====");
        
        if (res.headersSent) {
          console.error("❌ Cannot redirect - headers already sent");
          return;
        }
        
        return res.redirect("/login?error=saml_error&details=" + encodeURIComponent(err.message));
      }

      if (!user) {
        console.error("❌ SAML callback failed - no user");
        console.error("❌ Info object:", JSON.stringify(info, null, 2));
        
        if (res.headersSent) {
          console.error("❌ Cannot redirect - headers already sent");
          return;
        }
        
        return res.redirect("/login?error=saml_failed&info=" + encodeURIComponent(JSON.stringify(info)));
      }

      try {
        console.log("🔗 Processing SAML user data:", JSON.stringify(user, null, 2));
        
        // Ensure we have the required user data - use the correct property paths from the user object
        const userId = user.claims?.sub || user.samlProfile?.nameID || user.id;
        const email = user.claims?.email || user.samlProfile?.email || user.samlProfile?.nameID;
        const firstName = user.claims?.first_name || user.samlProfile?.firstName;
        const lastName = user.claims?.last_name || user.samlProfile?.lastName;

        if (!userId || !email) {
          console.error("❌ Missing required user data:", { userId, email });
          
          if (res.headersSent) {
            console.error("❌ Cannot redirect - headers already sent");
            return;
          }
          
          return res.redirect("/login?error=missing_user_data");
        }

        // Upsert user in database
        await upsertUser({
          id: userId,
          email: email,
          firstName: firstName || null,
          lastName: lastName || null,
          profileImageUrl: null,
        });

        // Create user object for session
        const sessionUser = {
          id: userId,
          claims: {
            sub: userId,
            email: email,
            first_name: firstName,
            last_name: lastName
          },
          authSource: 'saml'
        };

        console.log("🔗 Attempting to log in user with session data:", JSON.stringify(sessionUser, null, 2));
        
        req.logIn(sessionUser, (loginErr) => {
          if (loginErr) {
            console.error("❌ Login error:", loginErr);
            console.error("❌ Login error stack:", loginErr.stack);
            
            // Check if response has already been sent
            if (res.headersSent) {
              console.error("❌ Cannot redirect - headers already sent");
              return;
            }
            
            return res.redirect("/login?error=login_failed&details=" + encodeURIComponent(loginErr.message));
          }

          console.log("✅ SAML callback successful, redirecting to /");
          console.log("✅ Session after login:", req.session);
          console.log("✅ User in session:", req.user);
          
          // Check if response has already been sent
          if (res.headersSent) {
            console.error("❌ Cannot redirect - headers already sent");
            return;
          }
          
          return res.redirect("/");
        });

      } catch (dbError) {
        console.error("❌ Database error during SAML callback:", dbError);
        
        if (res.headersSent) {
          console.error("❌ Cannot redirect - headers already sent");
          return;
        }
        
        return res.redirect("/login?error=database_error&details=" + encodeURIComponent((dbError as Error).message));
      }
    })(req, res, next);
  });

  // Backward compatibility route for /api/callback
  app.post("/api/callback", (req, res, next) => {
    console.log("🔗 Legacy SAML callback received, redirecting to /saml/acs");
    req.url = '/saml/acs';
    app.handle(req, res, next);
  });

  // SAML Authentication status endpoint
  app.get("/api/saml/status", (req, res) => {
    const authStatus = {
      isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : false,
      user: req.user || null,
      sessionID: req.sessionID,
      session: req.session ? 'exists' : 'missing'
    };
    console.log("🔍 SAML Auth Status:", authStatus);
    res.json(authStatus);
  });

  // SAML Debug endpoint
  app.get("/api/saml/debug", (req, res) => {
    const debugInfo = {
      samlEnabled: process.env.SAML_ENABLED,
      entryPoint: process.env.SAML_ENTRY_POINT,
      hasCert: !!process.env.SAML_CERT,
      certLength: process.env.SAML_CERT ? process.env.SAML_CERT.length : 0,
      nodeEnv: process.env.NODE_ENV,
      timestamp: new Date().toISOString(),
      serverUrl: req.protocol + '://' + req.get('host'),
      requestHeaders: req.headers,
      session: req.session ? 'Session exists' : 'No session'
    };
    
    console.log("🔍 SAML Debug info requested:", debugInfo);
    res.json(debugInfo);
  });

  // SAML Metadata endpoint
  app.get("/api/saml/metadata", (req, res) => {
    console.log("📋 SAML Metadata requested");
    console.log("📋 Request headers:", req.headers);
    
    if (process.env.SAML_ENABLED === 'true') {
      const metadata = generateSamlMetadata();
      console.log("📋 Generated metadata:", metadata);
      res.type('application/xml');
      res.send(metadata);
    } else {
      console.log("❌ SAML not enabled for metadata request");
      res.status(404).json({ message: "SAML not enabled" });
    }
  });

  // Logout route
  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      req.session.destroy(() => {
        res.redirect("/login");
      });
    });
  });
}

// Enhanced authentication logging
function authLog(level: 'INFO' | 'WARN' | 'ERROR' | 'DEBUG', message: string, data?: any) {
  const timestamp = new Date().toISOString();
  const emoji = level === 'ERROR' ? '🔴' : level === 'WARN' ? '🟡' : level === 'INFO' ? '🔵' : '🟢';
  const logMessage = `${timestamp} ${emoji} [AUTH] ${message}`;

  if (data) {
    console.log(logMessage, typeof data === 'object' ? JSON.stringify(data, null, 2) : data);
  } else {
    console.log(logMessage);
  }
}

export const isAuthenticated: RequestHandler = async (req, res, next) => {
  try {
    authLog('DEBUG', `Authentication check for ${req.method} ${req.path}`, {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.sessionID,
      hasSession: !!req.session,
      isAuthenticated: req.isAuthenticated ? req.isAuthenticated() : false
    });

    // CRITICAL SECURITY: Only allow test user in development mode
    if (process.env.NODE_ENV === 'development' && (!req.isAuthenticated() || !req.user)) {
      authLog('DEBUG', 'Development mode: Creating test admin user');
      authLog('WARN', 'SECURITY: Authentication bypass active - DO NOT USE IN PRODUCTION');

      req.user = {
        claims: {
          sub: "test-admin-user",
          email: "admin@test.com",
          first_name: "Test",
          last_name: "Admin"
        },
        authSource: 'development',
        id: "test-admin-user" // Added id for getUser method
      };

      try {
        await upsertUser({
          id: "test-admin-user",
          email: "admin@test.com", 
          firstName: "Test",
          lastName: "Admin",
          profileImageUrl: null,
        });

        const currentUser = await getUserById("test-admin-user");
        const currentRole = currentUser?.role || "admin";

        if (!currentUser) {
          authLog('INFO', 'Test admin user created successfully');
        } else {
          authLog('INFO', `Test user authenticated with current role: ${currentRole}`);
        }
      } catch (dbError) {
        authLog('ERROR', 'Failed to setup test user:', dbError);
      }

      return next();
    }

    if (!req.isAuthenticated() || !req.user) {
      authLog('WARN', 'Unauthorized access attempt', {
        path: req.path,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        sessionId: req.sessionID
      });
      return res.status(401).json({ message: "Unauthorized" });
    }

    const user = req.user as any;
    authLog('DEBUG', 'User authenticated', {
      userId: user.claims?.sub || 'unknown',
      email: user.claims?.email || 'unknown',
      sessionId: req.sessionID,
      authSource: user.authSource || 'unknown'
    });

    authLog('DEBUG', 'Authentication successful, proceeding to next middleware');
    return next();

  } catch (error) {
    authLog('ERROR', 'Authentication middleware error:', {
      error: error instanceof Error ? {
        message: error.message,
        stack: error.stack,
        name: error.name
      } : error,
      request: {
        method: req.method,
        path: req.path,
        ip: req.ip,
        sessionId: req.sessionID
      }
    });
    return res.status(500).json({ message: "Internal server error" });
  }
};

// Assuming an auth controller object exists or will be created.
// This part needs to be integrated where the checkAuth and getUser are used.
// For demonstration, let's assume it's part of a larger auth module.
const authController = {
  checkAuth: (req: Request, res: Response) => {
    if (req.user) {
      res.json({ authenticated: true, user: req.user });
    } else {
      res.status(401).json({ authenticated: false });
    }
  },

  getUser: async (req: Request, res: Response) => {
    try {
      if (!req.user) {
        return res.status(401).json({ message: "Unauthorized" });
      }

      // Ensure req.user has an 'id' property that matches the database schema
      const userId = (req.user as any).id || (req.user as any).claims?.sub;
      if (!userId) {
        console.error('User ID not found in session.');
        return res.status(401).json({ message: "User identifier missing" });
      }

      // Get user from database with proper error handling
      const user = await prisma.user.findFirst({
        where: {
          id: userId
        }
      });

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      res.json(user);
    } catch (error) {
      console.error('Error fetching user:', error);
      res.status(500).json({ message: "Failed to fetch user" });
    }
  },
};