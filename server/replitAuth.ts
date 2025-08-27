import * as client from "openid-client";
import { Strategy, type VerifyFunction } from "openid-client/passport";

import passport from "passport";
import session from "express-session";
import type { Express, RequestHandler } from "express";
import memoize from "memoizee";
import connectPg from "connect-pg-simple";
import { storage } from "./storage";

if (!process.env.REPLIT_DOMAINS) {
  throw new Error("Environment variable REPLIT_DOMAINS not provided");
}

const getOidcConfig = memoize(
  async () => {
    // Use default Replit OIDC issuer if not explicitly set
    const issuerUrl = process.env.ISSUER_URL || "https://replit.com/oidc";
    console.log("🔑 Using OIDC issuer:", issuerUrl);
    
    return await client.discovery(
      new URL(issuerUrl),
      process.env.REPL_ID!
    );
  },
  { maxAge: 3600 * 1000 }
);

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
  
  if (isProduction && !process.env.DATABASE_URL) {
    throw new Error('DATABASE_URL is required for production session store');
  }
  
  // Use PostgreSQL session store for production, memory for development
  if (isProduction) {
    const pgStore = connectPg(session);
    const sessionStore = new pgStore({
      conString: process.env.DATABASE_URL,
      createTableIfMissing: true,
      ttl: sessionTtl,
      tableName: "sessions",
    });
    
    return session({
      secret: process.env.SESSION_SECRET!,
      store: sessionStore,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: true,
        maxAge: sessionTtl,
        sameSite: 'lax',
      },
      name: 'timetracker.sid',
    });
  } else {
    // Development settings
    return session({
      secret: process.env.SESSION_SECRET!,
      resave: true,
      saveUninitialized: true,
      rolling: true,
      cookie: {
        httpOnly: false,
        secure: false,
        maxAge: sessionTtl,
        sameSite: 'lax',
      },
      name: 'timetracker.sid',
    });
  }
}

function updateUserSession(
  user: any,
  tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers
) {
  user.claims = tokens.claims();
  user.access_token = tokens.access_token;
  user.refresh_token = tokens.refresh_token;
  user.expires_at = user.claims?.exp;
}

async function upsertUser(
  claims: any,
) {
  await storage.upsertUser({
    id: claims["sub"],
    email: claims["email"],
    firstName: claims["first_name"],
    lastName: claims["last_name"],
    profileImageUrl: claims["profile_image_url"],
  });
}

export async function setupAuth(app: Express) {
  app.set("trust proxy", 1);
  app.use(getSession());
  app.use(passport.initialize());
  app.use(passport.session());

  const config = await getOidcConfig();

  const verify: VerifyFunction = async (
    tokens: client.TokenEndpointResponse & client.TokenEndpointResponseHelpers,
    verified: passport.AuthenticateCallback
  ) => {
    const user = {};
    updateUserSession(user, tokens);
    await upsertUser(tokens.claims());
    verified(null, user);
  };

  const domains = process.env.REPLIT_DOMAINS!.split(",");
  console.log("🌐 Configuring OAuth strategies for domains:", domains);
  
  for (const domain of domains) {
    console.log(`🔧 Setting up strategy for domain: ${domain}`);
    console.log(`🔗 Callback URL: https://${domain}/api/callback`);
    
    const strategy = new Strategy(
      {
        name: `replitauth:${domain}`,
        config,
        scope: "openid email profile offline_access",
        callbackURL: `https://${domain}/api/callback`,
      },
      verify,
    );
    passport.use(strategy);
  }

  passport.serializeUser((user: Express.User, cb) => cb(null, user));
  passport.deserializeUser((user: Express.User, cb) => cb(null, user));

  app.get("/api/login", (req, res, next) => {
    console.log("🔐 Login attempt for hostname:", req.hostname);
    console.log("🔐 Available domains:", process.env.REPLIT_DOMAINS);
    
    // Use the first configured domain for localhost requests
    const configuredDomains = process.env.REPLIT_DOMAINS!.split(",");
    const targetDomain = configuredDomains.includes(req.hostname) ? req.hostname : configuredDomains[0];
    const strategyName = `replitauth:${targetDomain}`;
    
    console.log("🔐 Using domain:", targetDomain, "for strategy:", strategyName);
    
    passport.authenticate(strategyName, {
      prompt: "login consent",
      scope: ["openid", "email", "profile", "offline_access"],
    })(req, res, next);
  });

  app.get("/api/callback", (req, res, next) => {
    console.log("🔗 OAuth callback for hostname:", req.hostname);
    console.log("🔗 Full callback URL:", req.url);
    
    // Use the first configured domain for localhost requests
    const configuredDomains = process.env.REPLIT_DOMAINS!.split(",");
    const targetDomain = configuredDomains.includes(req.hostname) ? req.hostname : configuredDomains[0];
    
    console.log("🔗 Using domain:", targetDomain, "for callback");
    
    passport.authenticate(`replitauth:${targetDomain}`, (err: any, user: any, info: any) => {
      if (err) {
        console.error("❌ OAuth callback error:", err);
        return res.redirect("/api/login?error=oauth_error");
      }
      
      if (!user) {
        console.error("❌ OAuth callback failed - no user:", info);
        return res.redirect("/api/login?error=oauth_failed");
      }
      
      req.logIn(user, (loginErr) => {
        if (loginErr) {
          console.error("❌ Login error:", loginErr);
          return res.redirect("/api/login?error=login_failed");
        }
        
        console.log("✅ OAuth callback successful, redirecting to /");
        return res.redirect("/");
      });
    })(req, res, next);
  });

  app.get("/api/logout", (req, res) => {
    req.logout(() => {
      res.redirect(
        client.buildEndSessionUrl(config, {
          client_id: process.env.REPL_ID!,
          post_logout_redirect_uri: `${req.protocol}://${req.hostname}`,
        }).href
      );
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
    // Production mode MUST use real OAuth authentication
    if (process.env.NODE_ENV === 'development' && (!req.isAuthenticated() || !req.user)) {
      authLog('DEBUG', 'Development mode: Creating test admin user');
      authLog('WARN', 'SECURITY: Authentication bypass active - DO NOT USE IN PRODUCTION');
      
      // Create a mock authenticated user for testing
      req.user = {
        claims: {
          sub: "test-admin-user",
          email: "admin@test.com",
          first_name: "Test",
          last_name: "Admin"
        }
      };
      
      // Ensure the test user exists in database
      try {
        await storage.upsertUser({
          id: "test-admin-user",
          email: "admin@test.com", 
          firstName: "Test",
          lastName: "Admin",
          profileImageUrl: null,
        });
        
        // In development mode, respect the current database role instead of forcing admin
        // This allows role testing to work properly
        const currentUser = await storage.getUser("test-admin-user");
        const currentRole = currentUser?.role || "admin";
        
        // Only set admin role if user doesn't exist or has no role
        if (!currentUser || !currentUser.role) {
          await storage.updateUserRole("test-admin-user", "admin");
          authLog('INFO', 'Test admin user authenticated successfully');
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
      sessionId: req.sessionID
    });

    // Check if token has expired and refresh if needed
    if (user.expires_at && Date.now() / 1000 > user.expires_at) {
      authLog('WARN', 'Access token expired, attempting refresh', {
        userId: user.claims?.sub,
        expiresAt: user.expires_at,
        hasRefreshToken: !!user.refresh_token
      });

      if (user.refresh_token) {
        try {
          const config = await getOidcConfig();
          const tokens = await client.refreshTokenGrant(
            config,
            user.refresh_token
          );
          updateUserSession(user, tokens);
          await upsertUser(tokens.claims());
          authLog('INFO', 'Token refreshed successfully', {
            userId: tokens.claims().sub
          });
        } catch (refreshError) {
          authLog('ERROR', 'Token refresh failed:', {
            userId: user.claims?.sub,
            error: refreshError instanceof Error ? {
              message: refreshError.message,
              stack: refreshError.stack
            } : refreshError
          });
          return res.status(401).json({ message: "Unauthorized" });
        }
      } else {
        authLog('ERROR', 'No refresh token available for expired session', {
          userId: user.claims?.sub
        });
        return res.status(401).json({ message: "Unauthorized" });
      }
    }

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
