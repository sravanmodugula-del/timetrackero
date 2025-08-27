import { Pool, neonConfig } from '@neondatabase/serverless';
import { drizzle } from 'drizzle-orm/neon-serverless';
import ws from "ws";
import * as schema from "@shared/schema";

neonConfig.webSocketConstructor = ws;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

// Enhanced connection pool with resilience settings
export const pool = new Pool({ 
  connectionString: process.env.DATABASE_URL,
  max: 20, // Maximum connections
  idleTimeoutMillis: 30000, // 30 seconds idle timeout
  connectionTimeoutMillis: 5000, // 5 seconds connection timeout
});

// Add connection error handling to prevent server crashes
pool.on('error', (err) => {
  console.error('🔴 [DATABASE] Unexpected database pool error:', err);
  // Don't crash the server - log and continue
});

export const db = drizzle({ client: pool, schema });

// Database health check function
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    await pool.query('SELECT 1');
    return true;
  } catch (error) {
    console.error('🔴 [DATABASE] Health check failed:', error);
    return false;
  }
}

// Graceful database operation wrapper
export async function withDatabaseRetry<T>(operation: () => Promise<T>, maxRetries = 3): Promise<T> {
  let lastError: Error;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error as Error;
      console.error(`🟡 [DATABASE] Operation failed (attempt ${attempt}/${maxRetries}):`, error);
      
      // Don't retry on authentication or permission errors
      if (error instanceof Error && (error.message.includes('authentication') || error.message.includes('permission'))) {
        throw error;
      }
      
      // Wait before retry (exponential backoff)
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, 1000 * attempt));
      }
    }
  }
  
  throw lastError!;
}