#!/usr/bin/env node

/**
 * Production Readiness Check for TimeTracker Pro
 * Validates all environment variables and configurations for production deployment
 */

import fs from 'fs';
import https from 'https';
import { URL } from 'url';
import { fileURLToPath } from 'url';
import path from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Required environment variables for production
const REQUIRED_ENV_VARS = [
  'NODE_ENV',
  'SESSION_SECRET', 
  'REPL_ID',
  'REPLIT_DOMAINS',
  'DATABASE_URL'
];

const OPTIONAL_ENV_VARS = [
  'PORT',
  'TZ'
];

function checkEnvironmentVariables() {
  console.log('🔍 Checking environment variables...\n');
  
  let errors = 0;
  let warnings = 0;

  // Check required variables
  console.log('Required environment variables:');
  REQUIRED_ENV_VARS.forEach(varName => {
    const value = process.env[varName];
    if (value) {
      console.log(`✅ ${varName} = ${varName === 'SESSION_SECRET' || varName === 'DATABASE_URL' ? '***HIDDEN***' : value}`);
      
      // Additional validation
      if (varName === 'NODE_ENV' && value !== 'production') {
        console.log(`   ⚠️  Warning: NODE_ENV is "${value}", should be "production" for production deployment`);
        warnings++;
      }
      
      if (varName === 'SESSION_SECRET' && value.length < 32) {
        console.log(`   ⚠️  Warning: SESSION_SECRET should be at least 32 characters`);
        warnings++;
      }
      
      if (varName === 'REPLIT_DOMAINS' && value.includes('localhost')) {
        console.log(`   ⚠️  Warning: REPLIT_DOMAINS contains localhost, ensure production domain is configured`);
        warnings++;
      }
      
    } else {
      console.log(`❌ ${varName} - MISSING`);
      errors++;
    }
  });

  // Check optional variables
  console.log('\nOptional environment variables:');
  OPTIONAL_ENV_VARS.forEach(varName => {
    const value = process.env[varName];
    if (value) {
      console.log(`✅ ${varName} = ${value}`);
    } else {
      console.log(`➖ ${varName} - Using default`);
    }
  });

  return { errors, warnings };
}

function checkSecurityConfiguration() {
  console.log('\n🔒 Checking security configuration...\n');
  
  let warnings = 0;
  
  // Check NODE_ENV
  if (process.env.NODE_ENV === 'development') {
    console.log('❌ CRITICAL: NODE_ENV is set to "development"');
    console.log('   🚨 This enables authentication bypass - NEVER use in production!');
    return { errors: 1, warnings: 0 };
  } else if (process.env.NODE_ENV === 'production') {
    console.log('✅ NODE_ENV correctly set to production');
  }

  // Check session secret strength
  if (process.env.SESSION_SECRET) {
    const sessionSecret = process.env.SESSION_SECRET;
    if (sessionSecret.length >= 32) {
      console.log('✅ SESSION_SECRET length is adequate');
    } else {
      console.log('⚠️  SESSION_SECRET should be longer for better security');
      warnings++;
    }
  }

  // Check database URL for SSL
  if (process.env.DATABASE_URL && process.env.DATABASE_URL.includes('sslmode=require')) {
    console.log('✅ Database SSL is enabled');
  } else if (process.env.DATABASE_URL) {
    console.log('⚠️  Database SSL is not explicitly enabled');
    warnings++;
  }

  return { errors: 0, warnings };
}

async function checkBuildArtifacts() {
  console.log('\n🏗️  Checking build artifacts...\n');
  
  let errors = 0;
  
  // Check if build directory exists
  if (fs.existsSync('public')) {
    console.log('✅ Build directory (public/) exists');
    
    // Check for index.html
    if (fs.existsSync('public/index.html')) {
      console.log('✅ index.html found');
    } else {
      console.log('❌ index.html missing from build');
      errors++;
    }
    
    // Check for assets directory
    if (fs.existsSync('public/assets')) {
      const assetFiles = fs.readdirSync('public/assets');
      console.log(`✅ Assets directory contains ${assetFiles.length} files`);
    } else {
      console.log('⚠️  Assets directory not found - build may be incomplete');
      errors++;
    }
    
  } else {
    console.log('❌ Build directory (public/) does not exist');
    console.log('   💡 Run "npm run build" before production deployment');
    errors++;
  }
  
  return { errors, warnings: 0 };
}

async function performHealthCheck() {
  console.log('\n🏥 Performing application health check...\n');
  
  // This would normally check if the app starts successfully
  // For now, we'll just verify the main files exist
  
  let errors = 0;
  
  const criticalFiles = [
    'server/index.ts',
    'server/routes.ts',
    'server/replitAuth.ts',
    'server/storage.ts',
    'package.json'
  ];
  
  criticalFiles.forEach(file => {
    if (fs.existsSync(file)) {
      console.log(`✅ ${file}`);
    } else {
      console.log(`❌ ${file} - MISSING`);
      errors++;
    }
  });
  
  return { errors, warnings: 0 };
}

async function main() {
  console.log('🚀 TimeTracker Pro Production Readiness Check\n');
  console.log('=' .repeat(50));
  
  let totalErrors = 0;
  let totalWarnings = 0;
  
  // Run all checks
  const envCheck = checkEnvironmentVariables();
  totalErrors += envCheck.errors;
  totalWarnings += envCheck.warnings;
  
  const securityCheck = checkSecurityConfiguration();
  totalErrors += securityCheck.errors;
  totalWarnings += securityCheck.warnings;
  
  const buildCheck = await checkBuildArtifacts();
  totalErrors += buildCheck.errors;
  totalWarnings += buildCheck.warnings;
  
  const healthCheck = await performHealthCheck();
  totalErrors += healthCheck.errors;
  totalWarnings += healthCheck.warnings;
  
  // Final summary
  console.log('\n' + '=' .repeat(50));
  console.log('📊 PRODUCTION READINESS SUMMARY\n');
  
  if (totalErrors === 0) {
    console.log('✅ PRODUCTION READY');
    if (totalWarnings > 0) {
      console.log(`⚠️  ${totalWarnings} warnings found - consider reviewing`);
    }
    console.log('\n🚀 Your application is ready for production deployment!');
    process.exit(0);
  } else {
    console.log('❌ NOT READY FOR PRODUCTION');
    console.log(`   ${totalErrors} critical errors found`);
    console.log(`   ${totalWarnings} warnings found`);
    console.log('\n💡 Fix all errors before deploying to production');
    console.log('\n🔧 Common fixes:');
    console.log('   • Set NODE_ENV=production');
    console.log('   • Set all required environment variables');
    console.log('   • Run npm run build');
    console.log('   • Use strong SESSION_SECRET (32+ characters)');
    process.exit(1);
  }
}

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled promise rejection:', reason);
  process.exit(1);
});

// Run the check
main().catch(error => {
  console.error('❌ Production readiness check failed:', error);
  process.exit(1);
});