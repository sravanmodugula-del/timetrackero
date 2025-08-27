#!/usr/bin/env node

/**
 * Build validation script for TimeTracker Pro
 * Validates that all required static assets exist before deployment
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const requiredFiles = [
  'public/index.html',
  'public/assets',  // Directory should exist
];

const optionalFiles = [
  'public/manifest.json',
  'public/favicon.ico',
];

function checkFileExists(filePath) {
  const fullPath = path.resolve(filePath);
  return fs.existsSync(fullPath);
}

function validateBuild() {
  console.log('🔍 Validating build artifacts...\n');
  
  let errors = 0;
  let warnings = 0;

  // Check required files
  console.log('Required files:');
  requiredFiles.forEach(file => {
    if (checkFileExists(file)) {
      console.log(`✅ ${file}`);
    } else {
      console.log(`❌ ${file} - MISSING`);
      errors++;
    }
  });

  // Check optional files
  console.log('\nOptional files:');
  optionalFiles.forEach(file => {
    if (checkFileExists(file)) {
      console.log(`✅ ${file}`);
    } else {
      console.log(`⚠️  ${file} - Not found (optional)`);
      warnings++;
    }
  });

  // Validate assets directory has content
  const assetsDir = path.resolve('public/assets');
  if (fs.existsSync(assetsDir)) {
    const assetFiles = fs.readdirSync(assetsDir);
    if (assetFiles.length === 0) {
      console.log(`⚠️  public/assets directory is empty`);
      warnings++;
    } else {
      console.log(`✅ Found ${assetFiles.length} asset files`);
    }
  }

  // Summary
  console.log('\n📊 Build validation summary:');
  if (errors === 0) {
    console.log('✅ Build validation passed');
    if (warnings > 0) {
      console.log(`⚠️  ${warnings} warnings found`);
    }
    process.exit(0);
  } else {
    console.log(`❌ Build validation failed with ${errors} errors`);
    console.log('\n💡 To fix build issues:');
    console.log('   1. Run: npm run build');
    console.log('   2. Verify the build completed successfully');
    console.log('   3. Check that public/ directory contains built assets');
    process.exit(1);
  }
}

// Run validation
validateBuild();