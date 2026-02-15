import { readdirSync, existsSync, lstatSync, realpathSync } from 'fs';
import { join } from 'path';

// Check for next.config.ts in various locations
const locations = [
  '/vercel/share/v0-project',
  '/vercel/share/v0-next-shadcn',
  '/vercel/share',
  '/vercel',
  '/',
];

for (const loc of locations) {
  const tsPath = join(loc, 'next.config.ts');
  const jsPath = join(loc, 'next.config.js');
  const mjsPath = join(loc, 'next.config.mjs');
  
  console.log(`\n--- ${loc} ---`);
  console.log(`next.config.ts exists: ${existsSync(tsPath)}`);
  console.log(`next.config.js exists: ${existsSync(jsPath)}`);
  console.log(`next.config.mjs exists: ${existsSync(mjsPath)}`);
  
  if (existsSync(mjsPath)) {
    try {
      const stat = lstatSync(mjsPath);
      console.log(`next.config.mjs is symlink: ${stat.isSymbolicLink()}`);
      if (stat.isSymbolicLink()) {
        console.log(`  -> points to: ${realpathSync(mjsPath)}`);
      }
    } catch (e) {
      console.log(`Error checking: ${e.message}`);
    }
  }
  
  if (existsSync(jsPath)) {
    try {
      const stat = lstatSync(jsPath);
      console.log(`next.config.js is symlink: ${stat.isSymbolicLink()}`);
      if (stat.isSymbolicLink()) {
        console.log(`  -> points to: ${realpathSync(jsPath)}`);
      }
    } catch (e) {
      console.log(`Error checking: ${e.message}`);
    }
  }
}

// Also list ALL files in /vercel/share/v0-next-shadcn that start with "next"
console.log('\n--- Files starting with "next" in scaffold ---');
try {
  const files = readdirSync('/vercel/share/v0-next-shadcn');
  const nextFiles = files.filter(f => f.startsWith('next'));
  console.log(nextFiles);
} catch (e) {
  console.log(`Error: ${e.message}`);
}

// Check what findup-sync would actually find
console.log('\n--- Simulating findup-sync from scaffold dir ---');
let dir = '/vercel/share/v0-next-shadcn';
while (dir !== '/') {
  const tsCheck = join(dir, 'next.config.ts');
  if (existsSync(tsCheck)) {
    console.log(`FOUND next.config.ts at: ${tsCheck}`);
  }
  dir = join(dir, '..');
  // normalize
  dir = realpathSync(dir);
}
