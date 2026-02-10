// Minimal MCP server entry for mcp-server — replace with your implementation as needed.
/// <reference types="node" />

// Note: This file includes a placeholder integration with a "rolldice" tool. Implement or adjust the import path as needed.

import { rollDice } from '../tools/rolldice';

export async function startMcpServer(): Promise<void> {
  console.log('MCP server initialized');

  try {
    if (typeof rollDice === 'function') {
      const result = rollDice(6);
      console.log('Rolldice result:', result);
    } else {
      console.log('rolldice tool not available — implement integration in src/tools/rolldice');
    }
  } catch (err) {
    console.error('Error using rolldice tool:', err);
  }
}

// If run directly, start (useful for local testing)
// Fix for 'require' not defined in TypeScript/ESM
// Ensure Node.js types are available

if (typeof process !== 'undefined' && process.argv?.[1]?.endsWith('index.ts')) {
  startMcpServer().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}