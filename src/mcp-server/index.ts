// Minimal MCP server entry for mcp-server — replace with your implementation as needed.
/// <reference types="node" />

// Use shared rolldice utility
import { rollDice } from "../tools/rolldice";

export async function startMcpServer(): Promise<void> {
  console.log('MCP server initialized');

  try {
    const result = rollDice(6);
    console.log('Rolldice result:', result);
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
