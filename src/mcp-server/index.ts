// Minimal MCP server entry for mcp-server — replace with your implementation as needed.
/// <reference types="node" />

// Local rollDice to avoid cross-project import issues during type-check
function rollDice(sides: number): number {
  if (!Number.isInteger(sides) || sides <= 0) {
    throw new Error('sides must be a positive integer');
  }
  return Math.floor(Math.random() * sides) + 1;
}

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
