/**
 * MCP Server / Tools – Digital Twin III
 */

// Use shared rolldice utility
import { rollDice } from './tools/rolldice';

export async function startMcpServer(): Promise<void> {
  console.log('MCP server initialized');
  const result = rollDice(6);
  console.log('Rolldice result:', result);
}

type InterviewResult = {
  role: string;
  questions: string[];
  evaluatedAt: string;
};

export function runInterviewSimulation(role: string): InterviewResult {
  return {
    role,
    questions: [
      "What is SQL injection and how do you prevent it?",
      "Explain prompt injection in LLM systems.",
      "How does rate limiting protect AI APIs?",
      "Describe OWASP Top 10 and its relevance today."
    ],
    evaluatedAt: new Date().toISOString()
  };
}

/**
 * MCP tool registry (for agent discovery)
 */
export const tools = {
  runInterviewSimulation: {
    description: "Run a cybersecurity interview simulation for a given role",
    inputSchema: {
      type: "object",
      properties: {
        role: { type: "string" }
      },
      required: ["role"]
    }
  }
};
