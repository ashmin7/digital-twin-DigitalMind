export interface LabScenario {
  id: string;
  title: string;
  category: string;
  description: string;
  signal: string;
  response: string;
  outcome: string;
  severity: "HIGH" | "MEDIUM";
  action: "BLOCK" | "CHALLENGE";
  steps: string[];
}

export const labScenarios: Record<string, LabScenario> = {
  sql: {
    id: "SQL-01",
    title: "Query boundary check",
    category: "INJECTION DEFENSE",
    description: "See how a secure data layer treats suspicious input as inert data instead of executable query logic.",
    signal: "Untrusted query-shaped input observed",
    response: "Parameterized query boundary preserves the original query structure",
    outcome: "INPUT CONTAINED",
    severity: "HIGH",
    action: "BLOCK",
    steps: ["Observe input signal", "Apply parameterized-query policy", "Keep the data layer unchanged"],
  },
  xss: {
    id: "XSS-02",
    title: "Output encoding check",
    category: "BROWSER INPUT DEFENSE",
    description: "Review how a safe rendering boundary keeps markup-like input as text rather than executable browser content.",
    signal: "Markup-like content observed at the display boundary",
    response: "Output encoding converts untrusted content to inert text",
    outcome: "OUTPUT ENCODED",
    severity: "HIGH",
    action: "BLOCK",
    steps: ["Observe display-boundary signal", "Apply output-encoding policy", "Render content as inert text"],
  },
  "rate-limit": {
    id: "RATE-03",
    title: "Traffic burst check",
    category: "AUTOMATION DEFENSE",
    description: "Simulate a short request burst and inspect how a rate policy would challenge activity above its sample threshold.",
    signal: "12 simulated requests observed in a short window",
    response: "Sample threshold exceeded; additional requests receive a challenge",
    outcome: "BURST CHALLENGED",
    severity: "MEDIUM",
    action: "CHALLENGE",
    steps: ["Observe simulated request burst", "Compare against sample threshold", "Challenge activity over the limit"],
  },
  auth: {
    id: "AUTH-04",
    title: "Access boundary check",
    category: "IDENTITY & ACCESS",
    description: "Walk through a role-check decision for a protected resource without creating accounts or changing real permissions.",
    signal: "Protected resource requested without the required role",
    response: "Authorization check denies access before protected data is returned",
    outcome: "ACCESS DENIED",
    severity: "HIGH",
    action: "BLOCK",
    steps: ["Observe resource request", "Evaluate required role", "Deny access before data is returned"],
  },
};
