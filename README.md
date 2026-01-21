Digital Twin III – Cyber-Hardened Portfolio
Transforming a personal web portfolio into a secure, monitored, and AI-assisted digital presence.

Project Repository: [digital-twin-DigitalMind]
Owner: DigitalMind Team

1. Project Overview
•	Demonstrates a professional portfolio that is visually appealing and cyber-resilient.
•	Detects and blocks real cyber threats in real-time.
•	Analyzes attacker behavior and generates actionable insights.
•	Maintains audit logs and tracks security metrics.
•	Presents a secure, AI-assisted digital presence to prospective employers.

  Tech Stack:
•	Frontend: Next.js 16 + TypeScript
•	Backend: Node.js 20 (API routes) 
•	Database: Supabase (PostgreSQL)
•	Authentication: Clerk Auth
•	Deployment: Vercel
•	Security: WAF, CSP, X-Frame-Options, HSTS, structured logging
•	AI Agents: OpenAI GPT models

2. Key Features
•	Secure Authentication: Users can log in and manage profiles securely.
•	Real-time Threat Monitoring: Detects SQL injection, XSS, bot traffic, and other attack vectors.
•	AI-Driven Interactions: Conversational persona agent answers questions about skills, experience, and portfolio content.
•	Content Management: AI-assisted automated content creation and project documentation.
•	Analytics Dashboard: Visualizes attack patterns, blocked threats, and system performance.
•	Audit Logging: All security events are logged for transparency and accountability.

3. AI Agents Architecture
•	Persona Agent – Digital twin interactions, conversational AI, skill representation
•	Security Guardian – Threat detection, SQL/XSS detection, prompt injection prevention, blocking malicious inputs
•	Content Creator – Blog/project management, AI-powered markdown generation, MCP tool support
•	Threat Analytics – Security insights, pattern analysis, dashboard metrics, attack predictions
•	Audit Logger – Event logging, structured logs, real-time critical alerts
•	All agents work together securely, providing an interactive, self-defending portfolio experience.

4. Database Structure
•	security_events – Logs all security events (severity, threat type, source IP, actions)
•	blog_posts – Stores blog content, slugs, tags, and authors
•	projects – Portfolio projects, tech stacks, GitHub/live URLs, README content
•	threat_metrics_daily – Materialized view for analytics dashboards
•	Security: Row-level security ensures only authorized users or system roles can access or insert data
5. Contributors
•	Phuntshok Wangdruk – Backend / AI Agents
•	Victor Kamanja – Frontend Developer / PRD File
•	Ashmin Aryal – Team Lead / STAR File & README

