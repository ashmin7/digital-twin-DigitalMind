# Digital Twin III – Independent Cyber Range

An independent security lab built and maintained by Ashmin Aryal, combining controlled exercises with monitored defensive controls and an auditable event trail.

**Project Repository:** digital-twin-DigitalMind
**Owner:** Ashmin Aryal

---

## Project Overview
- Demonstrates a professional portfolio that is visually appealing and cyber-resilient.  
- Detects and blocks real cyber threats in real-time.  
- Analyzes attacker behavior and generates actionable insights.  
- Maintains audit logs and tracks security metrics.  
- Presents a secure, AI-assisted digital presence to prospective employers.  

## 📁 Repository Structure
digital-twin-DigitalMind/
├── 📄 agents.md # AI instruction manual (for Copilot/Claude)
├── 📄 README.md # Project overview (this file)
├── 📁 docs/ # Documentation hub
│ └── 📄 prd.md # Product Requirements Document
├── 📁 data/ # Structured intelligence
│ └── 📄 star.json # Project data (STAR format)
├── 📁 project-management/ # Workflow coordination
│ ├── 📄 github-proof.pdf # Project evidence archive
│ └── 📄 clickup-board.png # Project management state
├── 📁 app/ # Next.js application (Week 2+)
├── 📁 lib/ # Shared utilities & AI agents
├── 📁 public/ # Static assets
└── 📁 tests/ # Security & unit tests
---

### File Purposes:
- **`agents.md`**: Primary context file for AI tools (GitHub Copilot, Claude Desktop)
- **`docs/prd.md`**: Requirements and specifications for AI code generation
- **`docs/design.md`**: Technical design and architecture for implementation
- **`data/star.json`**: Structured lab and creator context for agent guidance
- **`README.md`**: Human onboarding and project overview

## Design & Architecture

For the comprehensive technical design ready for implementation, see:

- [Design Document (`docs/design.md`)](docs/design.md)

## Implementation Plan

For a step-by-step execution plan aligned with the PRD and design, see:

- [Implementation Plan (`docs/implementation-plan.md`)](docs/implementation-plan.md)

This covers system architecture, components, data flow, APIs, database schema, auth, AI integration points, security controls, non-functional requirements, and deployment architecture.

## MCP Configuration

For Model Context Protocol agent/tool definitions used by Copilot and other agents, see:

- [MCP Config (`docs/mcp.json`)](docs/mcp.json)

### MCP Server (lightweight)

For a minimal MCP server and example tool registry, see:

- [MCP Server (`src/mcp-server/index.ts`)](src/mcp-server/index.ts)

### How to run the MCP server

Use the dedicated build and start scripts:

```bash
# Compile only the MCP server (uses src/mcp-server/tsconfig.json)
npm run build:mcp

# Run the compiled server
npm run start

# Or run directly in dev with ts-node
npm run start:mcp

# Live-reload dev mode
npm run dev:mcp
```

## Tech Stack
- **Frontend:** Next.js 16 + TypeScript  
- **Backend:** Node.js 20 (API routes)  
- **Database:** Supabase (PostgreSQL)  
- **Authentication:** Clerk Auth  
- **Deployment:** Vercel  
- **Security:** WAF, CSP, X-Frame-Options, HSTS, structured logging  
- **AI Agents:** OpenAI GPT models  

---

## Key Features
- **Secure Authentication:** Users can log in and manage profiles securely.  
- **Real-time Threat Monitoring:** Detects SQL injection, XSS, bot traffic, and other attack vectors.  
- **AI-Driven Interactions:** Conversational persona agent answers questions about skills, experience, and portfolio content.  
- **Content Management:** AI-assisted automated content creation and project documentation.  
- **Analytics Dashboard:** Visualizes attack patterns, blocked threats, and system performance.  
- **Audit Logging:** All security events are logged for transparency and accountability.  

---

## AI Agents Architecture
- **Persona Agent:** Digital twin interactions, conversational AI, skill representation  
- **Security Guardian:** Threat detection, SQL/XSS detection, prompt injection prevention, blocking malicious inputs  
- **Content Creator:** Blog/project management, AI-powered markdown generation, MCP tool support  
- **Threat Analytics:** Security insights, pattern analysis, dashboard metrics, attack predictions  
- **Audit Logger:** Event logging, structured logs, real-time critical alerts  
- All agents work together securely, providing an interactive, self-defending portfolio experience.  

---

## Database Structure
- **security_events:** Logs all security events (severity, threat type, source IP, actions)  
- **blog_posts:** Stores blog content, slugs, tags, and authors  
- **projects:** Portfolio projects, tech stacks, GitHub/live URLs, README content  
- **threat_metrics_daily:** Materialized view for analytics dashboards  
- **Security:** Row-level security ensures only authorized users or system roles can access or insert data  

---

## Contributors
- **Phuntshok Wangdruk:** Backend / AI Agents  
- **Victor Kamanja:** Frontend Developer / PRD File  
