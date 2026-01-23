# Digital Twin III – Cyber-Hardened Portfolio PRD

## 1. Project Overview
The goal of the Digital Twin III – Cyber-Hardened Portfolio bootcamp is to transform a personal web application portfolio into a cyber-secured, monitored, and attack-resilient digital asset. The project demonstrates an individual’s ability to defend, monitor, and continuously harden a deployed portfolio against real-world threats such as SQL injection, authentication bypass, automated bot attacks and other security vulnerabilities. This PRD is intended for AI tools like Copilot, Claude, or GPT to help generate secure, standards-compliant portfolio code along with the necessary security controls.

By the end of the program, the portfolio must not only host professional identity and content, but also:

  - Detect and block real cyber threats in real time;
  - Analyse attacker behaviours;
  - Provide audit logs and metrics to demonstrate resilience;
  - Communicate security maturity to prospective employers.

## 2. AI Study URLs

These URLs will provide context to AI tools (Copilot, Claude, GPT agents) so they can generate relevant and secure code.

## AI Study URLs
1. https://www.owasp.org — OWASP Top 10 Application Security Risks  
2. https://nextjs.org/docs — Next.js official documentation  
3. https://vercel.com/docs — Vercel deployment & security guides  
4. https://supabase.com/docs — Supabase (PostgreSQL backend) docs  
5. https://developer.mozilla.org — Web security best practices (CSP, CORS)  
6. https://portswigger.net/web-security — Web security attack & defense techniques

## 3. Technical Requirements
Technology stack and security tools the portfolio will use.
  - Frontend: Next.js 16 (latest stable) with TypeScript  
  - Backend: Node.js 20 / API routes  
  - Database: Supabase (latest stable PostgreSQL)  
  - Deployment: Vercel  
  - Authentication: Clerk (Next.js SDK) for secure login and session management, or 0th/Supabase Auth
  - Web Application Firewall (WAF): Configured for common exploits  
  - Logging & Monitoring: Real-time access logs + attack telemetry  
  - Secure Headers: CSP, X-Frame-Options, HSTS  

## 4. Functional Requirements

  - Users can securely log in and manage their profile using Clerk authentication
  - The portfolio UI loads securely using HTTPS with strict headers.  
  - APIs reject unauthenticated or malicious requests.  
  - Real-time logs capture potential attack attempts.  
  - Defensive layers block SQL injection, XSS, brute force, and bot traffic.  
  - Security controls are demonstrable via dashboards or reports, including a real-time        security dashboard showing login attempts, blocked attacks, and traffic patterns.
  - Real-time security dashboard showing login attempts, blocked attacks, and traffic patterns.
  - Session and role management handled via Clerk dashboard.

## 5. Non-Functional Requirements
  
  - Security: Must align with OWASP Top 10 best practices.  
  - Performance: Page load times under 2 seconds under normal load.  
  - Reliability: Stable deployment with minimal downtime.  
  - Auditability: Logs and telemetry must be exportable and visible.  
  - Maintainability: Code follows standard linting and formatting rules.  

## 6. Acceptance Criteria

These are the conditions that determine whether the deliverables are completed successfully.
  
  - Portfolio deployed and publicly accessible.  
  - Defensive controls are configured (WAF, secure headers, authentication).  
  - Logs show at least one logged threat attempt and the system response.  
  - Evidence of SQL injection and bot attempt mitigation.  
  - Final deployment uses HTTPS with secure header policies.
  - AI-assisted development evidence: Copilot, Claude, or GPT used to generate secure portfolio code and configurations.


## 7. Process Requirements & Workflow
Repository Setup

Team repository created: digital-twin-DigitalMind
- Public visibility
- docs/prd.md added to /docs directory
- Team Collaboration
- All team members invited with Write access
- Each member commits at least one meaningful change
- GitHub insights show distinct authors
- AI Workflows
- AI tools must be configured (Copilot, Claude, GPT integration)
- Tasks are split and assigned via ClickUp with AI-ready descriptions

## 8. Risk & Security Considerations
  - Misconfigured WAF rules blocking legitimate traffic
  - Incomplete authentication flow exposing endpoints
  - Lack of adequate logging
  - Logging may expose sensitive data if improperly stored.
  - Misconfigured authentication flow exposing endpoints → mitigated by Clerk’s secure SDK and dashboards.



## 9. Mitigations
  - Test WAF configurations in staging
  - Use secure, token-based authentication
  - Capture logs in a structured centralized format



## AI Study URLs & Research References

### Core Research Papers
1. **Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks**
   - Authors: Lewis et al. (Facebook AI)
   - URL: https://arxiv.org/abs/2005.11401
   - Application: RAG system implementation

2. **ReAct: Synergizing Reasoning and Acting in Language Models**
   - Authors: Yao et al. (Google & Princeton)
   - URL: https://arxiv.org/abs/2210.03629
   - Application: AI agent decision-making

3. **Constitutional AI: Harmlessness from AI Feedback**
   - Authors: Anthropic Research
   - URL: https://arxiv.org/abs/2212.08073
   - Application: AI safety and moderation

### Technical Guides
4. **Next.js Security Best Practices**
   - URL: https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy
   - Usage: Implementing CSP, X-Frame-Options, HSTS

5. **Supabase Vector Database Documentation**
   - URL: https://supabase.com/docs/guides/ai/vector-columns
   - Usage: Storing and querying embeddings

6. **OpenAI Embeddings API**
   - URL: https://platform.openai.com/docs/guides/embeddings
   - Usage: Text embedding generation





