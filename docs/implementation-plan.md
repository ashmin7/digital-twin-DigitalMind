# IMPLEMENTATION PLAN
## Digital Twin III – Cyber-Hardened Portfolio
### Version 1.0 (2026-01-30)

---

This plan operationalizes the Technical Design (`docs/design.md`) and PRD (`docs/prd.md`) into concrete milestones, tasks, and acceptance criteria. It is intended for day-to-day execution and tracking.

## 1. Scope & Objectives

- Deliver a production-grade, cyber-hardened portfolio with threat detection, auditing, and a real-time security dashboard.
- Align implementation to OWASP Top 10 and the architecture in `docs/design.md`.
- Provide CI/CD, observability, and rollback readiness.

## 2. Environments & Prerequisites

- GitHub repository: ashmin7/digital-twin-DigitalMind
- Hosting: Vercel (preview + production)
- Database: Supabase (PostgreSQL, RLS, pgvector)
- Auth: Clerk (Next.js SDK)
- Secrets in GitHub Actions: VERCEL_TOKEN, ORG_ID, PROJECT_ID, CLERK_SECRET_KEY, DATABASE_URL, OPENAI_API_KEY, UPSTASH_REDIS_REST_URL, UPSTASH_REDIS_REST_TOKEN
- Local tooling: Node.js 20, pnpm or npm, GitHub CLI (`gh`)

## 3. Work Breakdown Structure (WBS)

### Phase 1: Foundation (Weeks 1–2)
- Next.js 16 App Router scaffold (TypeScript, ESLint, Prettier)
- Base pages: Home, About, Projects, Auth
- Supabase project + schema: users, projects, security_logs, threat_metrics_daily
- Clerk auth: sign-in/up, session handling, server-side verification
- .env management and secret placeholders

Acceptance:
- App builds and runs locally
- Supabase tables created; Clerk auth functional
- Basic pages render behind secure HTTPS locally (dev cert ok)

### Phase 2: Security Layer (Weeks 3–4)
- Middleware for headers (CSP, HSTS, X-Frame-Options, nosniff)
- Zod input validation for APIs
- Rate limiting via Upstash Redis (per-IP/user)
- WAF configuration (Vercel settings) and initial ruleset
- Structured security logging to `security_logs`

Acceptance:
- Requests show secure headers
- Malicious payloads blocked/logged (SQLi/XSS attempt evidence)
- Rate-limited endpoints return 429 and log event

### Phase 3: Monitoring & Dashboard (Weeks 5–6)
- Real-time security dashboard (Chart.js/SWR)
- Audit log viewer with filters and pagination
- Supabase Realtime subscriptions for new events
- Threat metrics aggregation + daily materialized view refresh job

Acceptance:
- Dashboard shows totals, breakdowns, and time series
- Log viewer lists events with severity, IP, threat type
- Verified realtime updates on simulated events

### Phase 4: AI Integration (Weeks 7–8)
- Enable pgvector; create HNSW index on `projects.embedding`
- Embedding generation pipeline (OpenAI Embeddings)
- Semantic search API + UI with relevance scoring

Acceptance:
- Top-k search results by cosine similarity > threshold
- Index utilization confirmed; latency under targets

### Phase 5: Testing & Hardening (Weeks 9–10)
- Unit + integration tests for APIs and middleware
- Security tests: injection, XSS, brute-force simulation
- Performance and load tests (95th percentile API < 500ms)
- Final OWASP alignment review

Acceptance:
- Tests pass in CI
- Documented evidence of blocked attempts
- Sign-off on OWASP checklist

## 4. Detailed Tasks (Checklist)

Frontend
- [ ] Scaffold Next.js App Router, Tailwind, layout and routes
- [ ] Auth pages using Clerk components
- [ ] Security dashboard (charts, summaries, timeseries)
- [ ] Audit log viewer (filters, pagination, RLS-safe queries)
- [ ] Projects page with semantic search UI

Backend/APIs
- [ ] Middleware: headers, JWT verification, request ID
- [ ] Rate limit utility (Upstash Redis)
- [ ] /api/security/logs (admin)
- [ ] /api/security/metrics (admin)
- [ ] /api/profile (user)
- [ ] /api/ai/embed (admin)
- [ ] /api/ai/search (public)

Database
- [ ] Create `users`, `projects`, `security_logs` tables
- [ ] Materialized view `threat_metrics_daily`
- [ ] RLS policies for sensitive tables
- [ ] pgvector enabled and indexed

Observability
- [ ] Structured logging (JSON), request IDs
- [ ] Alerts on CRITICAL events
- [ ] Dashboard data validation

CI/CD
- [ ] GitHub Actions: test, lint, security scan, deploy
- [ ] Vercel previews per PR
- [ ] Secrets populated; environment mappings

Docs
- [ ] Keep `docs/design.md` updated
- [ ] Maintain this implementation plan with progress
- [ ] Add runbooks: incident response, rollback

## 5. Testing Strategy

- Unit tests for validation, utilities, and components
- Integration tests for API routes (authz, rate limits, logging)
- Security test suite: SQLi/XSS payloads, brute-force, bot behavior
- Load tests (k6 or Artillery) for key APIs
- E2E smoke tests for sign-in, profile update, search

## 6. CI/CD Pipeline

- On PR: run tests, lint, SAST; produce Vercel preview
- On main merge: build, security scan, deploy to production
- Health checks + automated rollback if failure detected

## 7. Rollback & Recovery

- Application: revert commit/PR; redeploy previous artifact
- Database: use Supabase point-in-time restore or backups
- Config: maintain versioned environment configs; document changes

## 8. Acceptance Criteria Summary

- Publicly accessible portfolio deployed via Vercel
- Defensive controls active: WAF, headers, auth, rate limiting
- Logs show at least one blocked threat and system response
- Evidence of SQL injection and bot mitigation
- HTTPS enforced with secure headers
- AI-assisted development evidence (agents, commits, PRs)

## 9. Ownership & RACI (Placeholders)

- Product/Tech Lead: Ashmin Aryal (approvals, releases)
- Backend & AI Agents: Phuntshok Wangdruk (APIs, embeddings, security)
- Frontend & PRD: Victor Kamanja (UI, dashboard, docs)
- Reviewer: Team3 (peer reviews, QA)

## 10. Links

- Design Document: ./design.md
- PRD: ./prd.md
- Repository: https://github.com/ashmin7/digital-twin-DigitalMind

