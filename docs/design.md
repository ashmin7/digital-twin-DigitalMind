# TECHNICAL DESIGN DOCUMENT
## Digital Twin III – Cyber-Hardened Portfolio
### Version 1.0

---

**Document ID:** DT3-TDD-2026-001  
**Date:** January 27, 2026  
**Classification:** Confidential  
**Status:** Ready for Implementation

---

## 1. Executive Summary

This Technical Design Document (TDD) specifies the complete architecture and implementation details for the Digital Twin III – Cyber-Hardened Portfolio project. The system transforms a traditional web portfolio into a cyber-secured, monitored, and attack-resilient digital asset that demonstrates real-world threat defense capabilities.

### Primary Objectives

- Deploy a production-grade portfolio with enterprise-level security controls
- Detect and block real cyber threats including SQL injection, XSS, and bot attacks
- Implement comprehensive monitoring and audit logging for security analysis
- Demonstrate security maturity through real-time dashboards and metrics
- Align with OWASP Top 10 security best practices

### Technology Stack

| Component | Technology |
|-----------|------------|
| **Frontend** | Next.js 16 with TypeScript, React Server Components |
| **Backend** | Node.js 20, Next.js API Routes, Serverless Functions |
| **Database** | Supabase (PostgreSQL 15+) with Row Level Security |
| **Auth** | Clerk Authentication with Next.js SDK |
| **Hosting** | Vercel Edge Network with WAF |
| **Security** | Vercel WAF, Custom Middleware, Rate Limiting, Security Headers |

---

## 2. System Architecture

### 2.1 High-Level Architecture

The system follows a modern serverless architecture with multiple security layers:

1. **Presentation Layer:** Next.js 16 React application with Server Components and Client Components
2. **Security Layer:** Vercel WAF, Custom Middleware, Rate Limiting, Input Validation
3. **Application Layer:** Next.js API Routes and Server Actions
4. **Authentication Layer:** Clerk JWT-based authentication and session management
5. **Data Layer:** Supabase PostgreSQL with Row Level Security and pgvector for AI embeddings
6. **Monitoring Layer:** Real-time security dashboard, audit logging, and telemetry

### 2.2 Architecture Diagram

```
┌──────────────────────────────────────────────────────┐
│             User Browser / Client                    │
└─────────────────────┬────────────────────────────────┘
                      │ HTTPS
                      ▼
┌──────────────────────────────────────────────────────┐
│         Vercel Edge Network (CDN + WAF)              │
│  • DDoS Protection                                   │
│  • Bot Detection                                     │
│  • Geo-blocking                                      │
│  • Rate Limiting                                     │
└─────────────────────┬────────────────────────────────┘
                      │
                      ▼
┌──────────────────────────────────────────────────────┐
│       Next.js Middleware (Security Layer)            │
│  • Request Validation                                │
│  • Security Headers (CSP, HSTS, X-Frame-Options)     │
│  • Session Verification (Clerk)                      │
│  • Logging & Telemetry                               │
└─────────────────────┬────────────────────────────────┘
                      │
          ┌───────────┴──────────┐
          ▼                      ▼
┌───────────────────┐  ┌───────────────────────┐
│   Next.js Pages   │  │   Next.js API Routes  │
│  • Portfolio UI   │  │  • /api/security/*    │
│  • Dashboard      │  │  • /api/profile/*     │
│  • Auth Pages     │  │  • /api/logs/*        │
└─────────┬─────────┘  └────────┬──────────────┘
          │                     │
          └──────────┬──────────┘
                     ▼
    ┌────────────────────────────────┐
    │     Clerk Authentication       │
    │  • JWT Validation              │
    │  • Session Management          │
    │  • User Metadata               │
    └────────────────┬───────────────┘
                     ▼
    ┌────────────────────────────────┐
    │   Supabase PostgreSQL          │
    │  • User Profiles               │
    │  • Security Logs               │
    │  • Attack Telemetry            │
    │  • Portfolio Content           │
    │  • AI Embeddings (pgvector)    │
    └────────────────────────────────┘
```

### 2.3 Security Architecture

The security architecture implements defense-in-depth with multiple layers:

#### 2.3.1 Layer 1: Network Security (Vercel WAF)

- **DDoS Protection:** Automatic detection and mitigation of volumetric attacks
- **Bot Detection:** Challenge-response for automated bot traffic
- **Geo-blocking:** Optional blocking of high-risk geographic regions
- **IP Reputation:** Blocking of known malicious IP addresses

#### 2.3.2 Layer 2: Application Security (Middleware)

- **Input Validation:** Server-side validation of all user inputs using Zod schemas
- **XSS Prevention:** Content Security Policy and output encoding
- **CSRF Protection:** SameSite cookies and CSRF tokens
- **Rate Limiting:** Per-IP and per-user rate limits using Upstash Redis

#### 2.3.3 Layer 3: Data Security (Database)

- **SQL Injection Prevention:** Parameterized queries and prepared statements
- **Row Level Security:** PostgreSQL RLS policies for multi-tenant data isolation
- **Encryption at Rest:** AES-256 encryption for sensitive data
- **Encryption in Transit:** TLS 1.3 for all database connections

---

## 3. Component Breakdown

### 3.1 Frontend Components

| Component | Purpose | Technology |
|-----------|---------|------------|
| Portfolio Page | Main portfolio showcase | Next.js App Router, RSC |
| Security Dashboard | Real-time threat monitoring | React, Chart.js, SWR |
| Auth Components | Sign in, sign up, profile | Clerk React Components |
| Audit Log Viewer | Security event history | React, Tanstack Table |
| Profile Manager | User profile editing | React Hook Form, Zod |

### 3.2 Backend Components

| API Route | Purpose | Auth Required |
|-----------|---------|---------------|
| /api/security/logs | Retrieve security logs | Yes (Admin) |
| /api/security/metrics | Get security metrics | Yes (Admin) |
| /api/profile | User profile CRUD | Yes (User) |
| /api/ai/embed | Generate embeddings | Yes (Admin) |
| /api/ai/search | Semantic search | No |

---

## 4. Data Flow

### 4.1 Authentication Flow

1. User initiates sign-in from portfolio page
2. Clerk authentication widget handles OAuth/email flow
3. Clerk issues JWT with user claims and session ID
4. JWT stored in HttpOnly cookie (prevents XSS)
5. Middleware validates JWT on each request
6. User context available in API routes and server components

### 4.2 Security Event Flow

1. Suspicious request detected by middleware or WAF
2. Event metadata extracted (IP, user agent, payload, threat type)
3. Security logger creates structured log entry
4. Log entry persisted to Supabase security_logs table
5. Real-time notification sent to security dashboard via Supabase Realtime
6. Dashboard updates metrics and displays alert
7. Request blocked or challenged based on threat severity

### 4.3 AI-Powered Search Flow

1. User submits search query via portfolio interface
2. Query sent to /api/ai/search endpoint
3. OpenAI Embeddings API generates vector representation
4. pgvector performs cosine similarity search in Supabase
5. Top-k relevant results returned with similarity scores
6. Results rendered in search UI with highlighting

---

## 5. API Design

### 5.1 Security Logs API

```
GET /api/security/logs
Authorization: Bearer <JWT>

Query Parameters:
  - startDate: ISO8601 timestamp
  - endDate: ISO8601 timestamp
  - threatType: sql_injection|xss|bot|brute_force
  - limit: number (default: 100, max: 1000)
  - offset: number (default: 0)

Response 200:
{
  "logs": [
    {
      "id": "uuid",
      "timestamp": "2026-01-27T10:30:00Z",
      "threatType": "sql_injection",
      "ipAddress": "192.0.2.1",
      "userAgent": "Mozilla/5.0...",
      "requestPath": "/api/profile",
      "payload": "id=1 OR 1=1",
      "blocked": true,
      "severity": "high"
    }
  ],
  "total": 150,
  "limit": 100,
  "offset": 0
}
```

### 5.2 Security Metrics API

```
GET /api/security/metrics
Authorization: Bearer <JWT>

Query Parameters:
  - timeRange: 24h|7d|30d|90d

Response 200:
{
  "totalRequests": 15420,
  "blockedRequests": 234,
  "threatBreakdown": {
    "sql_injection": 45,
    "xss": 32,
    "bot": 156,
    "brute_force": 1
  },
  "topAttackIPs": [
    { "ip": "192.0.2.1", "count": 89 },
    { "ip": "198.51.100.5", "count": 67 }
  ],
  "timeSeriesData": [
    { "timestamp": "2026-01-27T00:00:00Z", "blocked": 12 },
    { "timestamp": "2026-01-27T01:00:00Z", "blocked": 8 }
  ]
}
```

### 5.3 Profile API

```
GET /api/profile
Authorization: Bearer <JWT>

Response 200:
{
  "id": "uuid",
  "clerkUserId": "user_xxx",
  "name": "John Doe",
  "email": "john@example.com",
  "bio": "Cybersecurity professional...",
  "skills": ["Security", "React", "Node.js"],
  "projects": [...],
  "updatedAt": "2026-01-27T10:00:00Z"
}

PUT /api/profile
Authorization: Bearer <JWT>
Content-Type: application/json

Body:
{
  "name": "John Doe",
  "bio": "Updated bio...",
  "skills": ["Security", "React", "Python"]
}
```

---

## 6. Database Schema

### 6.1 users Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique identifier |
| clerk_user_id | VARCHAR(255) | UNIQUE, NOT NULL | Clerk user ID |
| email | VARCHAR(255) | UNIQUE, NOT NULL | User email |
| name | VARCHAR(255) | NOT NULL | Display name |
| bio | TEXT | NULL | User biography |
| skills | TEXT[] | DEFAULT '{}' | Skills array |
| created_at | TIMESTAMPTZ | DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() | Last update |

### 6.2 security_logs Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique log ID |
| timestamp | TIMESTAMPTZ | DEFAULT NOW() | Event time |
| threat_type | VARCHAR(50) | NOT NULL | Attack type |
| severity | VARCHAR(20) | NOT NULL | low\|medium\|high\|critical |
| ip_address | INET | NOT NULL | Source IP |
| user_agent | TEXT | NULL | Browser/client |
| request_path | TEXT | NOT NULL | Target endpoint |
| payload | JSONB | NULL | Attack payload |
| blocked | BOOLEAN | DEFAULT FALSE | Was blocked? |
| user_id | UUID | FK(users.id) | Associated user |

### 6.3 projects Table

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | UUID | PRIMARY KEY | Unique project ID |
| user_id | UUID | FK(users.id) | Owner |
| title | VARCHAR(255) | NOT NULL | Project name |
| description | TEXT | NULL | Description |
| embedding | VECTOR(1536) | NULL | AI embedding |
| created_at | TIMESTAMPTZ | DEFAULT NOW() | Creation time |
| updated_at | TIMESTAMPTZ | DEFAULT NOW() | Last update |

**Indexes:**
- `CREATE INDEX idx_security_logs_timestamp ON security_logs(timestamp DESC);`
- `CREATE INDEX idx_security_logs_threat_type ON security_logs(threat_type);`
- `CREATE INDEX idx_security_logs_ip ON security_logs(ip_address);`
- `CREATE INDEX idx_projects_embedding ON projects USING hnsw (embedding vector_cosine_ops);`

---

## 7. Authentication & Authorization

### 7.1 Clerk Integration

Clerk provides a complete authentication solution with the following features:

- **Multiple Authentication Methods:** Email/password, OAuth (Google, GitHub), magic links
- **Session Management:** JWT-based sessions with automatic refresh
- **Multi-Factor Authentication:** Optional 2FA via SMS or authenticator apps
- **User Management:** Built-in user profile and metadata management
- **Security Features:** Rate limiting, bot detection, and attack protection

### 7.2 Role-Based Access Control (RBAC)

| Role | Permissions | Use Case |
|------|-------------|----------|
| Admin | Full access to all features, security logs, analytics | Portfolio owner/manager |
| User | View portfolio, update own profile | Registered visitors |
| Anonymous | View public portfolio content only | Non-authenticated visitors |

**Implementation:**

```typescript
// Middleware authorization check
export async function checkRole(userId: string, requiredRole: string) {
  const user = await db.users.findUnique({ where: { clerkUserId: userId } });
  return user?.role === requiredRole;
}

// API route protection
if (!await checkRole(auth().userId, 'admin')) {
  return new Response('Unauthorized', { status: 403 });
}
```

---

## 8. AI Integration Points

### 8.1 OpenAI Embeddings for Semantic Search

The system uses OpenAI's text-embedding-ada-002 model to generate vector embeddings for portfolio content, enabling semantic search capabilities.

#### 8.1.1 Embedding Generation Flow

1. Admin creates or updates project content
2. System concatenates title + description into embedding text
3. API call to OpenAI Embeddings endpoint
4. 1536-dimension vector returned
5. Vector stored in projects.embedding column (pgvector)
6. HNSW index created for fast similarity search

**Implementation:**

```typescript
import OpenAI from 'openai';

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

async function generateEmbedding(text: string): Promise<number[]> {
  const response = await openai.embeddings.create({
    model: 'text-embedding-ada-002',
    input: text,
  });
  return response.data[0].embedding;
}
```

#### 8.1.2 Search Query Flow

1. User submits natural language query
2. Query text converted to embedding vector via OpenAI
3. pgvector performs cosine similarity search against indexed embeddings
4. Top-k results returned with similarity scores
5. Results ranked and returned to user interface

**SQL Query:**

```sql
SELECT 
  id, 
  title, 
  description,
  1 - (embedding <=> $1::vector) as similarity
FROM projects
WHERE 1 - (embedding <=> $1::vector) > 0.7
ORDER BY similarity DESC
LIMIT 10;
```

### 8.2 AI-Powered Threat Detection (Future Enhancement)

Future iterations may include machine learning models for:

- Anomaly detection in access patterns
- Advanced bot detection using behavioral analysis
- Predictive threat intelligence
- Natural language threat reporting

---

## 9. Security Controls

### 9.1 Input Validation

All user inputs are validated using Zod schemas before processing:

```typescript
import { z } from 'zod';

// Profile Update Schema
const profileSchema = z.object({
  name: z.string().min(1).max(255),
  bio: z.string().max(2000).optional(),
  skills: z.array(z.string()).max(20),
  email: z.string().email()
});

// Validate input
const result = profileSchema.safeParse(requestBody);
if (!result.success) {
  return new Response(JSON.stringify(result.error), { status: 400 });
}
```

### 9.2 SQL Injection Prevention

- **Parameterized Queries:** All database queries use parameterized statements
- **ORM Usage:** Supabase client library handles query sanitization
- **Input Validation:** Zod schemas reject malicious input patterns
- **Row Level Security:** PostgreSQL RLS enforces data isolation

```typescript
// Parameterized query example
const { data, error } = await supabase
  .from('users')
  .select('*')
  .eq('email', userEmail); // Safe - parameterized
```

### 9.3 Cross-Site Scripting (XSS) Prevention

- **Content Security Policy:** Strict CSP headers block inline scripts
- **React Auto-Escaping:** React automatically escapes dynamic content
- **DOMPurify:** Sanitize any user-generated HTML content
- **Validation:** Reject input containing script tags or event handlers

### 9.4 Security Headers

| Header | Value |
|--------|-------|
| Content-Security-Policy | default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' |
| X-Frame-Options | DENY |
| X-Content-Type-Options | nosniff |
| Strict-Transport-Security | max-age=31536000; includeSubDomains |
| X-XSS-Protection | 1; mode=block |
| Referrer-Policy | strict-origin-when-cross-origin |

**Middleware Implementation:**

```typescript
// middleware.ts
export function middleware(request: NextRequest) {
  const response = NextResponse.next();
  
  response.headers.set('X-Frame-Options', 'DENY');
  response.headers.set('X-Content-Type-Options', 'nosniff');
  response.headers.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  response.headers.set('Content-Security-Policy', "default-src 'self'; script-src 'self'");
  
  return response;
}
```

### 9.5 Rate Limiting

Rate limiting implemented using Upstash Redis:

| Endpoint | Limit | Window |
|----------|-------|--------|
| Authentication | 5 requests | 15 minutes |
| API Routes | 100 requests | 1 hour |
| Search Queries | 20 requests | 1 minute |

**Implementation:**

```typescript
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(100, '1 h'),
});

const { success } = await ratelimit.limit(ip);
if (!success) {
  return new Response('Too Many Requests', { status: 429 });
}
```

---

## 10. Non-Functional Requirements

### 10.1 Performance

- **Page Load Time:** < 2 seconds on 4G connection
- **Time to Interactive (TTI):** < 3 seconds
- **First Contentful Paint (FCP):** < 1.8 seconds
- **API Response Time:** < 500ms for 95th percentile
- **Database Query Time:** < 100ms for indexed queries

### 10.2 Scalability

- **Concurrent Users:** Support up to 1,000 concurrent users
- **Serverless Architecture:** Auto-scaling via Vercel Edge Functions
- **Database Connection Pooling:** Supabase connection pooler with max 100 connections
- **CDN Caching:** Static assets cached at edge locations globally

### 10.3 Reliability

- **Uptime SLA:** 99.9% availability target
- **Error Rate:** < 0.1% error rate for API requests
- **Failover:** Automatic failover via Vercel's multi-region deployment
- **Backup Strategy:** Daily automated backups with 30-day retention

### 10.4 Observability

- **Logging:** Structured JSON logs with request IDs
- **Monitoring:** Real-time dashboards for security metrics
- **Alerting:** Automated alerts for critical security events
- **Tracing:** Distributed tracing for request flows

---

## 11. Deployment Architecture

### 11.1 Environment Configuration

| Environment | Purpose | URL Pattern |
|-------------|---------|-------------|
| Development | Local development and testing | localhost:3000 |
| Staging | Pre-production testing | staging.digitaltwin.dev |
| Production | Live production environment | digitaltwin.dev |

### 11.2 CI/CD Pipeline

Automated deployment pipeline using GitHub Actions and Vercel:

1. **Code Push:** Developer pushes code to GitHub repository
2. **Automated Tests:** GitHub Actions runs unit tests, integration tests, and security scans
3. **Build:** Next.js application built with production optimizations
4. **Security Scan:** SAST and dependency vulnerability scanning
5. **Deploy Preview:** Vercel creates preview deployment for pull requests
6. **Production Deploy:** Merge to main triggers production deployment
7. **Health Check:** Automated health checks validate deployment

**GitHub Actions Workflow:**

```yaml
name: Deploy

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npm test
      - run: npm run lint
      
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Snyk Security Scan
        uses: snyk/actions/node@master
        
  deploy:
    needs: [test, security]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: amondnet/vercel-action@v25
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.ORG_ID }}
          vercel-project-id: ${{ secrets.PROJECT_ID }}
```

### 11.3 Environment Variables

| Variable | Description |
|----------|-------------|
| NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY | Clerk public key for client-side auth |
| CLERK_SECRET_KEY | Clerk secret key for server-side auth |
| DATABASE_URL | Supabase PostgreSQL connection string |
| OPENAI_API_KEY | OpenAI API key for embeddings |
| UPSTASH_REDIS_REST_URL | Upstash Redis URL for rate limiting |
| UPSTASH_REDIS_REST_TOKEN | Upstash Redis auth token |

---

## 12. Implementation Phases

### 12.1 Phase 1: Foundation (Weeks 1-2)

- Initialize Next.js 16 project with TypeScript
- Set up Supabase database and schema
- Configure Clerk authentication
- Implement basic portfolio UI components
- Set up Vercel deployment pipeline

### 12.2 Phase 2: Security Implementation (Weeks 3-4)

- Configure Vercel WAF rules
- Implement security middleware (headers, validation, rate limiting)
- Create security logging infrastructure
- Implement SQL injection and XSS prevention
- Set up Row Level Security policies

### 12.3 Phase 3: Monitoring & Dashboard (Weeks 5-6)

- Build security dashboard UI
- Implement real-time security metrics
- Create audit log viewer
- Set up attack simulation tools
- Configure alerting and notifications

### 12.4 Phase 4: AI Integration (Weeks 7-8)

- Integrate OpenAI Embeddings API
- Enable pgvector extension in Supabase
- Implement semantic search functionality
- Create embedding generation pipeline
- Build search UI with relevance scoring

### 12.5 Phase 5: Testing & Hardening (Weeks 9-10)

- Penetration testing and vulnerability assessment
- Performance optimization and load testing
- Security audit and OWASP compliance verification
- Documentation and deployment guides
- Production deployment and monitoring

---

## 13. Appendix

### 13.1 Technology Stack Versions

| Technology | Version |
|------------|---------|
| Next.js | 16.x (latest stable) |
| Node.js | 20.x LTS |
| TypeScript | 5.x |
| React | 19.x |
| PostgreSQL | 15.x (via Supabase) |
| Clerk SDK | @clerk/nextjs ^5.x |

### 13.2 Key Dependencies

- @clerk/nextjs - Authentication
- @supabase/supabase-js - Database client
- zod - Schema validation
- @upstash/redis - Rate limiting
- openai - AI embeddings
- chart.js - Dashboard visualizations
- react-hook-form - Form management
- tailwindcss - Styling
- swr - Data fetching and caching

### 13.3 Reference Documentation

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Next.js Security: https://nextjs.org/docs/app/building-your-application/configuring/content-security-policy
- Clerk Documentation: https://clerk.com/docs
- Supabase Docs: https://supabase.com/docs
- Vercel Security: https://vercel.com/docs/security
- OpenAI Embeddings: https://platform.openai.com/docs/guides/embeddings

### 13.4 Glossary

- **CSP:** Content Security Policy
- **CSRF:** Cross-Site Request Forgery
- **DDoS:** Distributed Denial of Service
- **HNSW:** Hierarchical Navigable Small World (vector index algorithm)
- **JWT:** JSON Web Token
- **OWASP:** Open Web Application Security Project
- **RBAC:** Role-Based Access Control
- **RLS:** Row Level Security
- **RSC:** React Server Components
- **SAST:** Static Application Security Testing
- **SLA:** Service Level Agreement
- **TLS:** Transport Layer Security
- **TTI:** Time to Interactive
- **WAF:** Web Application Firewall
- **XSS:** Cross-Site Scripting

---

## 14. Document Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | January 27, 2026 | DigitalMind Team 3 | Initial release - Complete technical design specification |

---

## Document Status: APPROVED FOR IMPLEMENTATION

**Next Steps:**
1. Review and approve this technical design document
2. Provision infrastructure (Vercel, Supabase, Clerk accounts)
3. Initialize Next.js project structure
4. Begin Phase 1 implementation

**Approval Sign-off:**
- [ ] Technical Lead Review
- [ ] Security Review
- [ ] Architecture Review
- [ ] Stakeholder Approval

---

**END OF DOCUMENT**

