# Performance Comparison

## Overview
This document captures comparative performance characteristics of the Digital Twin III portfolio across environments and routes. The focus is on:
- App routes: Chat and agent orchestration endpoints
- Sandbox routes: `/sandbox/sql`, `/sandbox/xss`, `/sandbox/rate-limit`
- Security instrumentation: ArcJet WAF, Supabase logging

We aim to track latency, throughput, error rates, and security overhead.

## Test Environments
- Local: Windows 10/11, Node.js 20.x, Next.js app dev server
- Cloud: Vercel (Production), Supabase (managed Postgres), ArcJet (WAF)

## Metrics Collected
- Latency: p50, p90, p95, p99 (ms)
- Throughput: requests per second (RPS)
- Error rate: 4xx/5xx percentage
- Security overhead: additional latency introduced when detection and logging are active

## Scenarios
1. Persona Agent Chat (non-sandbox): normal traffic with rate limiting
2. Sandbox SQL: input reflection with sanitization and parameterized query demo
3. Sandbox XSS: CSP enforcement and output encoding demo
4. Sandbox Rate Limit: high-frequency requests triggering 429

## Methodology
- Load tools: `k6` or `autocannon` for HTTP load generation
- Duration: 60s per scenario, ramping from low to moderate RPS
- Payloads:
  - Chat: short user prompts (non-malicious)
  - SQL: typical SQL injection strings and safe equivalents
  - XSS: common `<script>` and event handler patterns and safe equivalents
  - Rate-limit: bursts from same IP
- Sampling: capture response time distributions and status codes

## Results (Placeholder)
| Scenario | Env     | p50 | p95 | p99 | RPS | Error % | Notes |
|---------|---------|-----|-----|-----|-----|---------|-------|
| Chat    | Local   | TBD | TBD | TBD | TBD | TBD     | Dev server baseline |
| Chat    | Vercel  | TBD | TBD | TBD | TBD | TBD     | Production caching/CDN effects |
| SQL     | Local   | TBD | TBD | TBD | TBD | TBD     | Sanitization overhead |
| SQL     | Vercel  | TBD | TBD | TBD | TBD | TBD     | WAF + logging overhead |
| XSS     | Local   | TBD | TBD | TBD | TBD | TBD     | CSP header validation |
| XSS     | Vercel  | TBD | TBD | TBD | TBD | TBD     | CDN + headers propagation |
| RateLim | Local   | TBD | TBD | TBD | TBD | TBD     | 429 behavior consistency |
| RateLim | Vercel  | TBD | TBD | TBD | TBD | TBD     | 429, audit log insertion |

## Observations (to be filled)
- Impact of ArcJet detection and Supabase inserts on tail latency
- Differences between dev server vs serverless runtime in Vercel
- Rate limiting consistency across geographies

## Recommendations (iterative)
- Consider response caching for non-sensitive endpoints
- Use CONCURRENT indexes and batched logging for heavy traffic
- Monitor Supabase table bloat and refresh materialized views off-peak

## Next Steps
- Replace placeholders with measured values from k6/autocannon runs
- Add CI job to run lightweight perf checks against preview deployments
- Visualize metrics in the security dashboard alongside threat telemetry
