# Data Refinement Log

This log documents dataset cleaning, prompt structure refinements, and API usage reductions that contributed to Week 4 performance improvements.

## Goals
- Improve response accuracy by curating and de-duplicating training/reference data
- Reduce latency by simplifying prompts and minimizing external calls
- Lower error rates by removing ambiguous or conflicting entries

## Guidelines
- No sensitive or proprietary data included; redact PII.
- Maintain traceability: note sources and commit SHAs where applicable.
- Validate changes against test prompts and sandbox routes.

## Change Log

### 2026-02-10 — Week 4 Refinement Pass
- Prompt structure
  - Consolidated system instructions to reduce token count
  - Streamlined tool selection hints; removed redundant sections
- Dataset cleaning
  - Removed outdated examples that conflicted with current agent behavior
  - Deduplicated overlapping Q&A entries and corrected mislabeled samples
  - Normalized formatting (headings, lists) for consistent parsing
- API usage
  - Reduced chained calls where a single call suffices
  - Deferred non-critical telemetry writes (batch/async where safe)

#### Impact (from performance-comparison.md)
- Response time: 4.2s → 2.1s
- Accuracy: Moderate → High
- Errors: Frequent fallback replies → Rare

## Validation
- Test suites: Persona non-sandbox prompts, sandbox SQL/XSS/rate-limit inputs
- Metrics captured: p50/p95/p99 latency, RPS, 4xx/5xx rates
- Notes: Tail latency improved when logging was batched and prompts were simplified

## Known Risks
- Over-simplification of prompts could reduce nuance in complex answers
- Deferred writes must preserve audit integrity (ensure eventual consistency)

## Next Actions
- Add small benchmark runners (k6/autocannon) to CI for preview deployments
- Cross-link this log from README and the performance document for discoverability
- Continue incremental dataset curation with clear commit messages

See also: `performance-comparison.md`.
