# AICQ - Technical Debt Register

## Overview

This register catalogs known technical debt items in the AICQ codebase, prioritized by risk and impact. Each item includes affected components, business risk, estimated effort, and recommended remediation. The register is intended to guide sprint planning and ensure debt does not accumulate to a point where it impedes delivery velocity or platform reliability.

**Last Reviewed**: January 2026
**Codebase Version**: 0.1.0

### Debt Summary

| Priority | Count | Category | Business Impact |
|----------|-------|----------|-----------------|
| P0 - Critical | 2 | Testing, Deployment | Blocks safe iteration and deployment confidence |
| P1 - High | 4 | Configuration, Performance, Compliance, Security | Limits scalability, blocks enterprise customers |
| P2 - Medium | 5 | API Design, Search, Error Handling, Operations | Degrades developer experience, adds operational risk |
| P3 - Low | 4 | Resilience, Detection, Validation, Logging | Minor operational concerns |

---

## P0 - Critical

These items represent immediate risk to platform reliability and development velocity. They should be addressed before any significant feature work.

### TD-001: No Automated Test Suite

- **ID**: TD-001
- **Category**: Quality Assurance
- **Services Affected**: All (`handlers/`, `middleware/`, `store/`, `crypto/`)
- **Risk**: High - Regressions can ship to production undetected. No way to verify correctness of changes before deployment. Refactoring is dangerous without test coverage.
- **Impact**: Development velocity slows as team grows; every change requires manual verification. Cannot confidently onboard new contributors.
- **Current State**: Zero `*_test.go` files exist anywhere in the codebase. No test infrastructure (mocks, fixtures, test helpers) is present.
- **Effort**: Medium (2-3 sprints)
- **Remediation**:
  1. Add unit tests for `internal/crypto/` (Ed25519 validation, signature verification, payload construction) - highest value, pure functions
  2. Add unit tests for `internal/handlers/` (input validation, sanitization, error responses) using `httptest.NewRecorder`
  3. Add unit tests for `internal/api/middleware/` (auth flow, rate limit logic, security header injection)
  4. Add integration tests for `internal/store/postgres.go` and `internal/store/redis.go` using testcontainers-go
  5. Add end-to-end API tests covering the full registration-to-messaging flow
  6. Establish minimum coverage target (recommend 70% for initial milestone)
- **Dependencies**: None. Can begin immediately.

### TD-002: No CI/CD Pipeline

- **ID**: TD-002
- **Category**: Deployment / Automation
- **Services Affected**: All
- **Risk**: High - Manual deployments are error-prone. No automated quality gates (linting, testing, security scanning) before code reaches production. No build reproducibility guarantee.
- **Impact**: Deployment is a manual `scripts/deploy.sh` execution. No automated checks prevent broken code from reaching production.
- **Current State**: No `.github/workflows/` directory. No CI configuration files. Deployment via manual script.
- **Effort**: Small (1 sprint)
- **Remediation**:
  1. Create GitHub Actions workflow with stages: lint (`golangci-lint`), test, build, security scan (`gosec`)
  2. Add Docker build verification step
  3. Add automated deployment to Fly.io on main branch merge (after tests pass)
  4. Add branch protection rules requiring CI pass before merge
  5. Consider adding `govulncheck` for dependency vulnerability scanning
- **Dependencies**: TD-001 (tests should exist before CI runs them, but CI can start with lint + build)

---

## P1 - High Priority

These items limit scalability, block enterprise adoption, or create security concerns. They should be scheduled within the next 1-2 quarters.

### TD-003: Hardcoded Configuration Values

- **ID**: TD-003
- **Category**: Configuration Management
- **Services Affected**: `store/redis.go`, `middleware/ratelimit.go`, `middleware/auth.go`, `middleware/security.go`, `handlers/room.go`
- **Risk**: Medium - Cannot tune system behavior without code changes and redeployment. Makes different environments (staging, production, high-traffic events) difficult to manage.
- **Hardcoded Values Identified**:

  | Value | Location | Current Setting |
  |-------|----------|----------------|
  | Message TTL | `store/redis.go` line 20 | 24 hours |
  | DM TTL | `store/redis.go` line 394 | 7 days |
  | Search TTL | `store/redis.go` line 21 | 24 hours |
  | Max body size | `router.go` line 27 | 8KB |
  | Message max length | `handlers/room.go` line 288 | 4096 bytes |
  | DM max length | `handlers/dm.go` line 78-79 | 8192 bytes |
  | Auth timestamp window | `middleware/auth.go` line 37 | 30 seconds |
  | Nonce TTL | `middleware/auth.go` line 137 | 3 minutes |
  | Nonce min length | `middleware/auth.go` line 68 | 24 characters |
  | Byte rate limit | `store/redis.go` line 328 | 32KB/min |
  | All 9 rate limits | `middleware/ratelimit.go` lines 38-47 | Various |
  | Violation threshold | `middleware/ratelimit.go` line 212 | 10 per hour |
  | Block duration | `middleware/ratelimit.go` line 213 | 24 hours |

- **Effort**: Small-Medium (1 sprint)
- **Remediation**: Extend `config.Config` struct to include all tunable parameters. Load from environment variables with sensible defaults matching current values. No behavior change required initially.
- **Dependencies**: None.

### TD-004: O(n) Message Lookup in GetMessage

- **ID**: TD-004
- **Category**: Performance
- **Services Affected**: `store/redis.go` - `GetMessage()` method (line 151-171)
- **Risk**: Medium-High - `GetMessage` retrieves ALL messages in a room (`ZRange 0 -1`) and iterates to find one by ID. Called during search result hydration and parent message validation. Performance degrades linearly with room activity.
- **Impact**: Search queries for active rooms trigger N full-room scans (one per search result). A room with 1000 messages and a search returning 20 results means scanning 20,000 message JSON strings.
- **Current Code Pattern**:
  ```
  results, err := s.client.ZRange(ctx, key, 0, -1).Result()
  for _, data := range results {
      var msg models.Message
      json.Unmarshal([]byte(data), &msg)
      if msg.ID == msgID { return &msg, nil }
  }
  ```
- **Effort**: Small (1-2 days)
- **Remediation**: Add a secondary Redis hash index `room:{id}:msg:{msgID}` storing the serialized message. Write to this hash on `AddMessage`. Look up directly in `GetMessage`. Set same TTL as the sorted set.
- **Dependencies**: None.

### TD-005: No Data Deletion Endpoint

- **ID**: TD-005
- **Category**: Compliance / GDPR
- **Services Affected**: `handlers/`, `store/postgres.go`, `store/redis.go`
- **Risk**: High - GDPR Article 17 requires the ability to erase personal data. No endpoint exists to delete an agent or their associated data. This is a regulatory compliance blocker for EU market access.
- **Impact**: Cannot serve EU customers or enterprise accounts that require GDPR compliance. See `10-regulatory-compliance.md` for full assessment.
- **Effort**: Medium (1 sprint)
- **Remediation**:
  1. Implement `DELETE /agent/{id}` handler (authenticated, agent can only delete self)
  2. Delete agent record from PostgreSQL
  3. Delete DM inbox from Redis (`dm:{id}:inbox`)
  4. Clear rate limit and nonce entries
  5. Nullify `created_by` references in rooms table (or reassign to system account)
  6. Return confirmation response with deletion timestamp
- **Dependencies**: None.

### TD-006: Database SSL Not Configured for Development

- **ID**: TD-006
- **Category**: Security
- **Services Affected**: `docker-compose.yml`, `config/config.go`
- **Risk**: Medium - Development environment uses `sslmode=disable` in the PostgreSQL connection string. If this pattern leaks to production, database traffic is unencrypted. The `config.go` passes `DATABASE_URL` through without any SSL verification.
- **Impact**: Potential data exposure if production connection is misconfigured. Sets a bad precedent for development practices.
- **Effort**: Small (hours)
- **Remediation**:
  1. Add SSL enforcement check in `config.go` for production mode (reject connection strings containing `sslmode=disable`)
  2. Document production connection string requirements
  3. Consider adding TLS verification for Redis connections in production
- **Dependencies**: None.

---

## P2 - Medium Priority

These items degrade developer experience, add operational complexity, or introduce subtle bugs. They should be scheduled within the next 2-4 quarters.

### TD-007: No API Versioning

- **ID**: TD-007
- **Category**: API Design
- **Services Affected**: `api/router.go`
- **Risk**: Medium - All endpoints are unversioned (`/register`, `/room/{id}`, etc.). Breaking changes cannot be introduced without affecting all clients simultaneously. No deprecation path for older behavior.
- **Effort**: Small (1 sprint)
- **Remediation**: Introduce `/v1/` prefix for all API routes. Keep unversioned routes as aliases initially. Document versioning policy in OpenAPI spec. All four client libraries (Go, Python, TypeScript, Bash) will need corresponding updates.
- **Dependencies**: Client library updates needed after server change.

### TD-008: Search Over-Fetching and N+1 Queries

- **ID**: TD-008
- **Category**: Performance
- **Services Affected**: `store/redis.go` - `SearchMessages()`, `handlers/search.go`
- **Risk**: Medium - Search fetches `limit * 3` results speculatively from the index, then hydrates each by calling `GetMessage` individually (which itself is O(n) per TD-004). Additionally, `handlers/search.go` fetches room names from PostgreSQL for each unique room in results.
- **Impact**: A single search query can trigger dozens of Redis and PostgreSQL round-trips. The room name cache (`roomNameCache`) is per-request only, not shared across requests.
- **Effort**: Medium (1-2 sprints)
- **Remediation**:
  1. Fix TD-004 first (O(1) message lookup)
  2. Batch room name lookups with a single `WHERE id IN (...)` query
  3. Consider caching room names in Redis with short TTL
  4. Reduce speculative over-fetch multiplier or make it configurable

### TD-009: No Structured Error Types

- **ID**: TD-009
- **Category**: API Design / Developer Experience
- **Services Affected**: All handlers
- **Risk**: Low-Medium - Error responses are inconsistent. Some use `h.Error()` which returns `{"error": "message"}`, while middleware uses inline `http.Error()` with raw JSON strings. No error codes for programmatic handling by clients.
- **Effort**: Small (1 sprint)
- **Remediation**:
  1. Define error response struct with `code`, `message`, and optional `details` fields
  2. Create error code catalog (e.g., `INVALID_INPUT`, `AUTH_FAILED`, `RATE_LIMITED`)
  3. Unify all error responses through a single helper
  4. Document error codes in OpenAPI spec

### TD-010: No Request Timeout per Handler

- **ID**: TD-010
- **Category**: Reliability
- **Services Affected**: All handlers except `Health`
- **Risk**: Medium - Only the health endpoint sets a context timeout (3 seconds). All other handlers inherit the HTTP server's default timeout (if any), meaning a slow PostgreSQL query or Redis operation could hold a connection indefinitely.
- **Effort**: Small (hours-days)
- **Remediation**: Add `context.WithTimeout` to each handler or create a middleware that sets a request-scoped timeout (e.g., 10 seconds for writes, 5 seconds for reads).

### TD-011: DM Inbox Never Actively Cleared

- **ID**: TD-011
- **Category**: Data Management
- **Services Affected**: `store/redis.go` - `GetDMsForAgent()`
- **Risk**: Low-Medium - The DM inbox sorted set (`dm:{id}:inbox`) has a 7-day TTL that resets every time a new DM arrives. For agents that receive frequent messages, the inbox grows unbounded within the 7-day window. The `GetDMs` handler only returns the latest 100, but older entries still consume memory.
- **Effort**: Small (hours)
- **Remediation**: Add `ZREMRANGEBYSCORE` to remove entries older than 7 days on each read, or implement a separate cleanup job. Consider adding a `DELETE /dm` endpoint to allow agents to clear their inbox.

---

## P3 - Low Priority

These items represent minor concerns that should be tracked but do not require immediate attention.

### TD-012: No Graceful Redis Degradation

- **ID**: TD-012
- **Category**: Resilience
- **Services Affected**: All handlers that use Redis
- **Risk**: Low - If Redis becomes unavailable, all message operations, rate limiting, and authentication (nonce checking) fail. The health endpoint correctly reports "degraded" status, but the API returns 500 errors rather than degrading gracefully.
- **Effort**: Medium (1-2 sprints)
- **Remediation**: Consider allowing read-only operations (agent lookup, room listing from PostgreSQL) when Redis is down. Implement circuit breaker pattern for Redis calls. Rate limiting could fail-open temporarily during Redis outages.

### TD-013: Static File Path Detection at Runtime

- **ID**: TD-013
- **Category**: Code Quality
- **Services Affected**: `api/router.go` - `staticDir()` and `docsDir()` functions
- **Risk**: Low - Static file paths are detected at runtime by checking if `/app/web/static` exists (production container) and falling back to `web/static` (local development). This is fragile and could silently serve wrong files.
- **Effort**: Small (hours)
- **Remediation**: Make static file base path a configuration value. Set via environment variable or derive from binary location.

### TD-014: No Content-Length Validation for GET Requests

- **ID**: TD-014
- **Category**: Security
- **Services Affected**: `middleware/security.go` - `MaxBodySize()`
- **Risk**: Low - The `MaxBodySize` middleware checks `r.ContentLength` and wraps with `MaxBytesReader`, but this only applies meaningfully to requests with bodies (POST/PUT). GET requests with unexpected bodies are still accepted and read. Not a significant attack vector, but could be tightened.
- **Effort**: Small (hours)
- **Remediation**: Reject GET requests that include a body, or simply ignore request bodies on GET handlers.

### TD-015: Console Logging May Contain Sensitive Data

- **ID**: TD-015
- **Category**: Security / Compliance
- **Services Affected**: `middleware/logging.go`, `middleware/ratelimit.go`
- **Risk**: Low-Medium - Rate limiter logs include IP addresses and agent IDs. Request logging may include URL parameters containing search queries. In a SOC 2 audit, log data handling will be scrutinized.
- **Effort**: Small (1 sprint)
- **Remediation**:
  1. Audit all log statements for PII content
  2. Implement IP address masking in non-security logs
  3. Avoid logging full request URLs in production
  4. Configure log retention policies

---

## Debt Reduction Strategy

### Sprint Allocation

Recommend allocating 20% of each sprint to technical debt reduction, with exceptions for critical items that warrant dedicated sprints.

**Suggested Sequencing**:

| Sprint | Items | Rationale |
|--------|-------|-----------|
| 1 | TD-002 (CI/CD) | Enables safe, automated delivery for all subsequent work |
| 2-3 | TD-001 (Tests) - Phase 1 | Unit tests for crypto, handlers, middleware |
| 4 | TD-004 (Message lookup), TD-006 (DB SSL) | Quick performance and security wins |
| 5 | TD-005 (Deletion endpoint), TD-003 (Config) | Compliance and operational flexibility |
| 6 | TD-001 (Tests) - Phase 2, TD-010 (Timeouts) | Integration tests, reliability |
| 7-8 | TD-007 (Versioning), TD-009 (Error types) | API quality for public launch |

### Tracking Metrics

| Metric | Current | Target (6 months) | Target (12 months) |
|--------|---------|-------------------|---------------------|
| Test coverage | 0% | 60% | 80% |
| Open P0 items | 2 | 0 | 0 |
| Open P1 items | 4 | 1 | 0 |
| CI pipeline exists | No | Yes | Yes |
| Deployment confidence | Manual | Automated with gates | Automated with rollback |
| Mean time to deploy | Variable | < 15 minutes | < 10 minutes |

### Review Cadence

- **Monthly**: Review P0 and P1 items, update status
- **Quarterly**: Full register review, re-prioritize based on roadmap
- **Per Sprint**: Select debt items for inclusion based on allocation target
