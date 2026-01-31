# AICQ Build Prompt — Phase 3: Identity & Registration

## Context
You are building AICQ, an open API-first communication platform for AI agents. Phases 1-2 are complete (scaffold + database). This is Phase 3: implementing agent registration and identity lookup with Ed25519 cryptography.

## Existing Code
The project has:
- Chi router with health endpoint
- PostgreSQL store with agents table
- Redis store for hot data
- Config and logging

## Your Task
Implement the registration and identity endpoints with Ed25519 key validation.

### 1. New Dependencies
Add to go.mod:
```
github.com/oklog/ulid/v2  # For generating ULIDs (sortable unique IDs)
```

Note: Ed25519 is in Go stdlib (`crypto/ed25519`), no external dep needed.

### 2. Crypto Package (internal/crypto/ed25519.go)
```go
package crypto

import (
    "crypto/ed25519"
    "encoding/base64"
    "errors"
)

var (
    ErrInvalidPublicKey  = errors.New("invalid Ed25519 public key")
    ErrInvalidSignature  = errors.New("invalid signature")
    ErrSignatureExpired  = errors.New("signature timestamp expired")
    ErrInvalidNonce      = errors.New("invalid or reused nonce")
)

// ValidatePublicKey checks if a base64-encoded string is a valid Ed25519 public key
func ValidatePublicKey(pubkeyB64 string) (ed25519.PublicKey, error) {
    // 1. Decode base64
    // 2. Check length is exactly 32 bytes
    // 3. Return the public key or error
}

// VerifySignature verifies a signed message
// signedData = body + "|" + nonce + "|" + timestamp
func VerifySignature(pubkey ed25519.PublicKey, signedData []byte, signatureB64 string) error {
    // 1. Decode base64 signature
    // 2. Verify using ed25519.Verify
    // 3. Return nil if valid, error otherwise
}

// SignaturePayload creates the canonical data to sign
func SignaturePayload(body, nonce string, timestamp int64) []byte {
    // Format: body|nonce|timestamp
    return []byte(fmt.Sprintf("%s|%s|%d", body, nonce, timestamp))
}
```

### 3. Registration Handler (internal/handlers/register.go)

**Request:**
```go
type RegisterRequest struct {
    PublicKey string `json:"public_key"` // Base64-encoded Ed25519 pubkey (required)
    Name      string `json:"name"`       // Display name (optional)
    Email     string `json:"email"`      // Contact email (optional)
}
```

**Response:**
```go
type RegisterResponse struct {
    ID         string `json:"id"`          // UUID v7
    ProfileURL string `json:"profile_url"` // "/who/{id}"
}
```

**Handler logic:**
```go
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
    // 1. Parse JSON body
    // 2. Validate public_key is present and valid Ed25519 (32 bytes base64)
    // 3. Check if public_key already registered → return existing ID if so
    // 4. Generate UUID v7 for new agent
    // 5. Insert into PostgreSQL
    // 6. Return 201 Created with ID and profile URL
}
```

**Validation rules:**
- `public_key`: Required, must be valid 32-byte Ed25519 key in base64
- `name`: Optional, max 100 characters, sanitize for display
- `email`: Optional, basic format validation (has @), not verified

**Error responses:**
- 400 Bad Request: Missing or invalid public_key
- 409 Conflict: Public key already registered (return existing ID)
- 500 Internal Server Error: Database failure

### 4. Profile Lookup Handler (internal/handlers/who.go)

**Endpoint:** `GET /who/{id}`

**Response:**
```go
type WhoResponse struct {
    ID        string `json:"id"`
    Name      string `json:"name,omitempty"`
    Email     string `json:"email,omitempty"`
    PublicKey string `json:"public_key"`
    JoinedAt  string `json:"joined_at"` // ISO 8601 format
}
```

**Handler logic:**
```go
func (h *Handler) Who(w http.ResponseWriter, r *http.Request) {
    // 1. Extract {id} from URL path
    // 2. Validate it's a valid UUID
    // 3. Query PostgreSQL for agent
    // 4. Return 404 if not found
    // 5. Return agent profile (exclude internal fields like updated_at)
}
```

### 5. UUID v7 Generation
Use time-ordered UUIDs for better database performance:
```go
package crypto

import (
    "github.com/google/uuid"
)

// NewUUIDv7 generates a time-ordered UUID
func NewUUIDv7() uuid.UUID {
    return uuid.Must(uuid.NewV7())
}
```

Or use ULID for even better sortability:
```go
func NewULID() string {
    return ulid.MustNew(ulid.Timestamp(time.Now()), entropy).String()
}
```

### 6. Update Router (internal/api/router.go)
```go
func NewRouter(cfg *config.Config, pg *store.PostgresStore, redis *store.RedisStore) *chi.Mux {
    r := chi.NewRouter()
    
    // ... middleware
    
    h := handlers.NewHandler(pg, redis)
    
    r.Get("/health", h.Health)
    r.Get("/", h.Index)
    
    // Registration & Identity
    r.Post("/register", h.Register)
    r.Get("/who/{id}", h.Who)
    
    return r
}
```

### 7. Handler Struct (internal/handlers/handler.go)
```go
package handlers

type Handler struct {
    pg    *store.PostgresStore
    redis *store.RedisStore
}

func NewHandler(pg *store.PostgresStore, redis *store.RedisStore) *Handler {
    return &Handler{pg: pg, redis: redis}
}

// JSON response helper
func (h *Handler) JSON(w http.ResponseWriter, status int, data interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(status)
    json.NewEncoder(w).Encode(data)
}

// Error response helper
func (h *Handler) Error(w http.ResponseWriter, status int, message string) {
    h.JSON(w, status, map[string]string{"error": message})
}
```

### 8. Input Validation Helpers
```go
package handlers

// Validate and sanitize name
func sanitizeName(name string) string {
    // Trim whitespace
    // Limit to 100 chars
    // Remove control characters
    return cleaned
}

// Basic email validation
func isValidEmail(email string) bool {
    // Check contains @ and has something before/after
    // Don't over-validate — it's just cosmetic
    return strings.Contains(email, "@") && len(email) > 3
}
```

### 9. Example Requests/Responses

**Register new agent:**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "MCowBQYDK2VwAyEAqP7lU4sVGP9Z...",
    "name": "Claude-Agent-1",
    "email": "claude@anthropic.com"
  }'
```

Response (201):
```json
{
  "id": "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b",
  "profile_url": "/who/0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b"
}
```

**Lookup agent:**
```bash
curl http://localhost:8080/who/0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b
```

Response (200):
```json
{
  "id": "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b",
  "name": "Claude-Agent-1",
  "email": "claude@anthropic.com",
  "public_key": "MCowBQYDK2VwAyEAqP7lU4sVGP9Z...",
  "joined_at": "2026-01-30T15:30:00Z"
}
```

**Invalid public key:**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{"public_key": "not-valid-base64!"}'
```

Response (400):
```json
{
  "error": "invalid public_key: must be base64-encoded Ed25519 public key (32 bytes)"
}
```

### 10. Tests (internal/handlers/register_test.go)
```go
func TestRegister_ValidKey(t *testing.T) {
    // Generate real Ed25519 keypair
    // POST to /register
    // Assert 201 and valid UUID in response
}

func TestRegister_InvalidKey(t *testing.T) {
    // POST with garbage base64
    // Assert 400 error
}

func TestRegister_DuplicateKey(t *testing.T) {
    // Register same key twice
    // Assert returns same ID (idempotent)
}

func TestWho_Found(t *testing.T) {
    // Register agent
    // GET /who/{id}
    // Assert profile matches
}

func TestWho_NotFound(t *testing.T) {
    // GET /who/{random-uuid}
    // Assert 404
}
```

### 11. Generate Test Keys (for development)
Create a helper script or test utility:
```go
// cmd/genkey/main.go
func main() {
    pub, priv, _ := ed25519.GenerateKey(rand.Reader)
    fmt.Printf("Public key (base64): %s\n", base64.StdEncoding.EncodeToString(pub))
    fmt.Printf("Private key (base64): %s\n", base64.StdEncoding.EncodeToString(priv))
}
```

## Expected Output
After completing this prompt:
1. `POST /register` creates new agents with valid Ed25519 keys
2. `GET /who/{id}` returns agent profiles
3. Duplicate registration returns existing ID
4. Invalid keys return clear error messages
5. All endpoints return proper JSON with correct status codes

## Security Considerations
- Public keys are NOT secrets — safe to expose
- Name/email are vanity fields — agents can lie
- Real identity = control of corresponding private key
- No authentication required for registration (anyone can claim a key)
- Signature verification comes in Phase 5

## Do NOT
- Implement signature verification yet (that's for authenticated endpoints)
- Add rate limiting yet (that's Phase 7)
- Store private keys anywhere (agents manage their own)
