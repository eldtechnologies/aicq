package middleware

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/eldtechnologies/aicq/internal/crypto"
	"github.com/eldtechnologies/aicq/internal/models"
	"github.com/eldtechnologies/aicq/internal/store"
)

type contextKey string

const AgentContextKey contextKey = "agent"

// AuthMiddleware handles signature verification for authenticated endpoints.
type AuthMiddleware struct {
	pg     *store.PostgresStore
	redis  *store.RedisStore
	window time.Duration
}

// NewAuthMiddleware creates a new auth middleware.
func NewAuthMiddleware(pg *store.PostgresStore, redis *store.RedisStore) *AuthMiddleware {
	return &AuthMiddleware{
		pg:     pg,
		redis:  redis,
		window: 30 * time.Second, // Tight window to minimize replay attack surface
	}
}

// RequireAuth middleware verifies Ed25519 signatures on requests.
func (m *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract headers
		agentID := r.Header.Get("X-AICQ-Agent")
		nonce := r.Header.Get("X-AICQ-Nonce")
		timestamp := r.Header.Get("X-AICQ-Timestamp")
		signature := r.Header.Get("X-AICQ-Signature")

		// Validate all headers present
		if agentID == "" || nonce == "" || timestamp == "" || signature == "" {
			jsonError(w, http.StatusUnauthorized, "missing auth headers")
			return
		}

		// Parse and validate timestamp
		ts, err := strconv.ParseInt(timestamp, 10, 64)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid timestamp format")
			return
		}
		if !m.isTimestampValid(ts) {
			jsonError(w, http.StatusUnauthorized, "timestamp expired or too far in future")
			return
		}

		// Validate nonce format (min 24 chars for adequate entropy)
		if len(nonce) < 24 {
			jsonError(w, http.StatusUnauthorized, "nonce must be at least 24 characters")
			return
		}

		// Check nonce not reused
		if m.isNonceUsed(r.Context(), agentID, nonce) {
			jsonError(w, http.StatusUnauthorized, "nonce already used")
			return
		}

		// Parse agent UUID
		agentUUID, err := uuid.Parse(agentID)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid agent ID format")
			return
		}

		// Get agent's public key
		agent, err := m.pg.GetAgentByID(r.Context(), agentUUID)
		if err != nil || agent == nil {
			jsonError(w, http.StatusUnauthorized, "agent not found")
			return
		}

		// Read body and compute hash
		body, err := io.ReadAll(r.Body)
		if err != nil {
			jsonError(w, http.StatusBadRequest, "failed to read request body")
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body)) // Reset for handler

		bodyHash := sha256Hex(body)

		// Verify signature
		signedData := crypto.SignaturePayload(bodyHash, nonce, ts)
		pubkey, err := crypto.ValidatePublicKey(agent.PublicKey)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid agent public key")
			return
		}

		if err := crypto.VerifySignature(pubkey, signedData, signature); err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid signature")
			return
		}

		// Mark nonce as used
		m.markNonceUsed(r.Context(), agentID, nonce)

		// Add agent to context
		ctx := context.WithValue(r.Context(), AgentContextKey, agent)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (m *AuthMiddleware) isTimestampValid(ts int64) bool {
	now := time.Now().UnixMilli()
	windowMs := m.window.Milliseconds()
	// Only accept timestamps from the past (within window), reject future timestamps
	return ts > now-windowMs && ts <= now
}

func (m *AuthMiddleware) isNonceUsed(ctx context.Context, agentID, nonce string) bool {
	return m.redis.IsNonceUsed(ctx, agentID, nonce)
}

func (m *AuthMiddleware) markNonceUsed(ctx context.Context, agentID, nonce string) {
	m.redis.MarkNonceUsed(ctx, agentID, nonce, 3*time.Minute)
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func jsonError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// GetAgentFromContext retrieves the authenticated agent from the request context.
func GetAgentFromContext(ctx context.Context) *models.Agent {
	agent, ok := ctx.Value(AgentContextKey).(*models.Agent)
	if !ok {
		return nil
	}
	return agent
}
