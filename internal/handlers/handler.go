package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"unicode"

	"github.com/aicq-protocol/aicq/internal/store"
)

// Handler contains shared dependencies for all HTTP handlers.
type Handler struct {
	pg    *store.PostgresStore
	redis *store.RedisStore
}

// NewHandler creates a new Handler with the given stores.
func NewHandler(pg *store.PostgresStore, redis *store.RedisStore) *Handler {
	return &Handler{pg: pg, redis: redis}
}

// JSON sends a JSON response with the given status code.
func (h *Handler) JSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// Error sends a JSON error response with the given status code.
func (h *Handler) Error(w http.ResponseWriter, status int, message string) {
	h.JSON(w, status, map[string]string{"error": message})
}

// sanitizeName trims and limits name to 100 characters, removing control characters.
func sanitizeName(name string) string {
	name = strings.TrimSpace(name)

	// Remove control characters
	name = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, name)

	// Limit to 100 characters
	if len(name) > 100 {
		name = name[:100]
	}

	return name
}

// isValidEmail performs basic email validation.
func isValidEmail(email string) bool {
	if email == "" {
		return true // Empty is valid (optional field)
	}
	return strings.Contains(email, "@") && len(email) > 3
}
