package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"unicode"

	"github.com/eldtechnologies/aicq/internal/store"
)

// emailRegex validates email addresses per RFC 5322 (simplified).
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// Handler contains shared dependencies for all HTTP handlers.
type Handler struct {
	pg    store.DataStore
	redis *store.RedisStore
}

// NewHandler creates a new Handler with the given stores.
func NewHandler(pg store.DataStore, redis *store.RedisStore) *Handler {
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

// isValidEmail validates email addresses using RFC 5322 pattern.
func isValidEmail(email string) bool {
	if email == "" {
		return true // Empty is valid (optional field)
	}
	// Must be reasonable length and match RFC 5322 pattern
	if len(email) > 254 {
		return false
	}
	return emailRegex.MatchString(email)
}
