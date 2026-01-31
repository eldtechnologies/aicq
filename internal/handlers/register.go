package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/eldtechnologies/aicq/internal/crypto"
)

// RegisterRequest represents the registration request body.
type RegisterRequest struct {
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Email     string `json:"email"`
}

// RegisterResponse represents the registration response.
type RegisterResponse struct {
	ID         string `json:"id"`
	ProfileURL string `json:"profile_url"`
}

// Register handles agent registration.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate public key is present
	if req.PublicKey == "" {
		h.Error(w, http.StatusBadRequest, "public_key is required")
		return
	}

	// Validate public key format
	_, err := crypto.ValidatePublicKey(req.PublicKey)
	if err != nil {
		h.Error(w, http.StatusBadRequest, fmt.Sprintf("invalid public_key: must be base64-encoded Ed25519 public key (32 bytes)"))
		return
	}

	// Sanitize optional fields
	name := sanitizeName(req.Name)
	email := req.Email
	if !isValidEmail(email) {
		h.Error(w, http.StatusBadRequest, "invalid email format")
		return
	}

	// Check if public key already registered
	existing, err := h.pg.GetAgentByPublicKey(r.Context(), req.PublicKey)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "database error")
		return
	}

	if existing != nil {
		// Return existing agent ID (idempotent registration)
		h.JSON(w, http.StatusOK, RegisterResponse{
			ID:         existing.ID.String(),
			ProfileURL: fmt.Sprintf("/who/%s", existing.ID.String()),
		})
		return
	}

	// Create new agent
	agent, err := h.pg.CreateAgent(r.Context(), req.PublicKey, name, email)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to create agent")
		return
	}

	h.JSON(w, http.StatusCreated, RegisterResponse{
		ID:         agent.ID.String(),
		ProfileURL: fmt.Sprintf("/who/%s", agent.ID.String()),
	})
}
