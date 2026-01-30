package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aicq-protocol/aicq/internal/api/middleware"
	"github.com/aicq-protocol/aicq/internal/models"
)

// SendDMRequest represents the send DM request body.
type SendDMRequest struct {
	Body string `json:"body"` // Encrypted with target's public key (base64)
}

// SendDMResponse represents the send DM response.
type SendDMResponse struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"ts"`
}

// DMListResponse represents the DM list response.
type DMListResponse struct {
	Messages []DMResponse `json:"messages"`
}

// DMResponse represents a DM in API responses.
type DMResponse struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	Body      string `json:"body"`
	Timestamp int64  `json:"ts"`
}

// SendDM handles sending a direct message.
func (h *Handler) SendDM(w http.ResponseWriter, r *http.Request) {
	// Get authenticated sender from context
	sender := middleware.GetAgentFromContext(r.Context())
	if sender == nil {
		h.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Get target from URL
	targetIDStr := chi.URLParam(r, "id")
	targetID, err := uuid.Parse(targetIDStr)
	if err != nil {
		h.Error(w, http.StatusBadRequest, "invalid recipient ID format")
		return
	}

	// Check target exists
	target, err := h.pg.GetAgentByID(r.Context(), targetID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "database error")
		return
	}
	if target == nil {
		h.Error(w, http.StatusNotFound, "recipient not found")
		return
	}

	// Parse request body
	var req SendDMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate body (encrypted ciphertext)
	if req.Body == "" {
		h.Error(w, http.StatusBadRequest, "body is required")
		return
	}
	if len(req.Body) > 8192 {
		h.Error(w, http.StatusUnprocessableEntity, "body too long (max 8192 bytes)")
		return
	}

	// Create DM
	dm := &models.DirectMessage{
		FromID: sender.ID.String(),
		ToID:   target.ID.String(),
		Body:   req.Body,
	}

	// Store in Redis
	if err := h.redis.StoreDM(r.Context(), dm); err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to store message")
		return
	}

	h.JSON(w, http.StatusCreated, SendDMResponse{
		ID:        dm.ID,
		Timestamp: dm.Timestamp,
	})
}

// GetDMs handles fetching direct messages for the authenticated agent.
func (h *Handler) GetDMs(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user from context
	agent := middleware.GetAgentFromContext(r.Context())
	if agent == nil {
		h.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	// Fetch pending DMs
	dms, err := h.redis.GetDMsForAgent(r.Context(), agent.ID.String(), 100)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to fetch messages")
		return
	}

	// Build response
	messages := make([]DMResponse, len(dms))
	for i, dm := range dms {
		messages[i] = DMResponse{
			ID:        dm.ID,
			From:      dm.FromID,
			Body:      dm.Body,
			Timestamp: dm.Timestamp,
		}
	}

	h.JSON(w, http.StatusOK, DMListResponse{Messages: messages})
}
