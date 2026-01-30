package handlers

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
)

// WhoResponse represents the agent profile response.
type WhoResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name,omitempty"`
	Email     string `json:"email,omitempty"`
	PublicKey string `json:"public_key"`
	JoinedAt  string `json:"joined_at"`
}

// Who handles agent profile lookup.
func (h *Handler) Who(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")

	// Validate UUID format
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.Error(w, http.StatusBadRequest, "invalid agent ID format")
		return
	}

	// Lookup agent
	agent, err := h.pg.GetAgentByID(r.Context(), id)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "database error")
		return
	}

	if agent == nil {
		h.Error(w, http.StatusNotFound, "agent not found")
		return
	}

	h.JSON(w, http.StatusOK, WhoResponse{
		ID:        agent.ID.String(),
		Name:      agent.Name,
		Email:     agent.Email,
		PublicKey: agent.PublicKey,
		JoinedAt:  agent.CreatedAt.Format("2006-01-02T15:04:05Z"),
	})
}
