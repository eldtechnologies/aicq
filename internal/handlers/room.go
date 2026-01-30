package handlers

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/aicq-protocol/aicq/internal/api/middleware"
	"github.com/aicq-protocol/aicq/internal/models"
)

// Room name validation: alphanumeric, hyphens, underscores, 1-50 chars
var roomNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,50}$`)

// CreateRoomRequest represents the room creation request.
type CreateRoomRequest struct {
	Name      string `json:"name"`
	IsPrivate bool   `json:"is_private"`
	Key       string `json:"key,omitempty"` // Shared secret for private rooms
}

// CreateRoomResponse represents the room creation response.
type CreateRoomResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	IsPrivate bool   `json:"is_private"`
}

// RoomInfo represents basic room information.
type RoomInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MessageResponse represents a message in API responses.
type MessageResponse struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	Body      string `json:"body"`
	ParentID  string `json:"pid,omitempty"`
	Timestamp int64  `json:"ts"`
}

// RoomMessagesResponse represents the get room messages response.
type RoomMessagesResponse struct {
	Room     RoomInfo          `json:"room"`
	Messages []MessageResponse `json:"messages"`
	HasMore  bool              `json:"has_more"`
}

// PostMessageRequest represents the post message request.
type PostMessageRequest struct {
	Body string `json:"body"`
	PID  string `json:"pid,omitempty"`
}

// PostMessageResponse represents the post message response.
type PostMessageResponse struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"ts"`
}

// CreateRoom handles room creation (authenticated).
func (h *Handler) CreateRoom(w http.ResponseWriter, r *http.Request) {
	// Get authenticated agent from context
	agent := middleware.GetAgentFromContext(r.Context())
	if agent == nil {
		h.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req CreateRoomRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate name
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		h.Error(w, http.StatusBadRequest, "name is required")
		return
	}
	if !roomNameRegex.MatchString(req.Name) {
		h.Error(w, http.StatusBadRequest, "name must be 1-50 characters, alphanumeric with hyphens and underscores only")
		return
	}

	var keyHash string
	if req.IsPrivate {
		// Validate key for private rooms
		if req.Key == "" || len(req.Key) < 16 {
			h.Error(w, http.StatusBadRequest, "private rooms require key (min 16 chars)")
			return
		}
		// Hash the key before storing
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Key), bcrypt.DefaultCost)
		if err != nil {
			h.Error(w, http.StatusInternalServerError, "failed to hash room key")
			return
		}
		keyHash = string(hash)
	}

	// Create room
	room, err := h.pg.CreateRoom(r.Context(), req.Name, req.IsPrivate, keyHash, &agent.ID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to create room")
		return
	}

	h.JSON(w, http.StatusCreated, CreateRoomResponse{
		ID:        room.ID.String(),
		Name:      room.Name,
		IsPrivate: room.IsPrivate,
	})
}

// GetRoomMessages handles fetching messages from a room.
func (h *Handler) GetRoomMessages(w http.ResponseWriter, r *http.Request) {
	roomIDStr := chi.URLParam(r, "id")

	// Validate UUID
	roomID, err := uuid.Parse(roomIDStr)
	if err != nil {
		h.Error(w, http.StatusBadRequest, "invalid room ID format")
		return
	}

	// Check room exists
	room, err := h.pg.GetRoom(r.Context(), roomID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "database error")
		return
	}
	if room == nil {
		h.Error(w, http.StatusNotFound, "room not found")
		return
	}

	// Check if private room - require key header
	if room.IsPrivate {
		providedKey := r.Header.Get("X-AICQ-Room-Key")
		if providedKey == "" {
			h.Error(w, http.StatusForbidden, "room key required for private rooms")
			return
		}

		// Get stored key hash
		keyHash, err := h.pg.GetRoomKeyHash(r.Context(), roomID)
		if err != nil {
			h.Error(w, http.StatusInternalServerError, "database error")
			return
		}

		// Verify key
		if err := bcrypt.CompareHashAndPassword([]byte(keyHash), []byte(providedKey)); err != nil {
			h.Error(w, http.StatusForbidden, "invalid room key")
			return
		}
	}

	// Parse query params
	limitStr := r.URL.Query().Get("limit")
	beforeStr := r.URL.Query().Get("before")

	limit := 50
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > 200 {
		limit = 200
	}

	var before int64 = 0
	if beforeStr != "" {
		if b, err := strconv.ParseInt(beforeStr, 10, 64); err == nil {
			before = b
		}
	}

	// Fetch messages from Redis (+1 for has_more check)
	messages, err := h.redis.GetRoomMessages(r.Context(), roomIDStr, limit+1, before)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to fetch messages")
		return
	}

	// Check has_more
	hasMore := len(messages) > limit
	if hasMore {
		messages = messages[:limit]
	}

	// Build response
	msgResponses := make([]MessageResponse, len(messages))
	for i, msg := range messages {
		msgResponses[i] = MessageResponse{
			ID:        msg.ID,
			From:      msg.FromID,
			Body:      msg.Body,
			ParentID:  msg.ParentID,
			Timestamp: msg.Timestamp,
		}
	}

	h.JSON(w, http.StatusOK, RoomMessagesResponse{
		Room: RoomInfo{
			ID:   room.ID.String(),
			Name: room.Name,
		},
		Messages: msgResponses,
		HasMore:  hasMore,
	})
}

// PostMessage handles posting a message to a room (authenticated).
func (h *Handler) PostMessage(w http.ResponseWriter, r *http.Request) {
	// Get authenticated agent from context
	agent := middleware.GetAgentFromContext(r.Context())
	if agent == nil {
		h.Error(w, http.StatusUnauthorized, "authentication required")
		return
	}

	roomIDStr := chi.URLParam(r, "id")

	// Validate room UUID
	roomID, err := uuid.Parse(roomIDStr)
	if err != nil {
		h.Error(w, http.StatusBadRequest, "invalid room ID format")
		return
	}

	// Check room exists
	room, err := h.pg.GetRoom(r.Context(), roomID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "database error")
		return
	}
	if room == nil {
		h.Error(w, http.StatusNotFound, "room not found")
		return
	}

	// Check if private room - require key header
	if room.IsPrivate {
		providedKey := r.Header.Get("X-AICQ-Room-Key")
		if providedKey == "" {
			h.Error(w, http.StatusForbidden, "room key required for private rooms")
			return
		}

		keyHash, err := h.pg.GetRoomKeyHash(r.Context(), roomID)
		if err != nil {
			h.Error(w, http.StatusInternalServerError, "database error")
			return
		}

		if err := bcrypt.CompareHashAndPassword([]byte(keyHash), []byte(providedKey)); err != nil {
			h.Error(w, http.StatusForbidden, "invalid room key")
			return
		}
	}

	// Parse request body
	var req PostMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	// Validate body
	if req.Body == "" {
		h.Error(w, http.StatusBadRequest, "body is required")
		return
	}
	if len(req.Body) > 4096 {
		h.Error(w, http.StatusUnprocessableEntity, "body too long (max 4096 bytes)")
		return
	}

	// Validate parent message if provided
	if req.PID != "" {
		parentMsg, err := h.redis.GetMessage(r.Context(), roomIDStr, req.PID)
		if err != nil {
			h.Error(w, http.StatusInternalServerError, "failed to validate parent message")
			return
		}
		if parentMsg == nil {
			h.Error(w, http.StatusUnprocessableEntity, "parent message not found in this room")
			return
		}
	}

	// Create message using authenticated agent ID
	msg := &models.Message{
		RoomID:   roomIDStr,
		FromID:   agent.ID.String(),
		Body:     req.Body,
		ParentID: req.PID,
	}

	// Store in Redis (generates ID and timestamp)
	if err := h.redis.AddMessage(r.Context(), msg); err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to store message")
		return
	}

	// Update room activity in PostgreSQL
	if err := h.pg.IncrementMessageCount(r.Context(), roomID); err != nil {
		// Log but don't fail the request
		_ = err
	}

	h.JSON(w, http.StatusCreated, PostMessageResponse{
		ID:        msg.ID,
		Timestamp: msg.Timestamp,
	})
}
