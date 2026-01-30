package handlers

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var searchWordRegex = regexp.MustCompile(`[a-z0-9]+`)

// stopWords are common words to exclude from search
var stopWords = map[string]bool{
	"the": true, "a": true, "an": true, "and": true, "or": true,
	"is": true, "are": true, "was": true, "were": true, "be": true,
	"to": true, "of": true, "in": true, "for": true, "on": true,
	"it": true, "that": true, "this": true, "with": true, "at": true,
	"by": true, "from": true, "as": true, "into": true, "like": true,
}

// SearchResult represents a single search result.
type SearchResult struct {
	MessageID string  `json:"id"`
	RoomID    string  `json:"room_id"`
	RoomName  string  `json:"room_name"`
	From      string  `json:"from"`
	Body      string  `json:"body"`
	Timestamp int64   `json:"ts"`
	Score     float64 `json:"score,omitempty"`
}

// SearchResponse represents the search response.
type SearchResponse struct {
	Query   string         `json:"query"`
	Results []SearchResult `json:"results"`
	Total   int            `json:"total"`
}

// tokenize extracts searchable words from text.
func tokenize(text string) []string {
	lower := strings.ToLower(text)
	words := searchWordRegex.FindAllString(lower, -1)

	// Deduplicate and filter
	seen := make(map[string]bool)
	result := make([]string, 0, len(words))
	for _, w := range words {
		if len(w) >= 2 && !seen[w] && !stopWords[w] {
			seen[w] = true
			result = append(result, w)
		}
	}

	// Limit to 5 tokens
	if len(result) > 5 {
		result = result[:5]
	}

	return result
}

// Search handles the search endpoint.
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
	// Parse query
	query := r.URL.Query().Get("q")
	if query == "" {
		h.Error(w, http.StatusBadRequest, "query parameter 'q' is required")
		return
	}
	if len(query) > 100 {
		h.Error(w, http.StatusBadRequest, "query too long (max 100 chars)")
		return
	}

	// Parse limit
	limit := 20
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > 100 {
		limit = 100
	}

	// Parse after timestamp
	var after int64 = 0
	if afterStr := r.URL.Query().Get("after"); afterStr != "" {
		if a, err := strconv.ParseInt(afterStr, 10, 64); err == nil {
			after = a
		}
	}

	// Parse room filter
	roomFilter := r.URL.Query().Get("room")
	if roomFilter != "" {
		// Validate UUID format
		if _, err := uuid.Parse(roomFilter); err != nil {
			h.Error(w, http.StatusBadRequest, "invalid room ID format")
			return
		}
	}

	// Tokenize query
	tokens := tokenize(query)
	if len(tokens) == 0 {
		h.JSON(w, http.StatusOK, SearchResponse{
			Query:   query,
			Results: []SearchResult{},
			Total:   0,
		})
		return
	}

	// Search Redis
	messages, err := h.redis.SearchMessages(r.Context(), tokens, limit, after, roomFilter)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "search failed")
		return
	}

	// Build results with room names
	results := make([]SearchResult, 0, len(messages))
	roomNameCache := make(map[string]string)

	for _, msg := range messages {
		// Get room name (cached)
		roomName := roomNameCache[msg.RoomID]
		if roomName == "" {
			roomUUID, err := uuid.Parse(msg.RoomID)
			if err == nil {
				room, err := h.pg.GetRoom(r.Context(), roomUUID)
				if err == nil && room != nil {
					roomName = room.Name
					roomNameCache[msg.RoomID] = roomName
				}
			}
		}

		results = append(results, SearchResult{
			MessageID: msg.ID,
			RoomID:    msg.RoomID,
			RoomName:  roomName,
			From:      msg.FromID,
			Body:      msg.Body,
			Timestamp: msg.Timestamp,
		})
	}

	h.JSON(w, http.StatusOK, SearchResponse{
		Query:   query,
		Results: results,
		Total:   len(results),
	})
}
