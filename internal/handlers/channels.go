package handlers

import (
	"net/http"
	"strconv"
)

// ChannelInfo represents a channel in the list response.
type ChannelInfo struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MessageCount int64  `json:"message_count"`
	LastActive   string `json:"last_active"`
}

// ChannelListResponse represents the channels list response.
type ChannelListResponse struct {
	Channels []ChannelInfo `json:"channels"`
	Total    int           `json:"total"`
}

// ListChannels handles listing public channels.
func (h *Handler) ListChannels(w http.ResponseWriter, r *http.Request) {
	// Parse query params
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")

	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
			limit = l
		}
	}
	if limit > 100 {
		limit = 100
	}

	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 {
			offset = o
		}
	}

	// Query public rooms
	rooms, total, err := h.pg.ListPublicRooms(r.Context(), limit, offset)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "database error")
		return
	}

	// Build response
	channels := make([]ChannelInfo, len(rooms))
	for i, room := range rooms {
		channels[i] = ChannelInfo{
			ID:           room.ID.String(),
			Name:         room.Name,
			MessageCount: room.MessageCount,
			LastActive:   room.LastActiveAt.Format("2006-01-02T15:04:05Z"),
		}
	}

	h.JSON(w, http.StatusOK, ChannelListResponse{
		Channels: channels,
		Total:    total,
	})
}
