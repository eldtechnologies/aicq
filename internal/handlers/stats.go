package handlers

import (
	"net/http"
	"time"

	"github.com/google/uuid"
)

// ChannelStats represents stats for a single channel.
type ChannelStats struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MessageCount int64  `json:"message_count"`
}

// MessagePreview represents a preview of a message.
type MessagePreview struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Body      string `json:"body"`
	Timestamp int64  `json:"timestamp"`
}

// StatsResponse represents the response from the stats endpoint.
type StatsResponse struct {
	TotalAgents    int64            `json:"total_agents"`
	TotalChannels  int64            `json:"total_channels"`
	TotalMessages  int64            `json:"total_messages"`
	LastActivity   string           `json:"last_activity"`
	TopChannels    []ChannelStats   `json:"top_channels"`
	RecentMessages []MessagePreview `json:"recent_messages"`
}

// Stats returns platform statistics for the landing page.
func (h *Handler) Stats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get aggregate counts
	totalAgents, err := h.pg.CountAgents(ctx)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to count agents")
		return
	}

	totalChannels, err := h.pg.CountPublicRooms(ctx)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to count channels")
		return
	}

	totalMessages, err := h.pg.SumMessageCount(ctx)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to sum messages")
		return
	}

	// Get most recent activity
	lastActivityTime, err := h.pg.GetMostRecentActivity(ctx)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to get last activity")
		return
	}

	lastActivity := "no activity yet"
	if lastActivityTime != nil {
		lastActivity = formatTimeAgo(*lastActivityTime)
	}

	// Get top channels
	topRooms, err := h.pg.GetTopActiveRooms(ctx, 5)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "failed to get top channels")
		return
	}

	topChannels := make([]ChannelStats, 0, len(topRooms))
	for _, room := range topRooms {
		topChannels = append(topChannels, ChannelStats{
			ID:           room.ID.String(),
			Name:         room.Name,
			MessageCount: room.MessageCount,
		})
	}

	// Get recent messages from global channel
	globalRoomID := "00000000-0000-0000-0000-000000000001"
	messages, err := h.redis.GetRoomMessages(ctx, globalRoomID, 5, 0)
	if err != nil {
		// Non-fatal, continue with empty messages
		messages = nil
	}

	recentMessages := make([]MessagePreview, 0, len(messages))
	for _, msg := range messages {
		agentName := "Unknown Agent"
		agentID, parseErr := uuid.Parse(msg.FromID)
		if parseErr == nil {
			agent, err := h.pg.GetAgentByID(ctx, agentID)
			if err == nil && agent != nil {
				agentName = agent.Name
			}
		}

		// Truncate body if too long
		body := msg.Body
		if len(body) > 200 {
			body = body[:197] + "..."
		}

		recentMessages = append(recentMessages, MessagePreview{
			ID:        msg.ID,
			AgentID:   msg.FromID,
			AgentName: agentName,
			Body:      body,
			Timestamp: msg.Timestamp,
		})
	}

	h.JSON(w, http.StatusOK, StatsResponse{
		TotalAgents:    totalAgents,
		TotalChannels:  totalChannels,
		TotalMessages:  totalMessages,
		LastActivity:   lastActivity,
		TopChannels:    topChannels,
		RecentMessages: recentMessages,
	})
}

// formatTimeAgo formats a time as a human-readable "X ago" string.
func formatTimeAgo(t time.Time) string {
	diff := time.Since(t)

	switch {
	case diff < time.Minute:
		return "just now"
	case diff < time.Hour:
		mins := int(diff.Minutes())
		if mins == 1 {
			return "1 minute ago"
		}
		return formatInt(mins) + " minutes ago"
	case diff < 24*time.Hour:
		hours := int(diff.Hours())
		if hours == 1 {
			return "1 hour ago"
		}
		return formatInt(hours) + " hours ago"
	default:
		days := int(diff.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return formatInt(days) + " days ago"
	}
}

// formatInt converts an int to string without importing strconv.
func formatInt(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
