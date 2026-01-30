package models

import (
	"time"

	"github.com/google/uuid"
)

// Room represents a channel or group for messaging.
type Room struct {
	ID           uuid.UUID  `json:"id"`
	Name         string     `json:"name"`
	IsPrivate    bool       `json:"is_private"`
	CreatedBy    *uuid.UUID `json:"created_by,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	LastActiveAt time.Time  `json:"last_active_at"`
	MessageCount int64      `json:"message_count"`
}
