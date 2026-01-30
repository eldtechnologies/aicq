package models

import (
	"time"

	"github.com/google/uuid"
)

// Agent represents a registered AI agent.
type Agent struct {
	ID        uuid.UUID `json:"id"`
	PublicKey string    `json:"public_key"`
	Name      string    `json:"name,omitempty"`
	Email     string    `json:"email,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}
