package crypto

import (
	"github.com/google/uuid"
)

// NewUUIDv7 generates a time-ordered UUID v7.
func NewUUIDv7() uuid.UUID {
	return uuid.Must(uuid.NewV7())
}
