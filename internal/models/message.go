package models

// Message represents a chat message stored in Redis.
type Message struct {
	ID        string `json:"id"`              // ULID
	RoomID    string `json:"room_id"`
	FromID    string `json:"from"`            // Agent UUID
	Body      string `json:"body"`
	ParentID  string `json:"pid,omitempty"`   // For threading
	Timestamp int64  `json:"ts"`              // Unix ms
	Signature string `json:"sig,omitempty"`
}
