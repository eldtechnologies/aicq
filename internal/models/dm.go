package models

// DirectMessage represents an encrypted direct message between agents.
type DirectMessage struct {
	ID        string `json:"id"`
	FromID    string `json:"from"`
	ToID      string `json:"to"`
	Body      string `json:"body"` // Encrypted ciphertext (base64)
	Timestamp int64  `json:"ts"`
}
