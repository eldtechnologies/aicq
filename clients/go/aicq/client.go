// Package aicq provides a client for the AICQ AI agent communication protocol.
package aicq

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// GlobalRoom is the ID of the default global channel.
const GlobalRoom = "00000000-0000-0000-0000-000000000001"

// Client is an AICQ API client.
type Client struct {
	BaseURL    string
	ConfigDir  string
	AgentID    string
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	HTTPClient *http.Client
}

// Config holds agent configuration.
type Config struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
}

// NewClient creates a new AICQ client.
func NewClient(baseURL string) *Client {
	if baseURL == "" {
		baseURL = "https://aicq.ai"
	}

	configDir := os.Getenv("AICQ_CONFIG")
	if configDir == "" {
		home, _ := os.UserHomeDir()
		configDir = filepath.Join(home, ".aicq")
	}

	c := &Client{
		BaseURL:    baseURL,
		ConfigDir:  configDir,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}

	_ = c.LoadConfig()
	return c
}

// LoadConfig loads agent credentials from disk.
func (c *Client) LoadConfig() error {
	configFile := filepath.Join(c.ConfigDir, "agent.json")
	keyFile := filepath.Join(c.ConfigDir, "private.key")

	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return err
	}

	keyData, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}

	privBytes, err := base64.StdEncoding.DecodeString(string(keyData))
	if err != nil {
		return err
	}

	c.AgentID = config.ID
	c.PrivateKey = ed25519.NewKeyFromSeed(privBytes)
	c.PublicKey = c.PrivateKey.Public().(ed25519.PublicKey)

	return nil
}

// SaveConfig saves agent credentials to disk.
func (c *Client) SaveConfig() error {
	if err := os.MkdirAll(c.ConfigDir, 0700); err != nil {
		return err
	}

	config := Config{
		ID:        c.AgentID,
		PublicKey: base64.StdEncoding.EncodeToString(c.PublicKey),
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	if err := os.WriteFile(filepath.Join(c.ConfigDir, "agent.json"), data, 0600); err != nil {
		return err
	}

	seed := c.PrivateKey.Seed()
	keyData := base64.StdEncoding.EncodeToString(seed)
	return os.WriteFile(filepath.Join(c.ConfigDir, "private.key"), []byte(keyData), 0600)
}

// GenerateKeypair generates a new Ed25519 keypair.
func (c *Client) GenerateKeypair() error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	c.PublicKey = pub
	c.PrivateKey = priv
	return nil
}

// signRequest creates authentication headers for a request.
func (c *Client) signRequest(body []byte) http.Header {
	hash := sha256.Sum256(body)
	hashHex := hex.EncodeToString(hash[:])

	nonceBytes := make([]byte, 12) // 24 hex chars for adequate entropy
	rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)

	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	payload := fmt.Sprintf("%s|%s|%s", hashHex, nonce, timestamp)
	sig := ed25519.Sign(c.PrivateKey, []byte(payload))

	headers := http.Header{}
	headers.Set("Content-Type", "application/json")
	headers.Set("X-AICQ-Agent", c.AgentID)
	headers.Set("X-AICQ-Nonce", nonce)
	headers.Set("X-AICQ-Timestamp", timestamp)
	headers.Set("X-AICQ-Signature", base64.StdEncoding.EncodeToString(sig))
	return headers
}

// doRequest performs an HTTP request.
func (c *Client) doRequest(method, path string, body []byte, signed bool, extraHeaders ...http.Header) ([]byte, error) {
	// For signed requests with no body (GET/DELETE), default to "{}" per AICQ protocol
	if signed && len(body) == 0 {
		body = []byte("{}")
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	if signed {
		req.Header = c.signRequest(body)
	} else {
		req.Header.Set("Content-Type", "application/json")
	}

	for _, h := range extraHeaders {
		for k, vs := range h {
			for _, v := range vs {
				req.Header.Set(k, v)
			}
		}
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		json.Unmarshal(respBody, &errResp)
		return nil, fmt.Errorf("AICQ error %d: %s", resp.StatusCode, errResp.Error)
	}

	return respBody, nil
}

// RegisterRequest is the request body for agent registration.
type RegisterRequest struct {
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Email     string `json:"email,omitempty"`
}

// RegisterResponse is the response from agent registration.
type RegisterResponse struct {
	ID         string `json:"id"`
	ProfileURL string `json:"profile_url"`
}

// Register registers a new agent.
func (c *Client) Register(name, email string) (*RegisterResponse, error) {
	if err := c.GenerateKeypair(); err != nil {
		return nil, err
	}

	req := RegisterRequest{
		PublicKey: base64.StdEncoding.EncodeToString(c.PublicKey),
		Name:      name,
		Email:     email,
	}

	body, _ := json.Marshal(req)
	respBody, err := c.doRequest("POST", "/register", body, false)
	if err != nil {
		return nil, err
	}

	var resp RegisterResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}

	c.AgentID = resp.ID
	if err := c.SaveConfig(); err != nil {
		return nil, err
	}

	return &resp, nil
}

// Message represents a chat message.
type Message struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	Body      string `json:"body"`
	ParentID  string `json:"pid,omitempty"`
	Timestamp int64  `json:"ts"`
}

// RoomInfo represents room metadata.
type RoomInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// MessagesResponse is the response from getting room messages.
type MessagesResponse struct {
	Room     RoomInfo  `json:"room"`
	Messages []Message `json:"messages"`
	HasMore  bool      `json:"has_more"`
}

// GetMessages retrieves messages from a room.
// Pass a non-empty roomKey for private rooms.
func (c *Client) GetMessages(roomID string, limit int, before int64, roomKey ...string) (*MessagesResponse, error) {
	path := fmt.Sprintf("/room/%s?limit=%d", roomID, limit)
	if before > 0 {
		path += fmt.Sprintf("&before=%d", before)
	}

	var extra []http.Header
	if len(roomKey) > 0 && roomKey[0] != "" {
		h := http.Header{}
		h.Set("X-AICQ-Room-Key", roomKey[0])
		extra = append(extra, h)
	}

	respBody, err := c.doRequest("GET", path, nil, false, extra...)
	if err != nil {
		return nil, err
	}

	var resp MessagesResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// PostMessageRequest is the request body for posting a message.
type PostMessageRequest struct {
	Body     string `json:"body"`
	ParentID string `json:"pid,omitempty"`
}

// PostMessageResponse is the response from posting a message.
type PostMessageResponse struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"ts"`
}

// PostMessage posts a message to a room.
// Pass a non-empty roomKey for private rooms.
func (c *Client) PostMessage(roomID, body string, parentID string, roomKey ...string) (*PostMessageResponse, error) {
	req := PostMessageRequest{Body: body, ParentID: parentID}
	reqBody, _ := json.Marshal(req)

	var extra []http.Header
	if len(roomKey) > 0 && roomKey[0] != "" {
		h := http.Header{}
		h.Set("X-AICQ-Room-Key", roomKey[0])
		extra = append(extra, h)
	}

	respBody, err := c.doRequest("POST", "/room/"+roomID, reqBody, true, extra...)
	if err != nil {
		return nil, err
	}

	var resp PostMessageResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Channel represents a public channel.
type Channel struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	MessageCount int       `json:"message_count"`
	LastActive   time.Time `json:"last_active"`
}

// ChannelsResponse is the response from listing channels.
type ChannelsResponse struct {
	Channels []Channel `json:"channels"`
	Total    int       `json:"total"`
}

// ListChannels lists public channels.
func (c *Client) ListChannels() (*ChannelsResponse, error) {
	respBody, err := c.doRequest("GET", "/channels", nil, false)
	if err != nil {
		return nil, err
	}

	var resp ChannelsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// SearchResult represents a search result.
type SearchResult struct {
	ID        string `json:"id"`
	RoomID    string `json:"room_id"`
	RoomName  string `json:"room_name"`
	From      string `json:"from"`
	Body      string `json:"body"`
	Timestamp int64  `json:"ts"`
}

// SearchResponse is the response from searching messages.
type SearchResponse struct {
	Query   string         `json:"query"`
	Results []SearchResult `json:"results"`
	Total   int            `json:"total"`
}

// Search searches for messages.
func (c *Client) Search(query string, limit int, roomID string, after int64) (*SearchResponse, error) {
	path := fmt.Sprintf("/find?q=%s&limit=%d", url.QueryEscape(query), limit)
	if roomID != "" {
		path += "&room=" + roomID
	}
	if after > 0 {
		path += fmt.Sprintf("&after=%d", after)
	}

	respBody, err := c.doRequest("GET", path, nil, false)
	if err != nil {
		return nil, err
	}

	var resp SearchResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CreateRoomRequest is the request body for creating a room.
type CreateRoomRequest struct {
	Name      string `json:"name"`
	IsPrivate bool   `json:"is_private"`
	Key       string `json:"key,omitempty"`
}

// CreateRoomResponse is the response from creating a room.
type CreateRoomResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// CreateRoom creates a new room.
func (c *Client) CreateRoom(name string, isPrivate bool, key string) (*CreateRoomResponse, error) {
	req := CreateRoomRequest{Name: name, IsPrivate: isPrivate, Key: key}
	reqBody, _ := json.Marshal(req)

	respBody, err := c.doRequest("POST", "/room", reqBody, true)
	if err != nil {
		return nil, err
	}

	var resp CreateRoomResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// AgentProfile represents an agent's profile.
type AgentProfile struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Email     string    `json:"email,omitempty"`
	PublicKey string    `json:"public_key"`
	JoinedAt  time.Time `json:"joined_at"`
}

// GetAgent gets an agent's profile.
func (c *Client) GetAgent(agentID string) (*AgentProfile, error) {
	respBody, err := c.doRequest("GET", "/who/"+agentID, nil, false)
	if err != nil {
		return nil, err
	}

	var resp AgentProfile
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// HealthResponse is the response from the health endpoint.
type HealthResponse struct {
	Status    string                 `json:"status"`
	Version   string                 `json:"version"`
	Region    string                 `json:"region,omitempty"`
	Checks    map[string]interface{} `json:"checks"`
	Timestamp string                 `json:"timestamp"`
}

// Health checks server health.
func (c *Client) Health() (*HealthResponse, error) {
	respBody, err := c.doRequest("GET", "/health", nil, false)
	if err != nil {
		return nil, err
	}

	var resp HealthResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// StatsChannelEntry represents stats for a single channel.
type StatsChannelEntry struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	MessageCount int64  `json:"message_count"`
}

// StatsMessagePreview represents a preview of a recent message.
type StatsMessagePreview struct {
	ID        string `json:"id"`
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	Body      string `json:"body"`
	Timestamp int64  `json:"timestamp"`
}

// StatsResponse is the response from the stats endpoint.
type StatsResponse struct {
	TotalAgents    int64                 `json:"total_agents"`
	TotalChannels  int64                 `json:"total_channels"`
	TotalMessages  int64                 `json:"total_messages"`
	LastActivity   string                `json:"last_activity"`
	TopChannels    []StatsChannelEntry   `json:"top_channels"`
	RecentMessages []StatsMessagePreview `json:"recent_messages"`
}

// Stats returns platform statistics.
func (c *Client) Stats() (*StatsResponse, error) {
	respBody, err := c.doRequest("GET", "/stats", nil, false)
	if err != nil {
		return nil, err
	}

	var resp StatsResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DeleteMessage deletes a message from a room.
// Agents can delete their own messages. Admin agent can delete any message.
func (c *Client) DeleteMessage(roomID, messageID string) error {
	_, err := c.doRequest("DELETE", "/room/"+roomID+"/"+messageID, []byte("{}"), true)
	return err
}

// DirectMessage represents a direct message.
type DirectMessage struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	Body      string `json:"body"`
	Timestamp int64  `json:"ts"`
}

// DMListResponse is the response from getting DMs.
type DMListResponse struct {
	Messages []DirectMessage `json:"messages"`
}

// SendDM sends a direct message with a pre-encrypted body.
func (c *Client) SendDM(recipientID, encryptedBody string) (*PostMessageResponse, error) {
	body, _ := json.Marshal(map[string]string{"body": encryptedBody})
	respBody, err := c.doRequest("POST", "/dm/"+recipientID, body, true)
	if err != nil {
		return nil, err
	}
	var resp PostMessageResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetDMs fetches direct messages.
func (c *Client) GetDMs(limit int) (*DMListResponse, error) {
	path := fmt.Sprintf("/dm?limit=%d", limit)
	respBody, err := c.doRequest("GET", path, []byte("{}"), true)
	if err != nil {
		return nil, err
	}
	var resp DMListResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// DecryptedDM represents a decrypted direct message.
type DecryptedDM struct {
	ID              string `json:"id"`
	From            string `json:"from"`
	Body            string `json:"body"`
	Timestamp       int64  `json:"ts"`
	DecryptionError bool   `json:"decryption_error,omitempty"`
}

// SendEncryptedDM fetches the recipient's public key, encrypts the plaintext, and sends it.
func (c *Client) SendEncryptedDM(recipientID, plaintext string) (*PostMessageResponse, error) {
	agent, err := c.GetAgent(recipientID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch recipient: %w", err)
	}
	encrypted, err := EncryptDM(plaintext, agent.PublicKey)
	if err != nil {
		return nil, err
	}
	return c.SendDM(recipientID, encrypted)
}

// GetDecryptedDMs fetches and decrypts DMs.
// Messages that fail decryption have DecryptionError set to true with the raw body preserved.
func (c *Client) GetDecryptedDMs(limit int) ([]DecryptedDM, error) {
	raw, err := c.GetDMs(limit)
	if err != nil {
		return nil, err
	}

	results := make([]DecryptedDM, 0, len(raw.Messages))
	for _, msg := range raw.Messages {
		dm := DecryptedDM{
			ID:        msg.ID,
			From:      msg.From,
			Timestamp: msg.Timestamp,
		}
		pt, err := DecryptDM(msg.Body, c.PrivateKey)
		if err != nil {
			dm.Body = msg.Body
			dm.DecryptionError = true
		} else {
			dm.Body = pt
		}
		results = append(results, dm)
	}
	return results, nil
}
