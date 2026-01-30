package store

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/redis/go-redis/v9"

	"github.com/aicq-protocol/aicq/internal/models"
)

const (
	messageTTL   = 24 * time.Hour
	searchTTL    = 24 * time.Hour
	rateLimitTTL = time.Minute
)

// RedisStore handles Redis operations for messages and caching.
type RedisStore struct {
	client *redis.Client
}

// NewRedisStore creates a new Redis store.
func NewRedisStore(ctx context.Context, redisURL string) (*RedisStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, err
	}

	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, err
	}

	return &RedisStore{client: client}, nil
}

// Close closes the Redis connection.
func (s *RedisStore) Close() error {
	return s.client.Close()
}

// Ping checks the Redis connection.
func (s *RedisStore) Ping(ctx context.Context) error {
	return s.client.Ping(ctx).Err()
}

// roomMessagesKey returns the key for a room's message sorted set.
func roomMessagesKey(roomID string) string {
	return fmt.Sprintf("room:%s:messages", roomID)
}

// searchWordKey returns the key for a search word index.
func searchWordKey(word string) string {
	return fmt.Sprintf("search:words:%s", strings.ToLower(word))
}

// rateLimitKey returns the key for an agent's rate limit counter.
func rateLimitKey(agentID string) string {
	return fmt.Sprintf("ratelimit:%s", agentID)
}

// AddMessage stores a message in Redis.
func (s *RedisStore) AddMessage(ctx context.Context, msg *models.Message) error {
	// Generate ULID if not set
	if msg.ID == "" {
		msg.ID = ulid.Make().String()
	}

	// Set timestamp if not set
	if msg.Timestamp == 0 {
		msg.Timestamp = time.Now().UnixMilli()
	}

	// Serialize message
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	key := roomMessagesKey(msg.RoomID)

	// Add to sorted set
	err = s.client.ZAdd(ctx, key, redis.Z{
		Score:  float64(msg.Timestamp),
		Member: string(data),
	}).Err()
	if err != nil {
		return err
	}

	// Set TTL on the sorted set
	s.client.Expire(ctx, key, messageTTL)

	// Index for search
	if err := s.IndexMessage(ctx, msg); err != nil {
		// Log but don't fail - search indexing is best-effort
		_ = err
	}

	return nil
}

// GetRoomMessages retrieves messages from a room.
func (s *RedisStore) GetRoomMessages(ctx context.Context, roomID string, limit int, before int64) ([]models.Message, error) {
	key := roomMessagesKey(roomID)

	var maxScore string
	if before > 0 {
		maxScore = fmt.Sprintf("(%d", before) // exclusive
	} else {
		maxScore = "+inf"
	}

	// Get messages in reverse order (newest first)
	results, err := s.client.ZRevRangeByScore(ctx, key, &redis.ZRangeBy{
		Min:   "-inf",
		Max:   maxScore,
		Count: int64(limit),
	}).Result()
	if err != nil {
		return nil, err
	}

	messages := make([]models.Message, 0, len(results))
	for _, data := range results {
		var msg models.Message
		if err := json.Unmarshal([]byte(data), &msg); err != nil {
			continue
		}
		messages = append(messages, msg)
	}

	return messages, nil
}

// GetMessage retrieves a specific message by ID.
func (s *RedisStore) GetMessage(ctx context.Context, roomID, msgID string) (*models.Message, error) {
	key := roomMessagesKey(roomID)

	// Get all messages and find the one with matching ID
	results, err := s.client.ZRange(ctx, key, 0, -1).Result()
	if err != nil {
		return nil, err
	}

	for _, data := range results {
		var msg models.Message
		if err := json.Unmarshal([]byte(data), &msg); err != nil {
			continue
		}
		if msg.ID == msgID {
			return &msg, nil
		}
	}

	return nil, nil
}

// wordRegex matches word characters for search indexing.
var wordRegex = regexp.MustCompile(`\w+`)

// IndexMessage indexes a message for search.
func (s *RedisStore) IndexMessage(ctx context.Context, msg *models.Message) error {
	// Tokenize body
	words := wordRegex.FindAllString(strings.ToLower(msg.Body), -1)

	// Deduplicate words
	seen := make(map[string]bool)
	for _, word := range words {
		if len(word) < 3 || seen[word] {
			continue
		}
		seen[word] = true

		key := searchWordKey(word)
		ref := fmt.Sprintf("%s:%s", msg.RoomID, msg.ID)

		// Add to search index
		s.client.ZAdd(ctx, key, redis.Z{
			Score:  float64(msg.Timestamp),
			Member: ref,
		})
		s.client.Expire(ctx, key, searchTTL)
	}

	return nil
}

// Search searches for messages containing the query words.
func (s *RedisStore) Search(ctx context.Context, query string, limit int) ([]models.Message, error) {
	// Tokenize query
	words := wordRegex.FindAllString(strings.ToLower(query), -1)
	if len(words) == 0 {
		return nil, nil
	}

	var refs []string

	if len(words) == 1 {
		// Single word search
		key := searchWordKey(words[0])
		refs, _ = s.client.ZRevRange(ctx, key, 0, int64(limit)-1).Result()
	} else {
		// Multi-word search - use intersection
		keys := make([]string, len(words))
		for i, word := range words {
			keys[i] = searchWordKey(word)
		}

		// Store intersection in temp key
		tempKey := fmt.Sprintf("search:temp:%d", time.Now().UnixNano())
		s.client.ZInterStore(ctx, tempKey, &redis.ZStore{
			Keys:      keys,
			Aggregate: "MIN",
		})
		s.client.Expire(ctx, tempKey, time.Minute)

		refs, _ = s.client.ZRevRange(ctx, tempKey, 0, int64(limit)-1).Result()
		s.client.Del(ctx, tempKey)
	}

	// Fetch full messages
	messages := make([]models.Message, 0, len(refs))
	for _, ref := range refs {
		parts := strings.SplitN(ref, ":", 2)
		if len(parts) != 2 {
			continue
		}
		roomID, msgID := parts[0], parts[1]

		msg, err := s.GetMessage(ctx, roomID, msgID)
		if err != nil || msg == nil {
			continue
		}
		messages = append(messages, *msg)
	}

	return messages, nil
}

// CheckRateLimit checks if an agent has exceeded the rate limit.
func (s *RedisStore) CheckRateLimit(ctx context.Context, agentID string, limit int, window time.Duration) (bool, error) {
	key := rateLimitKey(agentID)
	count, err := s.client.Get(ctx, key).Int()
	if err != nil && err != redis.Nil {
		return false, err
	}
	return count < limit, nil
}

// IncrementRateLimit increments the rate limit counter.
func (s *RedisStore) IncrementRateLimit(ctx context.Context, agentID string, window time.Duration) error {
	key := rateLimitKey(agentID)

	pipe := s.client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, window)
	_, err := pipe.Exec(ctx)
	return err
}

// nonceKey returns the key for nonce tracking.
func nonceKey(agentID, nonce string) string {
	return fmt.Sprintf("nonce:%s:%s", agentID, nonce)
}

// IsNonceUsed checks if a nonce has been used.
func (s *RedisStore) IsNonceUsed(ctx context.Context, agentID, nonce string) bool {
	key := nonceKey(agentID, nonce)
	exists, _ := s.client.Exists(ctx, key).Result()
	return exists > 0
}

// MarkNonceUsed marks a nonce as used with a TTL.
func (s *RedisStore) MarkNonceUsed(ctx context.Context, agentID, nonce string, ttl time.Duration) {
	key := nonceKey(agentID, nonce)
	s.client.Set(ctx, key, "1", ttl)
}

// dmInboxKey returns the key for an agent's DM inbox.
func dmInboxKey(agentID string) string {
	return fmt.Sprintf("dm:%s:inbox", agentID)
}

// StoreDM stores a direct message in the recipient's inbox.
func (s *RedisStore) StoreDM(ctx context.Context, dm *models.DirectMessage) error {
	if dm.ID == "" {
		dm.ID = ulid.Make().String()
	}
	if dm.Timestamp == 0 {
		dm.Timestamp = time.Now().UnixMilli()
	}

	key := dmInboxKey(dm.ToID)
	dmJSON, err := json.Marshal(dm)
	if err != nil {
		return err
	}

	err = s.client.ZAdd(ctx, key, redis.Z{
		Score:  float64(dm.Timestamp),
		Member: string(dmJSON),
	}).Err()
	if err != nil {
		return err
	}

	// DMs expire after 7 days
	s.client.Expire(ctx, key, 7*24*time.Hour)

	return nil
}

// GetDMsForAgent retrieves direct messages for an agent.
func (s *RedisStore) GetDMsForAgent(ctx context.Context, agentID string, limit int) ([]models.DirectMessage, error) {
	if limit <= 0 {
		limit = 100
	}

	key := dmInboxKey(agentID)
	results, err := s.client.ZRevRange(ctx, key, 0, int64(limit)-1).Result()
	if err != nil {
		return nil, err
	}

	dms := make([]models.DirectMessage, 0, len(results))
	for _, data := range results {
		var dm models.DirectMessage
		if err := json.Unmarshal([]byte(data), &dm); err != nil {
			continue
		}
		dms = append(dms, dm)
	}

	return dms, nil
}
