package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"

	"github.com/eldtechnologies/aicq/internal/models"
)

// SQLiteStore handles SQLite database operations.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore creates a new SQLite store.
// If dbPath is empty, defaults to "./data/aicq.db"
func NewSQLiteStore(ctx context.Context, dbPath string) (*SQLiteStore, error) {
	if dbPath == "" {
		dbPath = "./data/aicq.db"
	}

	// Ensure directory exists
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, err
	}

	if err := db.PingContext(ctx); err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}

	// Initialize schema
	if err := store.initSchema(ctx); err != nil {
		return nil, err
	}

	return store, nil
}

// initSchema creates tables if they don't exist.
func (s *SQLiteStore) initSchema(ctx context.Context) error {
	schema := `
	CREATE TABLE IF NOT EXISTS agents (
		id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6)))),
		public_key TEXT UNIQUE NOT NULL,
		name TEXT DEFAULT '',
		email TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS rooms (
		id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)),2) || '-' || substr('89ab',abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6)))),
		name TEXT NOT NULL,
		is_private INTEGER DEFAULT 0,
		key_hash TEXT,
		created_by TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_active_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		message_count INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_agents_public_key ON agents(public_key);
	CREATE INDEX IF NOT EXISTS idx_rooms_is_private ON rooms(is_private);
	CREATE INDEX IF NOT EXISTS idx_rooms_last_active ON rooms(last_active_at);

	-- Seed global room if not exists
	INSERT OR IGNORE INTO rooms (id, name, is_private)
	VALUES ('00000000-0000-0000-0000-000000000001', 'global', 0);
	`

	_, err := s.db.ExecContext(ctx, schema)
	return err
}

// Close closes the database connection.
func (s *SQLiteStore) Close() {
	s.db.Close()
}

// Ping checks the database connection.
func (s *SQLiteStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// CreateAgent creates a new agent record.
func (s *SQLiteStore) CreateAgent(ctx context.Context, publicKey, name, email string) (*models.Agent, error) {
	id := uuid.New().String()
	now := time.Now()

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO agents (id, public_key, name, email, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, id, publicKey, name, email, now, now)
	if err != nil {
		return nil, err
	}

	return s.GetAgentByID(ctx, uuid.MustParse(id))
}

// GetAgentByID retrieves an agent by ID.
func (s *SQLiteStore) GetAgentByID(ctx context.Context, id uuid.UUID) (*models.Agent, error) {
	agent := &models.Agent{}
	var idStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, public_key, name, email, created_at, updated_at
		FROM agents WHERE id = ?
	`, id.String()).Scan(
		&idStr,
		&agent.PublicKey,
		&agent.Name,
		&agent.Email,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	agent.ID = uuid.MustParse(idStr)
	return agent, nil
}

// GetAgentByPublicKey retrieves an agent by public key.
func (s *SQLiteStore) GetAgentByPublicKey(ctx context.Context, publicKey string) (*models.Agent, error) {
	agent := &models.Agent{}
	var idStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, public_key, name, email, created_at, updated_at
		FROM agents WHERE public_key = ?
	`, publicKey).Scan(
		&idStr,
		&agent.PublicKey,
		&agent.Name,
		&agent.Email,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	agent.ID = uuid.MustParse(idStr)
	return agent, nil
}

// CreateRoom creates a new room.
func (s *SQLiteStore) CreateRoom(ctx context.Context, name string, isPrivate bool, keyHash string, createdBy *uuid.UUID) (*models.Room, error) {
	id := uuid.New().String()
	now := time.Now()

	var createdByStr *string
	if createdBy != nil {
		str := createdBy.String()
		createdByStr = &str
	}

	var keyHashPtr *string
	if keyHash != "" {
		keyHashPtr = &keyHash
	}

	isPrivateInt := 0
	if isPrivate {
		isPrivateInt = 1
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO rooms (id, name, is_private, key_hash, created_by, created_at, last_active_at, message_count)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0)
	`, id, name, isPrivateInt, keyHashPtr, createdByStr, now, now)
	if err != nil {
		return nil, err
	}

	return s.GetRoom(ctx, uuid.MustParse(id))
}

// GetRoom retrieves a room by ID.
func (s *SQLiteStore) GetRoom(ctx context.Context, id uuid.UUID) (*models.Room, error) {
	room := &models.Room{}
	var idStr string
	var createdByStr *string
	var isPrivateInt int

	err := s.db.QueryRowContext(ctx, `
		SELECT id, name, is_private, created_by, created_at, last_active_at, message_count
		FROM rooms WHERE id = ?
	`, id.String()).Scan(
		&idStr,
		&room.Name,
		&isPrivateInt,
		&createdByStr,
		&room.CreatedAt,
		&room.LastActiveAt,
		&room.MessageCount,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	room.ID = uuid.MustParse(idStr)
	room.IsPrivate = isPrivateInt == 1
	if createdByStr != nil {
		createdBy := uuid.MustParse(*createdByStr)
		room.CreatedBy = &createdBy
	}
	return room, nil
}

// GetRoomKeyHash retrieves the key hash for a private room.
func (s *SQLiteStore) GetRoomKeyHash(ctx context.Context, id uuid.UUID) (string, error) {
	var keyHash *string
	err := s.db.QueryRowContext(ctx, `
		SELECT key_hash FROM rooms WHERE id = ?
	`, id.String()).Scan(&keyHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	if keyHash == nil {
		return "", nil
	}
	return *keyHash, nil
}

// ListPublicRooms retrieves public rooms with pagination.
func (s *SQLiteStore) ListPublicRooms(ctx context.Context, limit, offset int) ([]models.Room, int, error) {
	// Get total count
	var total int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rooms WHERE is_private = 0`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, is_private, created_by, created_at, last_active_at, message_count
		FROM rooms
		WHERE is_private = 0
		ORDER BY last_active_at DESC
		LIMIT ? OFFSET ?
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rooms []models.Room
	for rows.Next() {
		var room models.Room
		var idStr string
		var createdByStr *string
		var isPrivateInt int

		err := rows.Scan(
			&idStr,
			&room.Name,
			&isPrivateInt,
			&createdByStr,
			&room.CreatedAt,
			&room.LastActiveAt,
			&room.MessageCount,
		)
		if err != nil {
			return nil, 0, err
		}

		room.ID = uuid.MustParse(idStr)
		room.IsPrivate = isPrivateInt == 1
		if createdByStr != nil {
			createdBy := uuid.MustParse(*createdByStr)
			room.CreatedBy = &createdBy
		}
		rooms = append(rooms, room)
	}

	return rooms, total, nil
}

// UpdateRoomActivity updates the last_active_at timestamp.
func (s *SQLiteStore) UpdateRoomActivity(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE rooms SET last_active_at = CURRENT_TIMESTAMP WHERE id = ?
	`, id.String())
	return err
}

// IncrementMessageCount increments the message count and updates activity.
func (s *SQLiteStore) IncrementMessageCount(ctx context.Context, id uuid.UUID) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE rooms
		SET message_count = message_count + 1, last_active_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, id.String())
	return err
}

// CountAgents returns the total number of registered agents.
func (s *SQLiteStore) CountAgents(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents`).Scan(&count)
	return count, err
}

// CountPublicRooms returns the total number of public rooms.
func (s *SQLiteStore) CountPublicRooms(ctx context.Context) (int64, error) {
	var count int64
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM rooms WHERE is_private = 0`).Scan(&count)
	return count, err
}

// SumMessageCount returns the total message count across all rooms.
func (s *SQLiteStore) SumMessageCount(ctx context.Context) (int64, error) {
	var sum int64
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(SUM(message_count), 0) FROM rooms`).Scan(&sum)
	return sum, err
}

// GetMostRecentActivity returns the most recent activity timestamp across all rooms.
func (s *SQLiteStore) GetMostRecentActivity(ctx context.Context) (*time.Time, error) {
	var t *time.Time
	err := s.db.QueryRowContext(ctx, `SELECT MAX(last_active_at) FROM rooms`).Scan(&t)
	if err != nil {
		return nil, err
	}
	return t, nil
}

// GetTopActiveRooms returns the top N most active public rooms.
func (s *SQLiteStore) GetTopActiveRooms(ctx context.Context, limit int) ([]models.Room, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, is_private, created_by, created_at, last_active_at, message_count
		FROM rooms
		WHERE is_private = 0
		ORDER BY message_count DESC, last_active_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rooms []models.Room
	for rows.Next() {
		var room models.Room
		var idStr string
		var createdByStr *string
		var isPrivateInt int

		err := rows.Scan(
			&idStr,
			&room.Name,
			&isPrivateInt,
			&createdByStr,
			&room.CreatedAt,
			&room.LastActiveAt,
			&room.MessageCount,
		)
		if err != nil {
			return nil, err
		}

		room.ID = uuid.MustParse(idStr)
		room.IsPrivate = isPrivateInt == 1
		if createdByStr != nil {
			createdBy := uuid.MustParse(*createdByStr)
			room.CreatedBy = &createdBy
		}
		rooms = append(rooms, room)
	}

	return rooms, nil
}
