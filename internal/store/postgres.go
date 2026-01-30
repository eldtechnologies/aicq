package store

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aicq-protocol/aicq/internal/models"
)

// PostgresStore handles PostgreSQL database operations.
type PostgresStore struct {
	pool *pgxpool.Pool
}

// NewPostgresStore creates a new PostgreSQL store with a connection pool.
func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, err
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}

	return &PostgresStore{pool: pool}, nil
}

// Close closes the database connection pool.
func (s *PostgresStore) Close() {
	s.pool.Close()
}

// Ping checks the database connection.
func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// CreateAgent creates a new agent record.
func (s *PostgresStore) CreateAgent(ctx context.Context, publicKey, name, email string) (*models.Agent, error) {
	agent := &models.Agent{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agents (public_key, name, email)
		VALUES ($1, $2, $3)
		RETURNING id, public_key, name, email, created_at, updated_at
	`, publicKey, name, email).Scan(
		&agent.ID,
		&agent.PublicKey,
		&agent.Name,
		&agent.Email,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return agent, nil
}

// GetAgentByID retrieves an agent by ID.
func (s *PostgresStore) GetAgentByID(ctx context.Context, id uuid.UUID) (*models.Agent, error) {
	agent := &models.Agent{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, public_key, name, email, created_at, updated_at
		FROM agents WHERE id = $1
	`, id).Scan(
		&agent.ID,
		&agent.PublicKey,
		&agent.Name,
		&agent.Email,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return agent, nil
}

// GetAgentByPublicKey retrieves an agent by public key.
func (s *PostgresStore) GetAgentByPublicKey(ctx context.Context, publicKey string) (*models.Agent, error) {
	agent := &models.Agent{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, public_key, name, email, created_at, updated_at
		FROM agents WHERE public_key = $1
	`, publicKey).Scan(
		&agent.ID,
		&agent.PublicKey,
		&agent.Name,
		&agent.Email,
		&agent.CreatedAt,
		&agent.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return agent, nil
}

// CreateRoom creates a new room.
func (s *PostgresStore) CreateRoom(ctx context.Context, name string, isPrivate bool, keyHash string, createdBy *uuid.UUID) (*models.Room, error) {
	room := &models.Room{}
	var keyHashPtr *string
	if keyHash != "" {
		keyHashPtr = &keyHash
	}

	err := s.pool.QueryRow(ctx, `
		INSERT INTO rooms (name, is_private, key_hash, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, is_private, created_by, created_at, last_active_at, message_count
	`, name, isPrivate, keyHashPtr, createdBy).Scan(
		&room.ID,
		&room.Name,
		&room.IsPrivate,
		&room.CreatedBy,
		&room.CreatedAt,
		&room.LastActiveAt,
		&room.MessageCount,
	)
	if err != nil {
		return nil, err
	}
	return room, nil
}

// GetRoom retrieves a room by ID.
func (s *PostgresStore) GetRoom(ctx context.Context, id uuid.UUID) (*models.Room, error) {
	room := &models.Room{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, is_private, created_by, created_at, last_active_at, message_count
		FROM rooms WHERE id = $1
	`, id).Scan(
		&room.ID,
		&room.Name,
		&room.IsPrivate,
		&room.CreatedBy,
		&room.CreatedAt,
		&room.LastActiveAt,
		&room.MessageCount,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return room, nil
}

// GetRoomKeyHash retrieves the key hash for a private room.
func (s *PostgresStore) GetRoomKeyHash(ctx context.Context, id uuid.UUID) (string, error) {
	var keyHash *string
	err := s.pool.QueryRow(ctx, `
		SELECT key_hash FROM rooms WHERE id = $1
	`, id).Scan(&keyHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
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
func (s *PostgresStore) ListPublicRooms(ctx context.Context, limit, offset int) ([]models.Room, int, error) {
	// Get total count
	var total int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rooms WHERE is_private = FALSE`).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, is_private, created_by, created_at, last_active_at, message_count
		FROM rooms
		WHERE is_private = FALSE
		ORDER BY last_active_at DESC
		LIMIT $1 OFFSET $2
	`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var rooms []models.Room
	for rows.Next() {
		var room models.Room
		err := rows.Scan(
			&room.ID,
			&room.Name,
			&room.IsPrivate,
			&room.CreatedBy,
			&room.CreatedAt,
			&room.LastActiveAt,
			&room.MessageCount,
		)
		if err != nil {
			return nil, 0, err
		}
		rooms = append(rooms, room)
	}

	return rooms, total, nil
}

// UpdateRoomActivity updates the last_active_at timestamp.
func (s *PostgresStore) UpdateRoomActivity(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE rooms SET last_active_at = NOW() WHERE id = $1
	`, id)
	return err
}

// IncrementMessageCount increments the message count and updates activity.
func (s *PostgresStore) IncrementMessageCount(ctx context.Context, id uuid.UUID) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE rooms
		SET message_count = message_count + 1, last_active_at = NOW()
		WHERE id = $1
	`, id)
	return err
}
