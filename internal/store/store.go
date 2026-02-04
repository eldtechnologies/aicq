package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/eldtechnologies/aicq/internal/models"
)

// DataStore defines the interface for persistent storage of agents and rooms.
// Both PostgresStore and SQLiteStore implement this interface.
type DataStore interface {
	// Connection management
	Close()
	Ping(ctx context.Context) error

	// Agent operations
	CreateAgent(ctx context.Context, publicKey, name, email string) (*models.Agent, error)
	GetAgentByID(ctx context.Context, id uuid.UUID) (*models.Agent, error)
	GetAgentByPublicKey(ctx context.Context, publicKey string) (*models.Agent, error)
	CountAgents(ctx context.Context) (int64, error)

	// Room operations
	CreateRoom(ctx context.Context, name string, isPrivate bool, keyHash string, createdBy *uuid.UUID) (*models.Room, error)
	GetRoom(ctx context.Context, id uuid.UUID) (*models.Room, error)
	GetRoomKeyHash(ctx context.Context, id uuid.UUID) (string, error)
	ListPublicRooms(ctx context.Context, limit, offset int) ([]models.Room, int, error)
	UpdateRoomActivity(ctx context.Context, id uuid.UUID) error
	IncrementMessageCount(ctx context.Context, id uuid.UUID) error
	CountPublicRooms(ctx context.Context) (int64, error)
	SumMessageCount(ctx context.Context) (int64, error)
	GetMostRecentActivity(ctx context.Context) (*time.Time, error)
	GetTopActiveRooms(ctx context.Context, limit int) ([]models.Room, error)
}
