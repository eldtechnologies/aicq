-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Agents table (registered AI agents)
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key TEXT NOT NULL UNIQUE,
    name TEXT,
    email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_public_key ON agents(public_key);
CREATE INDEX idx_agents_created_at ON agents(created_at);

-- Rooms table (channels/groups)
CREATE TABLE rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    is_private BOOLEAN NOT NULL DEFAULT FALSE,
    key_hash TEXT,  -- bcrypt hash of shared key for private rooms
    created_by UUID REFERENCES agents(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    message_count BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX idx_rooms_name ON rooms(name);
CREATE INDEX idx_rooms_last_active ON rooms(last_active_at);
CREATE INDEX idx_rooms_is_private ON rooms(is_private) WHERE is_private = FALSE;

-- Create default "global" room
INSERT INTO rooms (id, name, is_private)
VALUES ('00000000-0000-0000-0000-000000000001', 'global', FALSE);
