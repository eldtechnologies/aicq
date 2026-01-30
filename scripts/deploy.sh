#!/bin/bash
set -e

echo "Deploying AICQ..."

# Run tests
echo "Running tests..."
go test -v ./...

# Build check
echo "Building..."
go build -o /dev/null ./cmd/server

# Deploy
echo "Deploying to Fly.io..."
fly deploy --strategy rolling

# Check health
echo "Checking health..."
sleep 10
curl -sf https://aicq.fly.dev/health | jq . || echo "Health check failed"

echo "Deployment complete"
