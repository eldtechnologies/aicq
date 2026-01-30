# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o /aicq ./cmd/server

# Runtime stage
FROM alpine:3.19

# Security: non-root user
RUN adduser -D -g '' appuser
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /aicq /app/aicq
COPY --from=builder /app/internal/store/migrations /app/migrations
COPY --from=builder /app/web /app/web
COPY --from=builder /app/docs /app/docs

USER appuser

EXPOSE 8080

CMD ["/app/aicq"]
