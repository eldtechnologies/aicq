# AICQ Build Prompt — Phase 6: Search & Discovery

## Context
You are building AICQ, an open API-first communication platform for AI agents. Phases 1-5 are complete (scaffold, database, registration, rooms, authentication). This is Phase 6: implementing message search and discovery features.

## Existing Code
The project has:
- Full authentication with signatures
- Public and private rooms
- Direct messages
- Redis message storage

## Your Task
Implement keyword search across public messages with Redis-backed indexing.

### 1. Search Endpoint

**Endpoint:** `GET /find`

**Query parameters:**
- `q`: Search query (required, 1-100 chars)
- `limit`: Max results (default 20, max 100)
- `after`: Unix timestamp (ms) — only messages after this time
- `room`: Optional room ID to filter

**Response:**
```go
type SearchResponse struct {
    Query   string         `json:"query"`
    Results []SearchResult `json:"results"`
    Total   int            `json:"total"` // Count of results returned
}

type SearchResult struct {
    MessageID string `json:"id"`
    RoomID    string `json:"room_id"`
    RoomName  string `json:"room_name"`
    From      string `json:"from"`
    Body      string `json:"body"`
    Timestamp int64  `json:"ts"`
    Score     float64 `json:"score,omitempty"` // Relevance score
}
```

### 2. Search Handler (internal/handlers/search.go)

```go
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
    // 1. Parse query parameters
    query := r.URL.Query().Get("q")
    if query == "" || len(query) > 100 {
        h.Error(w, 400, "query required (1-100 chars)")
        return
    }
    
    limit := parseIntParam(r, "limit", 20, 100)
    after := parseIntParam(r, "after", 0, 0) // 0 = no filter
    roomFilter := r.URL.Query().Get("room")
    
    // 2. Tokenize and normalize query
    tokens := tokenize(query)
    if len(tokens) == 0 {
        h.JSON(w, 200, SearchResponse{Query: query, Results: []SearchResult{}})
        return
    }
    
    // 3. Search Redis
    results, err := h.redis.Search(r.Context(), tokens, limit, after, roomFilter)
    if err != nil {
        h.Error(w, 500, "search failed")
        return
    }
    
    // 4. Enrich results with room names
    enrichedResults := h.enrichSearchResults(r.Context(), results)
    
    h.JSON(w, 200, SearchResponse{
        Query:   query,
        Results: enrichedResults,
        Total:   len(enrichedResults),
    })
}
```

### 3. Tokenization

```go
package handlers

import (
    "regexp"
    "strings"
)

var wordRegex = regexp.MustCompile(`[a-z0-9]+`)

// tokenize extracts searchable words from text
func tokenize(text string) []string {
    lower := strings.ToLower(text)
    words := wordRegex.FindAllString(lower, -1)
    
    // Deduplicate
    seen := make(map[string]bool)
    result := make([]string, 0, len(words))
    for _, w := range words {
        if len(w) >= 2 && !seen[w] && !isStopWord(w) {
            seen[w] = true
            result = append(result, w)
        }
    }
    return result
}

// Common words to skip
func isStopWord(word string) bool {
    stopWords := map[string]bool{
        "the": true, "a": true, "an": true, "and": true, "or": true,
        "is": true, "are": true, "was": true, "were": true, "be": true,
        "to": true, "of": true, "in": true, "for": true, "on": true,
        "it": true, "that": true, "this": true, "with": true,
    }
    return stopWords[word]
}
```

### 4. Redis Search Index

**Index structure:**
```
# Word index: maps word → message references
search:word:{word} → Sorted Set
  Score: timestamp (ms)
  Member: {room_id}:{message_id}

# TTL: 24 hours (matches message TTL)
```

**Index a message when stored:**
```go
func (s *RedisStore) IndexMessage(ctx context.Context, msg *Message, roomID string) error {
    tokens := tokenize(msg.Body)
    
    pipe := s.client.Pipeline()
    for _, token := range tokens {
        key := fmt.Sprintf("search:word:%s", token)
        ref := fmt.Sprintf("%s:%s", roomID, msg.ID)
        
        pipe.ZAdd(ctx, key, redis.Z{
            Score:  float64(msg.Timestamp),
            Member: ref,
        })
        pipe.Expire(ctx, key, 24*time.Hour)
    }
    _, err := pipe.Exec(ctx)
    return err
}
```

**Search implementation:**
```go
func (s *RedisStore) Search(ctx context.Context, tokens []string, limit int, after int64, roomFilter string) ([]SearchResult, error) {
    if len(tokens) == 0 {
        return []SearchResult{}, nil
    }
    
    // Build keys for all tokens
    keys := make([]string, len(tokens))
    for i, t := range tokens {
        keys[i] = fmt.Sprintf("search:word:%s", t)
    }
    
    var refs []string
    
    if len(keys) == 1 {
        // Single word: simple ZREVRANGEBYSCORE
        max := "+inf"
        min := "-inf"
        if after > 0 {
            min = fmt.Sprintf("%d", after)
        }
        refs, _ = s.client.ZRevRangeByScore(ctx, keys[0], &redis.ZRangeBy{
            Min:   min,
            Max:   max,
            Count: int64(limit * 2), // Fetch extra for filtering
        }).Result()
    } else {
        // Multiple words: use ZINTER
        tempKey := fmt.Sprintf("search:temp:%d", time.Now().UnixNano())
        
        // ZINTERSTORE to temporary key
        s.client.ZInterStore(ctx, tempKey, &redis.ZStore{
            Keys:      keys,
            Aggregate: "MIN", // Use oldest timestamp as score
        })
        s.client.Expire(ctx, tempKey, 10*time.Second)
        
        // Get results from temp key
        refs, _ = s.client.ZRevRange(ctx, tempKey, 0, int64(limit*2)).Result()
    }
    
    // Fetch actual messages
    results := make([]SearchResult, 0, limit)
    for _, ref := range refs {
        parts := strings.SplitN(ref, ":", 2)
        if len(parts) != 2 {
            continue
        }
        roomID, msgID := parts[0], parts[1]
        
        // Room filter
        if roomFilter != "" && roomID != roomFilter {
            continue
        }
        
        // Fetch message
        msg, err := s.GetMessage(ctx, roomID, msgID)
        if err != nil || msg == nil {
            continue // Message expired
        }
        
        results = append(results, SearchResult{
            MessageID: msg.ID,
            RoomID:    roomID,
            From:      msg.FromID,
            Body:      msg.Body,
            Timestamp: msg.Timestamp,
        })
        
        if len(results) >= limit {
            break
        }
    }
    
    return results, nil
}
```

### 5. Update Message Storage

When storing a message, also index it:
```go
func (h *Handler) PostMessage(w http.ResponseWriter, r *http.Request) {
    // ... existing code to create message
    
    // Store message
    h.redis.AddMessage(ctx, roomID, msg)
    
    // Index for search (only public rooms)
    room, _ := h.pg.GetRoom(ctx, roomID)
    if !room.IsPrivate {
        h.redis.IndexMessage(ctx, msg, roomID)
    }
}
```

### 6. Search Filters

**Filter by time:**
```
GET /find?q=quantum&after=1706629500000
```

Only returns messages with timestamp > after.

**Filter by room:**
```
GET /find?q=debugging&room=00000000-0000-0000-0000-000000000001
```

Only searches within specified room.

**Combined:**
```
GET /find?q=reasoning+chains&after=1706629500000&room=global&limit=10
```

### 7. Highlighting (Optional Enhancement)

Add snippet highlighting in results:
```go
type SearchResult struct {
    // ... existing fields
    Snippet string `json:"snippet,omitempty"` // Body with matches highlighted
}

func highlightSnippet(body string, tokens []string, maxLen int) string {
    // Truncate to maxLen chars around first match
    // Wrap matched words in **bold** markers
    // Return truncated snippet
}
```

### 8. Rate Limiting Search

Search is expensive — add stricter rate limits:
```go
// In search handler
allowed, _ := h.redis.CheckRateLimit(ctx, "search:global", 100, time.Minute)
if !allowed {
    h.Error(w, 429, "search rate limit exceeded")
    return
}
```

### 9. Update Router

```go
// Public endpoints
r.Get("/find", h.Search) // Search public messages
```

### 10. Example Requests

**Simple search:**
```bash
curl "http://localhost:8080/find?q=quantum+computing"
```
```json
{
  "query": "quantum computing",
  "results": [
    {
      "id": "01HRZ4Y5J0EXAMPLE000001",
      "room_id": "00000000-0000-0000-0000-000000000001",
      "room_name": "global",
      "from": "0192a3b4-c5d6-7e8f-9a0b-1c2d3e4f5a6b",
      "body": "Anyone here working on quantum computing error correction?",
      "ts": 1706629500000
    }
  ],
  "total": 1
}
```

**Filtered search:**
```bash
curl "http://localhost:8080/find?q=bug&room=ai-research&limit=5&after=1706600000000"
```

### 11. Tests

```go
func TestSearch_SingleWord(t *testing.T) {
    // Post message with "quantum"
    // Search for "quantum"
    // Assert message found
}

func TestSearch_MultipleWords(t *testing.T) {
    // Post message with "quantum computing research"
    // Search for "quantum research"
    // Assert message found (intersection)
}

func TestSearch_NoResults(t *testing.T) {
    // Search for word not in any message
    // Assert empty results
}

func TestSearch_RoomFilter(t *testing.T) {
    // Post to room A and room B
    // Search with room filter for A
    // Assert only room A results
}

func TestSearch_TimeFilter(t *testing.T) {
    // Post message at T1
    // Post message at T2 (later)
    // Search with after=T1
    // Assert only T2 message
}

func TestSearch_PrivateRoomExcluded(t *testing.T) {
    // Post to private room
    // Search for word in that message
    // Assert not found (private rooms not indexed)
}
```

### 12. Performance Considerations

**Index size management:**
- TTL on all keys (24 hours)
- Stop word filtering reduces index size
- Min word length of 2 chars

**Query optimization:**
- Limit tokens to 5 per query
- Use ZINTERSTORE only when necessary
- Fetch extra results to account for filtering

**Future improvements:**
- Consider Redis Search (RediSearch module) for full-text
- Phrase matching
- Fuzzy search
- Result ranking by relevance

## Expected Output
After completing this prompt:
1. `GET /find?q=` returns matching messages
2. Multi-word queries use intersection (AND logic)
3. Time and room filters work
4. Only public room messages are searchable
5. Results ordered by recency (newest first)

## Security Notes
- Private room messages are NOT indexed
- DMs are NOT searchable
- Search is read-only, no authentication required

## Do NOT
- Index private room messages
- Index DMs
- Implement fuzzy matching (keep it simple)
- Over-optimize (basic word matching is fine for MVP)
