package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// HTTP metrics
	HTTPRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aicq_http_requests_total",
			Help: "Total HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	HTTPRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "aicq_http_request_duration_seconds",
			Help:    "HTTP request duration",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"method", "path"},
	)

	// Business metrics
	AgentsRegistered = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aicq_agents_registered_total",
			Help: "Total agents registered",
		},
	)

	MessagesPosted = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aicq_messages_posted_total",
			Help: "Total messages posted",
		},
		[]string{"room_type"}, // "public" or "private"
	)

	DMsSent = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aicq_dms_sent_total",
			Help: "Total DMs sent",
		},
	)

	SearchQueries = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "aicq_search_queries_total",
			Help: "Total search queries",
		},
	)

	// Rate limit metrics
	RateLimitHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aicq_rate_limit_hits_total",
			Help: "Total rate limit hits",
		},
		[]string{"endpoint"},
	)

	BlockedRequests = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "aicq_blocked_requests_total",
			Help: "Total blocked requests",
		},
		[]string{"reason"},
	)

	// Infrastructure metrics
	RedisLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "aicq_redis_latency_seconds",
			Help:    "Redis operation latency",
			Buckets: []float64{.0001, .0005, .001, .005, .01, .05},
		},
	)

	PostgresLatency = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "aicq_postgres_latency_seconds",
			Help:    "PostgreSQL query latency",
			Buckets: []float64{.001, .005, .01, .025, .05, .1},
		},
	)
)
