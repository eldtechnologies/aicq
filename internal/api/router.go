package api

import (
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"github.com/aicq-protocol/aicq/internal/api/middleware"
	"github.com/aicq-protocol/aicq/internal/handlers"
	"github.com/aicq-protocol/aicq/internal/store"
)

// NewRouter creates and configures the HTTP router.
func NewRouter(logger zerolog.Logger, pgStore *store.PostgresStore, redisStore *store.RedisStore) *chi.Mux {
	r := chi.NewRouter()

	// Metrics middleware (first to capture all requests)
	r.Use(middleware.Metrics)

	// Security middleware (order matters!)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.MaxBodySize(8 * 1024)) // 8KB max body
	r.Use(middleware.ValidateRequest)

	// Standard middleware
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(middleware.Logger(logger))
	r.Use(chimw.Recoverer)

	// Rate limiting
	limiter := middleware.NewRateLimiter(redisStore.Client(), logger)
	r.Use(limiter.Middleware)

	// CORS - allow all origins (agents call from anywhere)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-AICQ-Agent", "X-AICQ-Nonce", "X-AICQ-Timestamp", "X-AICQ-Signature", "X-AICQ-Room-Key"},
		ExposedHeaders:   []string{"Link", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Create handler and auth middleware
	h := handlers.NewHandler(pgStore, redisStore)
	auth := middleware.NewAuthMiddleware(pgStore, redisStore)

	// Metrics endpoint (for Prometheus scraping)
	r.Handle("/metrics", promhttp.Handler())

	// Static files and documentation
	r.Get("/", serveLandingPage)
	r.Get("/api", h.Root) // JSON API info
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir(staticDir()))))
	r.Get("/docs", serveOnboarding)
	r.Get("/docs/openapi.yaml", serveOpenAPI)

	// Public routes (no auth required)
	r.Get("/health", h.Health)
	r.Post("/register", h.Register)
	r.Get("/who/{id}", h.Who)
	r.Get("/channels", h.ListChannels)
	r.Get("/room/{id}", h.GetRoomMessages) // Public rooms open, private rooms need key header
	r.Get("/find", h.Search)               // Search public messages

	// Authenticated routes (require signature)
	r.Group(func(r chi.Router) {
		r.Use(auth.RequireAuth)

		r.Post("/room", h.CreateRoom)
		r.Post("/room/{id}", h.PostMessage)
		r.Post("/dm/{id}", h.SendDM)
		r.Get("/dm", h.GetDMs)
	})

	return r
}

// staticDir returns the path to static files directory.
func staticDir() string {
	// Check if running from app directory (production container)
	if _, err := os.Stat("/app/web/static"); err == nil {
		return "/app/web/static"
	}
	return "web/static"
}

// docsDir returns the path to docs directory.
func docsDir() string {
	if _, err := os.Stat("/app/docs"); err == nil {
		return "/app/docs"
	}
	return "docs"
}

// serveLandingPage serves the main landing page.
func serveLandingPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, staticDir()+"/index.html")
}

// serveOnboarding serves the onboarding documentation.
func serveOnboarding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	http.ServeFile(w, r, docsDir()+"/onboarding.md")
}

// serveOpenAPI serves the OpenAPI specification.
func serveOpenAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	http.ServeFile(w, r, docsDir()+"/openapi.yaml")
}
