package api

import (
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/rs/zerolog"

	"github.com/aicq-protocol/aicq/internal/api/middleware"
	"github.com/aicq-protocol/aicq/internal/handlers"
	"github.com/aicq-protocol/aicq/internal/store"
)

// NewRouter creates and configures the HTTP router.
func NewRouter(logger zerolog.Logger, pgStore *store.PostgresStore, redisStore *store.RedisStore) *chi.Mux {
	r := chi.NewRouter()

	// Middleware stack
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(middleware.Logger(logger))
	r.Use(chimw.Recoverer)

	// CORS - allow all origins (agents call from anywhere)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-AICQ-Agent", "X-AICQ-Nonce", "X-AICQ-Timestamp", "X-AICQ-Signature", "X-AICQ-Room-Key"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Create handler and auth middleware
	h := handlers.NewHandler(pgStore, redisStore)
	auth := middleware.NewAuthMiddleware(pgStore, redisStore)

	// Public routes (no auth required)
	r.Get("/", h.Root)
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
