package middleware

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

// Logger returns a request logging middleware using zerolog.
func Logger(logger zerolog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Wrap response writer to capture status code
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			defer func() {
				logger.Info().
					Str("method", r.Method).
					Str("path", r.URL.Path).
					Int("status", ww.Status()).
					Dur("latency", time.Since(start)).
					Str("request_id", middleware.GetReqID(r.Context())).
					Str("remote_addr", r.RemoteAddr).
					Msg("request completed")
			}()

			next.ServeHTTP(ww, r)
		})
	}
}
