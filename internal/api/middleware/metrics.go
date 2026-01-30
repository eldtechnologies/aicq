package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/aicq-protocol/aicq/internal/metrics"
)

// statusWriter wraps http.ResponseWriter to capture status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Metrics returns middleware that records Prometheus metrics.
func Metrics(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status
		wrapped := &statusWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start).Seconds()
		path := normalizePath(r.URL.Path)

		metrics.HTTPRequestsTotal.WithLabelValues(
			r.Method, path, strconv.Itoa(wrapped.status),
		).Inc()

		metrics.HTTPRequestDuration.WithLabelValues(
			r.Method, path,
		).Observe(duration)
	})
}

// normalizePath normalizes paths to avoid high cardinality in metrics.
func normalizePath(path string) string {
	patterns := []struct{ prefix, normalized string }{
		{"/who/", "/who/:id"},
		{"/room/", "/room/:id"},
		{"/dm/", "/dm/:id"},
	}
	for _, p := range patterns {
		if strings.HasPrefix(path, p.prefix) && len(path) > len(p.prefix) {
			return p.normalized
		}
	}
	return path
}
