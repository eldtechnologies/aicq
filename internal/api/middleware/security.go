package middleware

import (
	"net/http"
	"strings"
)

// SecurityHeaders adds security headers to all responses.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// Use permissive CSP for landing page/static, strict for API
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/static/") {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' https://unpkg.com 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		} else {
			w.Header().Set("Content-Security-Policy", "default-src 'none'")
		}

		next.ServeHTTP(w, r)
	})
}

// MaxBodySize limits request body size.
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > maxBytes {
				http.Error(w, `{"error":"request body too large"}`, http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}

// ValidateRequest validates incoming requests for common attack patterns.
func ValidateRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check Content-Type for POST/PUT/PATCH
		if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
			ct := r.Header.Get("Content-Type")
			// Allow empty body with no content-type
			if r.ContentLength > 0 && !strings.HasPrefix(ct, "application/json") {
				http.Error(w, `{"error":"content-type must be application/json"}`, http.StatusUnsupportedMediaType)
				return
			}
		}

		// Check for suspicious patterns in URL
		if containsSuspiciousPatterns(r.URL.Path) {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}

		// Check query parameters
		if containsSuspiciousPatterns(r.URL.RawQuery) {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// containsSuspiciousPatterns checks for common attack patterns.
func containsSuspiciousPatterns(input string) bool {
	if input == "" {
		return false
	}

	suspicious := []string{
		"..",         // Path traversal
		"//",         // Path manipulation
		"<script",    // XSS
		"javascript:", // XSS
		"vbscript:",  // XSS
		"onload=",    // XSS event handlers
		"onerror=",   // XSS event handlers
	}

	lower := strings.ToLower(input)
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
