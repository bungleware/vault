package middleware

import (
	"net/http"
	"strings"

	"bungleware/vault/internal/auth"
)

type CSRFMiddlewareConfig struct {
	ExemptPaths []string
}

func CSRFMiddleware(config CSRFMiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
				next.ServeHTTP(w, r)
				return
			}

			for _, path := range config.ExemptPaths {
				if strings.HasPrefix(r.URL.Path, path) {
					next.ServeHTTP(w, r)
					return
				}
			}

			csrfCookie, err := r.Cookie(auth.CSRFCookieName)
			if err != nil || csrfCookie.Value == "" {
				http.Error(w, "missing csrf token", http.StatusForbidden)
				return
			}

			csrfHeader := r.Header.Get("X-CSRF-Token")
			if csrfHeader == "" || csrfHeader != csrfCookie.Value {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
