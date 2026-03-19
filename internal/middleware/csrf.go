package middleware

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"bungleware/vault/internal/auth"
)

type CSRFMiddlewareConfig struct {
	ExemptPaths []string
	ExemptFuncs []func(r *http.Request) bool
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

			for _, fn := range config.ExemptFuncs {
				if fn(r) {
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
			if csrfHeader == "" || subtle.ConstantTimeCompare([]byte(csrfHeader), []byte(csrfCookie.Value)) != 1 {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
