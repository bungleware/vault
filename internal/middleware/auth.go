package middleware

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"bungleware/vault/internal/auth"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type contextKey string

const (
	UserIDKey   contextKey = "user_id"
	UsernameKey contextKey = "username"
	IsAdminKey  contextKey = "is_admin"
)

// SessionValidator checks if a token issued at a given time is still valid
type SessionValidator func(userID int, issuedAt time.Time) bool

// AuthMiddleware validates JWT tokens and adds user info to context
func createAuthMiddleware(jwtSecret string, sessionValidator ...SessionValidator) func(http.Handler) http.Handler {
	var validator SessionValidator
	if len(sessionValidator) > 0 {
		validator = sessionValidator[0]
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""
			if cookie, err := r.Cookie(auth.AccessTokenCookieName); err == nil {
				token = cookie.Value
			}
			if token == "" {
				authHeader := r.Header.Get("Authorization")
				if authHeader != "" {
					parts := strings.Split(authHeader, " ")
					if len(parts) == 2 && parts[0] == "Bearer" {
						token = parts[1]
					}
				}
			}

			// No token found
			if token == "" {
				slog.WarnContext(r.Context(), "Auth failed: missing authentication token",
					"path", r.URL.Path,
					"method", r.Method,
				)
				http.Error(w, "missing authentication token", http.StatusUnauthorized)
				return
			}

			// Validate token
			claims, err := auth.ValidateToken(token, jwtSecret)
			if err != nil {
				slog.WarnContext(r.Context(), "Auth failed: invalid or expired token",
					"path", r.URL.Path,
					"method", r.Method,
					"error", err.Error(),
				)
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Check if session is still valid (not invalidated by reset/import)
			if validator != nil && claims.IssuedAt != nil {
				if !validator(claims.UserID, claims.IssuedAt.Time) {
					slog.WarnContext(r.Context(), "Auth failed: session invalidated",
						"path", r.URL.Path,
						"method", r.Method,
					)
					http.Error(w, "session expired", http.StatusUnauthorized)
					return
				}
			}

			// Add user info to context
			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, UsernameKey, claims.Username)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthMiddleware validates JWT tokens from cookie or Authorization header.
func AuthMiddleware(jwtSecret string, sessionValidator ...SessionValidator) func(http.Handler) http.Handler {
	return createAuthMiddleware(jwtSecret, sessionValidator...)
}

// OptionalAuthMiddleware sets user context if token exists, but allows requests without a token.
func OptionalAuthMiddleware(jwtSecret string, sessionValidator ...SessionValidator) func(http.Handler) http.Handler {
	var validator SessionValidator
	if len(sessionValidator) > 0 {
		validator = sessionValidator[0]
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ""
			if cookie, err := r.Cookie(auth.AccessTokenCookieName); err == nil {
				token = cookie.Value
			}
			if token == "" {
				authHeader := r.Header.Get("Authorization")
				if authHeader != "" {
					parts := strings.Split(authHeader, " ")
					if len(parts) == 2 && parts[0] == "Bearer" {
						token = parts[1]
					}
				}
			}

			if token == "" {
				next.ServeHTTP(w, r)
				return
			}

			claims, err := auth.ValidateToken(token, jwtSecret)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			if validator != nil && claims.IssuedAt != nil {
				if !validator(claims.UserID, claims.IssuedAt.Time) {
					http.Error(w, "session expired", http.StatusUnauthorized)
					return
				}
			}

			ctx := context.WithValue(r.Context(), UserIDKey, claims.UserID)
			ctx = context.WithValue(ctx, UsernameKey, claims.Username)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserID extracts user ID from context
func GetUserID(ctx context.Context) (int, bool) {
	userID, ok := ctx.Value(UserIDKey).(int)
	return userID, ok
}

// GetUsername extracts username from context
func GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(UsernameKey).(string)
	return username, ok
}

type CORSConfig struct {
	AllowedOrigins []string
}

// CORS middleware for handling cross-origin requests
func CORS(config CORSConfig) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(config.AllowedOrigins))
	for _, origin := range config.AllowedOrigins {
		if origin != "" {
			allowed[origin] = struct{}{}
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if origin != "" {
				if _, ok := allowed[origin]; ok {
					w.Header().Set("Access-Control-Allow-Origin", origin)
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
					w.Header().Set("Access-Control-Expose-Headers", "Content-Range, Content-Length, Accept-Ranges, Content-Disposition")
					w.Header().Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AdminQuerier is the minimal interface needed for admin middleware
type AdminQuerier interface {
	GetUserByID(ctx context.Context, id int64) (sqlc.User, error)
}

// AdminMiddleware checks if the user is an admin
// Note: This should be used after AuthMiddleware to ensure user is authenticated
func AdminMiddleware(db AdminQuerier) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID, ok := GetUserID(r.Context())
			if !ok {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user is admin
			user, err := db.GetUserByID(r.Context(), int64(userID))
			if err != nil {
				slog.WarnContext(r.Context(), "Admin check failed: user not found",
					"user_id", userID,
					"error", err.Error(),
				)
				http.Error(w, "user not found", http.StatusNotFound)
				return
			}

			if !user.IsAdmin {
				slog.WarnContext(r.Context(), "Admin access denied",
					"user_id", userID,
				)
				http.Error(w, "admin access required", http.StatusForbidden)
				return
			}

			// Add admin flag to context for handlers
			ctx := context.WithValue(r.Context(), IsAdminKey, true)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetUserIsAdmin extracts admin status from context
func GetUserIsAdmin(ctx context.Context) bool {
	isAdmin, ok := ctx.Value(IsAdminKey).(bool)
	return ok && isAdmin
}

// responseWriter wraps http.ResponseWriter to capture status code and size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if rw.statusCode == 0 {
		rw.statusCode = http.StatusOK
	}
	size, err := rw.ResponseWriter.Write(b)
	rw.size += size
	return size, err
}

// Hijack implements http.Hijacker interface for WebSocket support
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := rw.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, http.ErrNotSupported
	}
	return hijacker.Hijack()
}

// Logging middleware logs HTTP requests with structured fields
func Logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     0,
			size:           0,
		}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Calculate duration
		duration := time.Since(start)

		// Skip logging for successful static file requests and health checks
		if wrapped.statusCode == 200 &&
			(r.URL.Path == "/api/health" ||
				!strings.HasPrefix(r.URL.Path, "/api/")) {
			return
		}

		// Build log attributes - keep it simple and readable
		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", wrapped.statusCode),
			slog.String("duration", duration.Round(time.Millisecond).String()),
		}

		// Add user info if available from context
		if userID, ok := GetUserID(r.Context()); ok {
			attrs = append(attrs, slog.Int("user_id", userID))
		}

		// Log at appropriate level based on status code
		level := slog.LevelInfo
		msg := "HTTP"
		if wrapped.statusCode >= 500 {
			level = slog.LevelError
			msg = "HTTP ERROR"
		} else if wrapped.statusCode >= 400 {
			level = slog.LevelWarn
			msg = "HTTP WARN"
		}

		slog.LogAttrs(r.Context(), level, msg, attrs...)
	})
}
