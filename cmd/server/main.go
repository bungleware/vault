package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/db"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/handlers/projects"
	"bungleware/vault/internal/handlers/sharing"
	"bungleware/vault/internal/handlers/tracks"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/logger"
	"bungleware/vault/internal/middleware"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/storage"
	"bungleware/vault/internal/transcoding"

	"github.com/joho/godotenv"
)

var CommitSHA = "unknown"
var Version = "dev"

type Config struct {
	Port               string
	DataDir            string
	AuthConfig         auth.Config
	CORSAllowedOrigins []string
	PublicBaseURL      string
}

func loadConfig() Config {
	_ = godotenv.Load()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" || jwtSecret == "change-this-secret-key" {
		slog.Error("JWT_SECRET is required and must not use the default value")
		os.Exit(1)
	}

	accessTTL := getDurationEnv("ACCESS_TOKEN_TTL", 15*time.Minute)
	refreshTTL := getDurationEnv("REFRESH_TOKEN_TTL", 30*24*time.Hour)
	signedURLTTL := getDurationEnv("SIGNED_URL_TTL", 5*time.Minute)

	signedURLSecret := os.Getenv("SIGNED_URL_SECRET")
	if signedURLSecret == "" {
		slog.Error("SIGNED_URL_SECRET is required")
		os.Exit(1)
	}

	cookieDomain := os.Getenv("COOKIE_DOMAIN")
	cookieSecure := getBoolEnv("COOKIE_SECURE", false)
	cookieSameSite := os.Getenv("COOKIE_SAMESITE")
	if cookieSameSite == "" {
		cookieSameSite = "Lax"
	}

	tokenPepper := os.Getenv("TOKEN_PEPPER")
	if tokenPepper == "" {
		slog.Error("TOKEN_PEPPER is not set; refresh/reset tokens are hashed without a pepper")
		os.Exit(1)
	}

	return Config{
		Port:    port,
		DataDir: dataDir,
		AuthConfig: auth.Config{
			JWTSecret:           jwtSecret,
			JWTExpiration:       accessTTL,
			RefreshExpiration:   refreshTTL,
			SignedURLSecret:     signedURLSecret,
			SignedURLExpiration: signedURLTTL,
			TokenPepper:         tokenPepper,
			CookieDomain:        cookieDomain,
			CookieSecure:        cookieSecure,
			CookieSameSite:      cookieSameSite,
		},
		CORSAllowedOrigins: parseCommaEnv("CORS_ALLOWED_ORIGINS"),
		PublicBaseURL:      os.Getenv("PUBLIC_BASE_URL"),
	}
}

func parseCommaEnv(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		slog.Warn("Invalid duration env, using fallback", "key", key, "value", value)
		return fallback
	}
	return parsed
}

func getBoolEnv(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	if value == "true" || value == "1" || value == "yes" {
		return true
	}
	if value == "false" || value == "0" || value == "no" {
		return false
	}
	return fallback
}

func serveFrontend() http.Handler {
	distPath := "./frontend/dist"

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}

		path := filepath.Join(distPath, r.URL.Path)

		isIndexHTML := false
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			path = filepath.Join(distPath, "index.html")
			isIndexHTML = true
		} else if filepath.Base(path) == "index.html" {
			isIndexHTML = true
		}

		if isIndexHTML {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		} else {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}

		http.ServeFile(w, r, path)
	})
}

func main() {
	logLevel := slog.LevelInfo
	if l := os.Getenv("LOG_LEVEL"); l != "" {
		switch l {
		case "debug":
			logLevel = slog.LevelDebug
		case "warn":
			logLevel = slog.LevelWarn
		case "error":
			logLevel = slog.LevelError
		}
	}
	slog.SetDefault(slog.New(logger.NewPrettyHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})))
	slog.Info("Starting Vault server")

	config := loadConfig()
	slog.Info("Configuration loaded",
		"port", config.Port,
		"data_dir", config.DataDir,
	)

	if config.PublicBaseURL == "" {
		slog.Warn("PUBLIC_BASE_URL is not set; share URLs will be built from the request Host header, which is attacker-controlled")
	}

	database, err := db.New(db.Config{
		DataDir:        config.DataDir,
		DBFile:         "vault.db",
		MigrationsPath: "migrations",
	})
	if err != nil {
		slog.Error("Failed to initialize database", "error", err)
		os.Exit(1)
	}
	defer database.Close()
	slog.Info("Database initialized successfully")

	wsHub := handlers.NewWSHub()
	wsHandler := handlers.NewWebSocketHandler(wsHub, config.CORSAllowedOrigins)

	// WORKERS
	transcoder := transcoding.NewTranscoder(database, 2)
	transcoder.SetNotifier(wsHub)
	transcoder.Start()
	defer transcoder.Stop()
	slog.Info("Transcoding system initialized", "workers", 2)

	storageAdapter := storage.NewFilesystemStorage(config.DataDir)
	svc := service.NewService(database, storageAdapter, config.AuthConfig)

	go func() {
		slog.Info("Starting cover migration for existing projects")
		if err := svc.Projects.MigrateCovers(context.Background()); err != nil {
			slog.Warn("Cover migration encountered errors", "error", err)
		} else {
			slog.Info("Cover migration completed successfully")
		}
	}()

	authHandler := handlers.NewAuthHandler(svc.Auth, config.AuthConfig)
	adminHandler := handlers.NewAdminHandler(svc.Admin)
	prefsHandler := handlers.NewPreferencesHandler(svc.Preferences)
	statsHandler := handlers.NewStatsHandler(svc.Stats, Version, CommitSHA)
	instanceHandler := handlers.NewInstanceHandler(svc.Instance, config.DataDir, wsHub)
	mediaHandler := handlers.NewMediaHandler(config.AuthConfig)
	projectsHandler := projects.NewProjectsHandler(svc.Projects, database, config.DataDir)
	foldersHandler := handlers.NewFoldersHandler(svc.Folders)
	tracksHandler := tracks.NewTracksHandler(svc.Tracks, transcoder)
	versionsHandler := handlers.NewVersionsHandler(svc.Versions, svc.Tracks, storageAdapter, transcoder)
	streamingHandler := handlers.NewStreamingHandler(svc.Tracks)
	sharingHandler := sharing.NewSharingHandler(svc.Sharing, storageAdapter, config.PublicBaseURL, config.DataDir)
	collaborationHub := handlers.NewCollaborationHub()
	collaborationHandler := handlers.NewCollaborationWebSocketHandler(collaborationHub, config.CORSAllowedOrigins)
	notesHandler := handlers.NewNotesHandler(svc.Notes, svc.Tracks)
	organizationHandler := handlers.NewOrganizationHandler(svc.Organization)

	mux := http.NewServeMux()

	frontendHandler := serveFrontend()

	// Create rate limiters for public endpoints
	authRL := middleware.NewIPRateLimiter(5, 10)      // Auth endpoints: 5 req/min, burst 10
	refreshRL := middleware.NewIPRateLimiter(20, 30)  // Token refresh: 20 req/min, burst 30
	tokenRL := middleware.NewIPRateLimiter(10, 15)    // Token validation: 10 req/min, burst 15
	publicRL := middleware.NewIPRateLimiter(30, 40)   // Public info: 30 req/min, burst 40
	shareRL := middleware.NewIPRateLimiter(60, 80)    // Share access: 60 req/min, burst 80

	// Public endpoints with rate limiting
	mux.HandleFunc("GET /api/auth/check-users", publicRL.RateLimit(httputil.Wrap(authHandler.CheckUsersExists)))
	mux.HandleFunc("POST /api/auth/register", authRL.RateLimit(httputil.Wrap(authHandler.Register)))
	mux.HandleFunc("POST /api/auth/register-with-invite", authRL.RateLimit(httputil.Wrap(authHandler.RegisterWithInvite)))
	mux.HandleFunc("GET /api/auth/validate-invite-token", tokenRL.RateLimit(httputil.Wrap(authHandler.ValidateInviteToken)))
	mux.HandleFunc("POST /api/auth/reset-password", authRL.RateLimit(httputil.Wrap(authHandler.ResetPassword)))
	mux.HandleFunc("GET /api/auth/validate-reset-token", tokenRL.RateLimit(httputil.Wrap(authHandler.ValidateResetToken)))
	mux.HandleFunc("POST /api/auth/login", authRL.RateLimit(httputil.Wrap(authHandler.Login)))
	mux.HandleFunc("POST /api/auth/refresh", refreshRL.RateLimit(httputil.Wrap(authHandler.Refresh)))
	mux.HandleFunc("GET /api/share/{token}", shareRL.RateLimit(httputil.Wrap(sharingHandler.ValidateShareToken)))
	mux.HandleFunc("GET /api/share/{token}/stream", shareRL.RateLimit(httputil.Wrap(sharingHandler.StreamSharedTrack)))
	mux.HandleFunc("GET /api/share/{token}/stream/{trackId}", shareRL.RateLimit(httputil.Wrap(sharingHandler.StreamSharedProjectTrack)))
	mux.HandleFunc("GET /api/share/{token}/cover", shareRL.RateLimit(httputil.Wrap(sharingHandler.GetSharedProjectCover)))
	mux.HandleFunc("GET /api/share/{token}/download", shareRL.RateLimit(httputil.Wrap(sharingHandler.DownloadShared)))
	mux.HandleFunc("GET /api/share/{token}/track/{trackId}/download", shareRL.RateLimit(httputil.Wrap(sharingHandler.DownloadSharedProjectTrack)))
	mux.HandleFunc("PUT /api/share/{token}/track/{trackId}/update", shareRL.RateLimit(httputil.Wrap(sharingHandler.UpdateSharedTrackFromToken)))
	mux.HandleFunc("GET /api/instance/version", publicRL.RateLimit(httputil.Wrap(statsHandler.GetInstanceVersion)))

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	sessionValidator := func(userID int, issuedAt time.Time) bool {
		return svc.Auth.ValidateSession(context.Background(), userID, issuedAt)
	}

	authMW := middleware.AuthMiddleware(config.AuthConfig.JWTSecret, sessionValidator)
	optionalAuthMW := middleware.OptionalAuthMiddleware(config.AuthConfig.JWTSecret, sessionValidator)
	signedURLMW := middleware.SignedURLMiddleware(config.AuthConfig.SignedURLSecret, 30*time.Second)
	adminMW := middleware.AdminMiddleware(database.Queries)

	mux.Handle("GET /api/auth/me", authMW(httputil.Wrap(authHandler.Me)))
	mux.Handle("PUT /api/auth/username", authMW(httputil.Wrap(authHandler.UpdateUsername)))
	mux.Handle("DELETE /api/auth/me", authMW(httputil.Wrap(authHandler.DeleteSelf)))
	mux.Handle("POST /api/auth/logout", authMW(httputil.Wrap(authHandler.Logout)))

	mux.Handle("GET /api/users", authMW(adminMW(httputil.Wrap(adminHandler.ListAllUsersPublic))))

	mux.Handle("GET /api/admin/users", authMW(adminMW(httputil.Wrap(adminHandler.ListUsers))))
	mux.Handle("POST /api/admin/users/invite", authMW(adminMW(httputil.Wrap(adminHandler.CreateInvite))))
	mux.Handle("PUT /api/admin/users/{id}/role", authMW(adminMW(httputil.Wrap(adminHandler.UpdateUserRole))))
	mux.Handle("PUT /api/admin/users/{id}/rename", authMW(adminMW(httputil.Wrap(adminHandler.RenameUser))))
	mux.Handle("DELETE /api/admin/users/{id}", authMW(adminMW(httputil.Wrap(adminHandler.DeleteUser))))
	mux.Handle("POST /api/admin/users/{id}/reset-link", authMW(adminMW(httputil.Wrap(adminHandler.CreateResetLink))))

	mux.Handle("GET /api/admin/instance/export/size", authMW(adminMW(httputil.Wrap(instanceHandler.GetExportSize))))
	mux.Handle("GET /api/admin/instance/export", authMW(adminMW(httputil.Wrap(instanceHandler.ExportInstance))))
	mux.Handle("POST /api/admin/instance/import", authMW(adminMW(httputil.Wrap(instanceHandler.ImportInstance))))
	mux.Handle("POST /api/admin/instance/reset", authMW(adminMW(httputil.Wrap(instanceHandler.ResetInstance))))

	mux.Handle("GET /api/preferences", authMW(httputil.Wrap(prefsHandler.GetPreferences)))
	mux.Handle("PUT /api/preferences", authMW(httputil.Wrap(prefsHandler.UpdatePreferences)))

	mux.Handle("GET /api/stats/storage", authMW(httputil.Wrap(statsHandler.GetStorageStats)))
	mux.Handle("GET /api/stats/storage/global", authMW(httputil.Wrap(statsHandler.GetGlobalStorageStats)))
	mux.Handle("GET /api/instance", authMW(httputil.Wrap(statsHandler.GetInstanceInfo)))
	mux.Handle("PUT /api/instance/name", authMW(adminMW(httputil.Wrap(statsHandler.UpdateInstanceName))))

	mux.Handle("POST /api/projects", authMW(httputil.Wrap(projectsHandler.CreateProject)))
	mux.Handle("GET /api/projects", authMW(httputil.Wrap(projectsHandler.ListProjects)))
	mux.Handle("GET /api/projects/{id}", authMW(httputil.Wrap(projectsHandler.GetProject)))
	mux.Handle("PUT /api/projects/{id}", authMW(httputil.Wrap(projectsHandler.UpdateProject)))
	mux.Handle("PUT /api/projects/{id}/folder", authMW(httputil.Wrap(projectsHandler.MoveProject)))
	mux.Handle("POST /api/projects/move-to-folder", authMW(httputil.Wrap(projectsHandler.MoveProjectsToFolder)))
	mux.Handle("DELETE /api/projects/{id}", authMW(httputil.Wrap(projectsHandler.DeleteProject)))
	mux.Handle("PUT /api/projects/{id}/cover", authMW(httputil.Wrap(projectsHandler.UploadProjectCover)))
	mux.Handle("DELETE /api/projects/{id}/cover", authMW(httputil.Wrap(projectsHandler.DeleteProjectCover)))
	mux.Handle("GET /api/projects/{id}/cover", optionalAuthMW(signedURLMW(httputil.Wrap(projectsHandler.GetProjectCover))))
	mux.Handle("POST /api/projects/{id}/duplicate", authMW(httputil.Wrap(projectsHandler.DuplicateProject)))
	mux.Handle("GET /api/projects/{id}/export", authMW(httputil.Wrap(projectsHandler.ExportProject)))

	mux.Handle("POST /api/folders", authMW(httputil.Wrap(foldersHandler.CreateFolder)))
	mux.Handle("GET /api/folders", authMW(httputil.Wrap(foldersHandler.ListFolders)))
	mux.Handle("GET /api/folders/all", authMW(httputil.Wrap(foldersHandler.ListAllFolders)))
	mux.Handle("GET /api/folders/{id}", authMW(httputil.Wrap(foldersHandler.GetFolder)))
	mux.Handle("GET /api/folders/{id}/contents", authMW(httputil.Wrap(foldersHandler.GetFolderContents)))
	mux.Handle("PUT /api/folders/{id}", authMW(httputil.Wrap(foldersHandler.UpdateFolder)))
	mux.Handle("POST /api/folders/{id}/empty", authMW(httputil.Wrap(foldersHandler.EmptyFolder)))
	mux.Handle("DELETE /api/folders/{id}", authMW(httputil.Wrap(foldersHandler.DeleteFolder)))

	mux.Handle("POST /api/library/upload", authMW(httputil.Wrap(tracksHandler.UploadTrack)))
	mux.Handle("POST /api/tracks/reorder", authMW(httputil.Wrap(tracksHandler.UpdateTracksOrder)))
	mux.Handle("GET /api/tracks", authMW(httputil.Wrap(tracksHandler.ListTracks)))
	mux.Handle("GET /api/tracks/search", authMW(httputil.Wrap(tracksHandler.SearchTracks)))
	mux.Handle("GET /api/tracks/{id}", authMW(httputil.Wrap(tracksHandler.GetTrack)))
	mux.Handle("PUT /api/tracks/{id}", authMW(httputil.Wrap(tracksHandler.UpdateTrack)))
	mux.Handle("DELETE /api/tracks/{id}", authMW(httputil.Wrap(tracksHandler.DeleteTrack)))
	mux.Handle("POST /api/tracks/{id}/duplicate", authMW(httputil.Wrap(tracksHandler.DuplicateTrack)))

	mux.Handle("GET /api/tracks/{track_id}/versions", authMW(httputil.Wrap(versionsHandler.ListVersions)))
	mux.Handle("POST /api/tracks/{track_id}/versions/upload", authMW(httputil.Wrap(versionsHandler.UploadVersion)))
	mux.Handle("GET /api/tracks/{track_id}/versions/{id}/download", authMW(httputil.Wrap(versionsHandler.DownloadVersion)))
	mux.Handle("GET /api/versions/{id}", authMW(httputil.Wrap(versionsHandler.GetVersion)))
	mux.Handle("PUT /api/versions/{id}", authMW(httputil.Wrap(versionsHandler.UpdateVersion)))
	mux.Handle("POST /api/versions/{id}/activate", authMW(httputil.Wrap(versionsHandler.ActivateVersion)))
	mux.Handle("DELETE /api/versions/{id}", authMW(httputil.Wrap(versionsHandler.DeleteVersion)))

	mux.Handle("GET /api/stream/{id}", optionalAuthMW(signedURLMW(httputil.Wrap(streamingHandler.StreamTrack))))

	mux.Handle("POST /api/tracks/{id}/share", authMW(httputil.Wrap(sharingHandler.CreateShareToken)))
	mux.Handle("GET /api/share", authMW(httputil.Wrap(sharingHandler.ListShareTokens)))
	mux.Handle("PUT /api/share/{id}", authMW(httputil.Wrap(sharingHandler.UpdateShareToken)))
	mux.Handle("DELETE /api/share/{id}", authMW(httputil.Wrap(sharingHandler.DeleteShareToken)))

	mux.Handle("POST /api/projects/{id}/share", authMW(httputil.Wrap(sharingHandler.CreateProjectShareToken)))
	mux.Handle("GET /api/share/projects", authMW(httputil.Wrap(sharingHandler.ListProjectShareTokens)))
	mux.Handle("PUT /api/share/projects/{id}", authMW(httputil.Wrap(sharingHandler.UpdateProjectShareToken)))
	mux.Handle("DELETE /api/share/projects/{id}", authMW(httputil.Wrap(sharingHandler.DeleteProjectShareToken)))

	mux.Handle("PUT /api/tracks/{id}/visibility", authMW(httputil.Wrap(sharingHandler.UpdateTrackVisibility)))
	mux.Handle("PUT /api/projects/{id}/visibility", authMW(httputil.Wrap(sharingHandler.UpdateProjectVisibility)))

	mux.Handle("POST /api/share/accept/{token}", authMW(httputil.Wrap(sharingHandler.AcceptShare)))
	mux.Handle("GET /api/share/shared-with-me", authMW(httputil.Wrap(sharingHandler.ListSharedWithMe)))
	mux.Handle("DELETE /api/share/leave/{id}", authMW(httputil.Wrap(sharingHandler.LeaveShare)))

	mux.Handle("POST /api/projects/{id}/share-with-users", authMW(httputil.Wrap(sharingHandler.ShareProjectWithUsers)))
	mux.Handle("POST /api/tracks/{id}/share-with-users", authMW(httputil.Wrap(sharingHandler.ShareTrackWithUsers)))
	mux.Handle("GET /api/projects/{id}/share-users", authMW(httputil.Wrap(sharingHandler.ListProjectShareUsers)))
	mux.Handle("GET /api/tracks/{id}/share-users", authMW(httputil.Wrap(sharingHandler.ListTrackShareUsers)))
	mux.Handle("PUT /api/user-shares/projects/{shareId}", authMW(httputil.Wrap(sharingHandler.UpdateProjectSharePermissions)))
	mux.Handle("PUT /api/user-shares/tracks/{shareId}", authMW(httputil.Wrap(sharingHandler.UpdateTrackSharePermissions)))
	mux.Handle("GET /api/projects/shared-with-me", authMW(httputil.Wrap(sharingHandler.ListProjectsSharedWithMe)))
	mux.Handle("GET /api/tracks/shared-with-me", authMW(httputil.Wrap(sharingHandler.ListTracksSharedWithMe)))
	mux.Handle("DELETE /api/user-shares/projects/{id}", authMW(httputil.Wrap(sharingHandler.RevokeProjectShare)))
	mux.Handle("DELETE /api/user-shares/tracks/{id}", authMW(httputil.Wrap(sharingHandler.RevokeTrackShare)))
	mux.Handle("DELETE /api/projects/{id}/leave", authMW(httputil.Wrap(sharingHandler.LeaveSharedProject)))
	mux.Handle("DELETE /api/shared-tracks/{id}/leave", authMW(httputil.Wrap(sharingHandler.LeaveSharedTrack)))

	mux.Handle("PUT /api/shared-projects/{id}/organize", authMW(httputil.Wrap(organizationHandler.OrganizeSharedProject)))
	mux.Handle("PUT /api/shared-tracks/{id}/organize", authMW(httputil.Wrap(organizationHandler.OrganizeSharedTrack)))
	mux.Handle("POST /api/organize/bulk", authMW(httputil.Wrap(organizationHandler.BulkOrganize)))

	mux.Handle("GET /api/tracks/{trackId}/notes", authMW(httputil.Wrap(notesHandler.GetTrackNotes)))
	mux.Handle("PUT /api/tracks/{trackId}/notes", authMW(httputil.Wrap(notesHandler.UpsertTrackNote)))
	mux.Handle("GET /api/projects/{projectId}/notes", authMW(httputil.Wrap(notesHandler.GetProjectNotes)))
	mux.Handle("PUT /api/projects/{projectId}/notes", authMW(httputil.Wrap(notesHandler.UpsertProjectNote)))
	mux.Handle("DELETE /api/notes/{noteId}", authMW(httputil.Wrap(notesHandler.DeleteNote)))

	mux.Handle("GET /api/ws", authMW(http.HandlerFunc(wsHandler.HandleConnection)))
	mux.Handle("GET /api/ws/collaborate", authMW(http.HandlerFunc(collaborationHandler.HandleCollaboration)))

	mux.Handle("GET /api/media/stream/{id}", authMW(httputil.Wrap(mediaHandler.StreamURL)))
	mux.Handle("GET /api/media/projects/{id}/cover", authMW(httputil.Wrap(mediaHandler.ProjectCoverURL)))

	mux.Handle("/", frontendHandler)

	csrfMW := middleware.CSRFMiddleware(middleware.CSRFMiddlewareConfig{
		ExemptPaths: []string{
			"/api/auth/login",
			"/api/auth/register",
			"/api/auth/refresh",
			"/api/auth/reset-password",
			"/api/auth/validate-invite-token",
			"/api/auth/validate-reset-token",
			"/api/auth/check-users",
			"/api/health",
		},
		// Exempt only the unauthenticated share-token track update endpoint.
		// All other /api/share/ mutating endpoints require user auth and must stay CSRF-protected.
		ExemptFuncs: []func(r *http.Request) bool{
			func(r *http.Request) bool {
				return strings.HasPrefix(r.URL.Path, "/api/share/") &&
					strings.Contains(r.URL.Path, "/track/") &&
					strings.HasSuffix(r.URL.Path, "/update")
			},
		},
	})

	handler := middleware.CORS(middleware.CORSConfig{AllowedOrigins: config.CORSAllowedOrigins})(
		csrfMW(middleware.SecurityHeaders(middleware.Logging(mux))),
	)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", config.Port),
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("Server starting",
		"addr", server.Addr,
		"url", fmt.Sprintf("http://localhost%s", server.Addr),
	)
	if err := server.ListenAndServe(); err != nil {
		slog.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
