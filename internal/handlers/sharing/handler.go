package sharing

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/storage"

	"golang.org/x/crypto/bcrypt"
)

type SharingHandler struct {
	db      *db.DB
	storage storage.Storage
}

func NewSharingHandler(database *db.DB, storageAdapter storage.Storage) *SharingHandler {
	return &SharingHandler{db: database, storage: storageAdapter}
}

func buildShareURL(r *http.Request, token string) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/share/%s", scheme, r.Host, token)
}

func hashSharePassword(password *string) (sql.NullString, error) {
	if password == nil || *password == "" {
		return sql.NullString{Valid: false}, nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		return sql.NullString{}, fmt.Errorf("failed to hash password: %w", err)
	}

	return sql.NullString{String: string(hash), Valid: true}, nil
}

func (h *SharingHandler) canManageTrackShares(ctx context.Context, track sqlc.Track, userID int64) (bool, error) {
	project, err := h.db.Queries.GetProjectByID(ctx, track.ProjectID)
	if err == nil && project.UserID == userID {
		return true, nil
	}

	share, err := h.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
		ProjectID: track.ProjectID,
		SharedTo:  userID,
	})
	if err == nil && share.CanEdit {
		return true, nil
	}

	return false, nil
}
