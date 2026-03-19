package service

import (
	"context"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type PreferencesService interface {
	GetUserPreferences(ctx context.Context, userID int64) (sqlc.UserPreference, error)
	UpdateUserPreferences(ctx context.Context, params sqlc.UpdateUserPreferencesParams) (sqlc.UserPreference, error)
}

type preferencesService struct {
	db *db.DB
}

func NewPreferencesService(database *db.DB) PreferencesService {
	return &preferencesService{db: database}
}

func (s *preferencesService) GetUserPreferences(ctx context.Context, userID int64) (sqlc.UserPreference, error) {
	return s.db.GetUserPreferences(ctx, userID)
}

func (s *preferencesService) UpdateUserPreferences(ctx context.Context, params sqlc.UpdateUserPreferencesParams) (sqlc.UserPreference, error) {
	return s.db.UpdateUserPreferences(ctx, params)
}
