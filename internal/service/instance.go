package service

import (
	"context"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type InstanceService interface {
	GetDBPath() string
	ForceCheckpoint() error
	CloseDB() error
	ReconnectDB() error

	GetInstanceSettings(ctx context.Context) (sqlc.InstanceSetting, error)
	InvalidateSessions(ctx context.Context) error
	CreateUser(ctx context.Context, params sqlc.CreateUserParams) (sqlc.User, error)
	CreateUserPreferences(ctx context.Context, params sqlc.CreateUserPreferencesParams) error
}

type instanceService struct {
	db *db.DB
}

func NewInstanceService(database *db.DB) InstanceService {
	return &instanceService{db: database}
}

func (s *instanceService) GetDBPath() string {
	return s.db.GetPath()
}

func (s *instanceService) ForceCheckpoint() error {
	return s.db.ForceCheckpoint()
}

func (s *instanceService) CloseDB() error {
	return s.db.Close()
}

func (s *instanceService) ReconnectDB() error {
	return s.db.Reconnect()
}

func (s *instanceService) GetInstanceSettings(ctx context.Context) (sqlc.InstanceSetting, error) {
	return s.db.Queries.GetInstanceSettings(ctx)
}

func (s *instanceService) InvalidateSessions(ctx context.Context) error {
	return s.db.Queries.InvalidateSessions(ctx)
}

func (s *instanceService) CreateUser(ctx context.Context, params sqlc.CreateUserParams) (sqlc.User, error) {
	return s.db.Queries.CreateUser(ctx, params)
}

func (s *instanceService) CreateUserPreferences(ctx context.Context, params sqlc.CreateUserPreferencesParams) error {
	return s.db.Queries.CreateUserPreferences(ctx, params)
}
