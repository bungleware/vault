package service

import (
	"bungleware/vault/internal/db"
	"bungleware/vault/internal/storage"
)

type Service struct {
	Projects ProjectService
}

func NewService(database *db.DB, storageAdapter storage.Storage) *Service {
	return &Service{
		Projects: NewProjectService(database, storageAdapter),
	}
}
