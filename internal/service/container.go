package service

import (
	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/db"
	"bungleware/vault/internal/storage"
)

type Service struct {
	Projects     ProjectService
	Auth         AuthService
	Tracks       TracksService
	Sharing      SharingService
	Stats        StatsService
	Admin        AdminService
	Preferences  PreferencesService
	Notes        NotesService
	Organization OrganizationService
	Versions     VersionsService
	Folders      FoldersService
	Instance     InstanceService
}

func NewService(database *db.DB, storageAdapter storage.Storage, authConfig auth.Config) *Service {
	return &Service{
		Projects:     NewProjectService(database, storageAdapter),
		Auth:         NewAuthService(database, authConfig),
		Tracks:       NewTracksService(database, storageAdapter),
		Sharing:      NewSharingService(database),
		Stats:        NewStatsService(database),
		Admin:        NewAdminService(database, authConfig),
		Preferences:  NewPreferencesService(database),
		Notes:        NewNotesService(database),
		Organization: NewOrganizationService(database),
		Versions:     NewVersionsService(database),
		Folders:      NewFoldersService(database),
		Instance:     NewInstanceService(database),
	}
}
