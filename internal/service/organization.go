package service

import (
	"context"
	"database/sql"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type OrganizationService interface {
	GetUserProjectShare(ctx context.Context, projectID, userID int64) (sqlc.UserProjectShare, error)
	GetUserTrackShare(ctx context.Context, trackID, userID int64) (sqlc.UserTrackShare, error)
	CheckFolderExists(ctx context.Context, folderID, userID int64) (bool, error)
	GetMaxOrderInFolder(ctx context.Context, userID, folderID int64) (int64, error)
	GetMaxOrderAtRoot(ctx context.Context, userID int64) (int64, error)
	UpsertSharedProjectOrganization(ctx context.Context, params sqlc.UpsertSharedProjectOrganizationParams) (sqlc.UserSharedProjectOrganization, error)
	UpsertSharedTrackOrganization(ctx context.Context, params sqlc.UpsertSharedTrackOrganizationParams) (sqlc.UserSharedTrackOrganization, error)
	UpdateProjectCustomOrder(ctx context.Context, params sqlc.UpdateProjectCustomOrderParams) error
}

type organizationService struct {
	db *db.DB
}

func NewOrganizationService(database *db.DB) OrganizationService {
	return &organizationService{db: database}
}

func (s *organizationService) GetUserProjectShare(ctx context.Context, projectID, userID int64) (sqlc.UserProjectShare, error) {
	return s.db.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
		ProjectID: projectID,
		SharedTo:  userID,
	})
}

func (s *organizationService) GetUserTrackShare(ctx context.Context, trackID, userID int64) (sqlc.UserTrackShare, error) {
	return s.db.GetUserTrackShare(ctx, sqlc.GetUserTrackShareParams{
		TrackID:  trackID,
		SharedTo: userID,
	})
}

func (s *organizationService) CheckFolderExists(ctx context.Context, folderID, userID int64) (bool, error) {
	count, err := s.db.CheckFolderExists(ctx, sqlc.CheckFolderExistsParams{
		ID:     folderID,
		UserID: userID,
	})
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *organizationService) GetMaxOrderInFolder(ctx context.Context, userID, folderID int64) (int64, error) {
	result, err := s.db.GetMaxOrderInFolder(ctx, sqlc.GetMaxOrderInFolderParams{
		UserID:   userID,
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err != nil {
		return 0, err
	}
	n, _ := result.(int64)
	return n, nil
}

func (s *organizationService) GetMaxOrderAtRoot(ctx context.Context, userID int64) (int64, error) {
	result, err := s.db.GetMaxOrderAtRoot(ctx, userID)
	if err != nil {
		return 0, err
	}
	n, _ := result.(int64)
	return n, nil
}

func (s *organizationService) UpsertSharedProjectOrganization(ctx context.Context, params sqlc.UpsertSharedProjectOrganizationParams) (sqlc.UserSharedProjectOrganization, error) {
	return s.db.UpsertSharedProjectOrganization(ctx, params)
}

func (s *organizationService) UpsertSharedTrackOrganization(ctx context.Context, params sqlc.UpsertSharedTrackOrganizationParams) (sqlc.UserSharedTrackOrganization, error) {
	return s.db.UpsertSharedTrackOrganization(ctx, params)
}

func (s *organizationService) UpdateProjectCustomOrder(ctx context.Context, params sqlc.UpdateProjectCustomOrderParams) error {
	_, err := s.db.UpdateProjectCustomOrder(ctx, params)
	return err
}
