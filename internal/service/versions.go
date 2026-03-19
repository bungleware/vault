package service

import (
	"context"
	"database/sql"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

// DeleteVersionResult holds info needed by the handler to clean up storage after a DB delete.
type DeleteVersionResult struct {
	ProjectPublicID string
	TrackID         int64
}

type VersionsService interface {
	// Track lookup (also used by streaming handler)
	GetTrackByPublicID(ctx context.Context, publicID string) (sqlc.Track, error)
	GetTrackByID(ctx context.Context, trackID int64) (sqlc.Track, error)
	GetProjectByID(ctx context.Context, projectID int64) (sqlc.Project, error)

	// Version queries
	ListVersions(ctx context.Context, trackID int64) ([]sqlc.TrackVersion, error)
	GetVersion(ctx context.Context, versionID int64) (sqlc.TrackVersion, error)
	GetVersionWithOwnership(ctx context.Context, versionID int64) (sqlc.GetTrackVersionWithOwnershipRow, error)

	// Version mutations
	UpdateVersion(ctx context.Context, params sqlc.UpdateTrackVersionParams) (sqlc.TrackVersion, error)
	SetActiveVersion(ctx context.Context, versionID, trackID int64) error
	// DeleteVersion validates constraints and deletes from DB; caller handles storage cleanup.
	DeleteVersion(ctx context.Context, versionID int64) (DeleteVersionResult, error)

	// File operations
	GetTrackFile(ctx context.Context, versionID int64, quality string) (sqlc.TrackFile, error)
	GetCompletedTrackFile(ctx context.Context, versionID int64, quality string) (sqlc.TrackFile, error)

	// Upload helpers
	CountVersions(ctx context.Context, trackID int64) (int64, error)
	GetMaxVersionOrder(ctx context.Context, trackID int64) (int64, error)
	CreateVersion(ctx context.Context, params sqlc.CreateTrackVersionParams) (sqlc.TrackVersion, error)
	UpdateVersionDuration(ctx context.Context, versionID int64, duration float64) error
	CreateTrackFile(ctx context.Context, params sqlc.CreateTrackFileParams) (sqlc.TrackFile, error)
}

type versionsService struct {
	db *db.DB
}

func NewVersionsService(database *db.DB) VersionsService {
	return &versionsService{db: database}
}

func (s *versionsService) GetTrackByPublicID(ctx context.Context, publicID string) (sqlc.Track, error) {
	return s.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
}

func (s *versionsService) GetTrackByID(ctx context.Context, trackID int64) (sqlc.Track, error) {
	return s.db.Queries.GetTrackByID(ctx, trackID)
}

func (s *versionsService) GetProjectByID(ctx context.Context, projectID int64) (sqlc.Project, error) {
	return s.db.Queries.GetProjectByID(ctx, projectID)
}

func (s *versionsService) ListVersions(ctx context.Context, trackID int64) ([]sqlc.TrackVersion, error) {
	return s.db.Queries.ListTrackVersions(ctx, trackID)
}

func (s *versionsService) GetVersion(ctx context.Context, versionID int64) (sqlc.TrackVersion, error) {
	return s.db.Queries.GetTrackVersion(ctx, versionID)
}

func (s *versionsService) GetVersionWithOwnership(ctx context.Context, versionID int64) (sqlc.GetTrackVersionWithOwnershipRow, error) {
	return s.db.Queries.GetTrackVersionWithOwnership(ctx, versionID)
}

func (s *versionsService) UpdateVersion(ctx context.Context, params sqlc.UpdateTrackVersionParams) (sqlc.TrackVersion, error) {
	return s.db.Queries.UpdateTrackVersion(ctx, params)
}

func (s *versionsService) SetActiveVersion(ctx context.Context, versionID, trackID int64) error {
	return s.db.Queries.SetActiveVersion(ctx, sqlc.SetActiveVersionParams{
		ActiveVersionID: sql.NullInt64{Int64: versionID, Valid: true},
		ID:              trackID,
	})
}

func (s *versionsService) DeleteVersion(ctx context.Context, versionID int64) (DeleteVersionResult, error) {
	var result DeleteVersionResult

	err := s.db.WithTx(ctx, func(q *sqlc.Queries) error {
		versionWithOwnership, err := q.GetTrackVersionWithOwnership(ctx, versionID)
		if err != nil {
			return ErrNotFound
		}
		track, err := q.GetTrackByID(ctx, versionWithOwnership.TrackID)
		if err != nil {
			return ErrNotFound
		}

		if track.ActiveVersionID.Valid && track.ActiveVersionID.Int64 == versionID {
			return ErrBadRequest
		}

		count, err := q.CountTrackVersions(ctx, versionWithOwnership.TrackID)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrBadRequest
		}

		project, err := q.GetProjectByID(ctx, track.ProjectID)
		if err != nil {
			return ErrNotFound
		}

		result = DeleteVersionResult{
			ProjectPublicID: project.PublicID,
			TrackID:         track.ID,
		}

		return q.DeleteTrackVersion(ctx, versionID)
	})

	return result, err
}

func (s *versionsService) GetTrackFile(ctx context.Context, versionID int64, quality string) (sqlc.TrackFile, error) {
	return s.db.Queries.GetTrackFile(ctx, sqlc.GetTrackFileParams{
		VersionID: versionID,
		Quality:   quality,
	})
}

func (s *versionsService) GetCompletedTrackFile(ctx context.Context, versionID int64, quality string) (sqlc.TrackFile, error) {
	return s.db.Queries.GetCompletedTrackFile(ctx, sqlc.GetCompletedTrackFileParams{
		VersionID: versionID,
		Quality:   quality,
	})
}

func (s *versionsService) CountVersions(ctx context.Context, trackID int64) (int64, error) {
	return s.db.Queries.CountTrackVersions(ctx, trackID)
}

func (s *versionsService) GetMaxVersionOrder(ctx context.Context, trackID int64) (int64, error) {
	result, err := s.db.Queries.GetMaxVersionOrder(ctx, trackID)
	if err != nil {
		return 0, err
	}
	n, _ := result.(int64)
	return n, nil
}

func (s *versionsService) CreateVersion(ctx context.Context, params sqlc.CreateTrackVersionParams) (sqlc.TrackVersion, error) {
	return s.db.Queries.CreateTrackVersion(ctx, params)
}

func (s *versionsService) UpdateVersionDuration(ctx context.Context, versionID int64, duration float64) error {
	return s.db.Queries.UpdateTrackVersionDuration(ctx, sqlc.UpdateTrackVersionDurationParams{
		DurationSeconds: sql.NullFloat64{Float64: duration, Valid: true},
		ID:              versionID,
	})
}

func (s *versionsService) CreateTrackFile(ctx context.Context, params sqlc.CreateTrackFileParams) (sqlc.TrackFile, error) {
	return s.db.Queries.CreateTrackFile(ctx, params)
}
