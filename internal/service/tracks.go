package service

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/ids"
	"bungleware/vault/internal/storage"
)

// TrackAccessResult describes the level of access a user has to a track.
type TrackAccessResult struct {
	HasAccess      bool
	CanEdit        bool
	CanDownload    bool
	IsOwner        bool
	IsProjectOwner bool
}

// GetTrackResult contains everything the handler needs to build a track detail response.
type GetTrackResult struct {
	Track       sqlc.GetTrackWithDetailsRow
	Project     *sqlc.Project
	Owner       *sqlc.User
	FolderID    *int64
	Access      TrackAccessResult
}

// ListTracksByProjectResult contains the result of listing tracks for a specific project.
type ListTracksByProjectResult struct {
	Project        sqlc.Project
	Tracks         []sqlc.ListTracksWithDetailsByProjectIDRow
	IsProjectOwner bool
	ProjectShare   *sqlc.UserProjectShare
}

// UpdateTrackInput holds the fields that can be updated on a track.
type UpdateTrackInput struct {
	Title           *string
	Artist          *string
	Album           *string
	ProjectID       *int64
	Key             *string
	BPM             *int64
	Notes           *string
	NotesAuthorName *string
}

// TrackOrder pairs a track ID with its desired position.
type TrackOrder struct {
	ID    int64
	Order int64
}

// SaveUploadedTrackInput contains everything needed to persist an uploaded track.
type SaveUploadedTrackInput struct {
	ProjectIDStr string
	Title        string
	Artist       sql.NullString
	Album        sql.NullString
	OriginalName string
	Reader       io.Reader
}

// SaveUploadedTrackResult is returned after a successful upload.
type SaveUploadedTrackResult struct {
	Track     sqlc.Track
	Version   sqlc.TrackVersion
	SavedPath string
	Format    string
}

// TracksService is the interface for all track-related business logic.
type TracksService interface {
	CheckTrackAccess(ctx context.Context, trackID, projectID, userID int64) (TrackAccessResult, error)

	ListAllTracksByUser(ctx context.Context, userID int64) ([]sqlc.ListTracksByUserRow, error)
	ListTracksByProject(ctx context.Context, userID int64, projectIDStr string) (*ListTracksByProjectResult, error)
	GetTrack(ctx context.Context, userID int64, publicID string) (*GetTrackResult, error)
	UpdateTrack(ctx context.Context, userID int64, publicID string, input UpdateTrackInput) (sqlc.Track, error)
	DeleteTrack(ctx context.Context, userID int64, publicID string) error
	DuplicateTrack(ctx context.Context, userID int64, publicID string) (sqlc.Track, error)
	UpdateTracksOrder(ctx context.Context, userID int64, orders []TrackOrder) error
	SearchTracks(ctx context.Context, userID int64, query string, limit int64) ([]sqlc.SearchTracksAccessibleByUserRow, error)

	SaveUploadedTrack(ctx context.Context, userID int64, input SaveUploadedTrackInput) (*SaveUploadedTrackResult, error)
	UpdateVersionDuration(ctx context.Context, versionID int64, duration float64) error

	// Low-level lookups used by streaming and other handlers
	GetTrackByPublicID(ctx context.Context, publicID string) (sqlc.Track, error)
	GetTrackByID(ctx context.Context, trackID int64) (sqlc.Track, error)
	GetProjectByID(ctx context.Context, projectID int64) (sqlc.Project, error)
	GetUserPreferences(ctx context.Context, userID int64) (sqlc.UserPreference, error)
	GetCompletedTrackFile(ctx context.Context, versionID int64, quality string) (sqlc.TrackFile, error)
}

type tracksService struct {
	db      *db.DB
	storage storage.Storage
}

func NewTracksService(database *db.DB, storageAdapter storage.Storage) TracksService {
	return &tracksService{db: database, storage: storageAdapter}
}

func (s *tracksService) CheckTrackAccess(ctx context.Context, trackID, projectID, userID int64) (TrackAccessResult, error) {
	result := TrackAccessResult{}
	project, err := s.db.Queries.GetProjectByID(ctx, projectID)
	if err == nil && project.UserID == userID {
		result.HasAccess = true
		result.CanEdit = true
		result.CanDownload = true
		result.IsProjectOwner = true
		return result, nil
	}

	trackShare, err := s.db.Queries.GetUserTrackShare(ctx, sqlc.GetUserTrackShareParams{
		TrackID:  trackID,
		SharedTo: userID,
	})
	if err == nil {
		result.HasAccess = true
		result.CanEdit = trackShare.CanEdit
		result.CanDownload = trackShare.CanDownload
		return result, nil
	}

	projectShare, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
		ProjectID: projectID,
		SharedTo:  userID,
	})
	if err == nil {
		result.HasAccess = true
		result.CanEdit = projectShare.CanEdit
		result.CanDownload = projectShare.CanDownload
		return result, nil
	}

	return result, nil
}

func (s *tracksService) ListAllTracksByUser(ctx context.Context, userID int64) ([]sqlc.ListTracksByUserRow, error) {
	return s.db.Queries.ListTracksByUser(ctx, userID)
}

func (s *tracksService) ListTracksByProject(ctx context.Context, userID int64, projectIDStr string) (*ListTracksByProjectResult, error) {
	var project sqlc.Project

	if id, err := parseID(projectIDStr); err == nil {
		p, err := s.db.Queries.GetProjectByID(ctx, id)
		if err == nil {
			project = p
		}
	}

	if project.ID == 0 {
		p, err := s.db.Queries.GetProjectByPublicIDNoFilter(ctx, projectIDStr)
		if err == nil {
			project = ProjectRowToProject(p)
		}
	}

	if project.ID == 0 {
		return nil, ErrNotFound
	}

	isProjectOwner := project.UserID == userID
	var projectShare *sqlc.UserProjectShare

	if !isProjectOwner {
		share, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if err == sql.ErrNoRows {
			return nil, ErrForbidden
		}
		if err != nil {
			return nil, err
		}
		projectShare = &share
	}

	dbTracks, err := s.db.Queries.ListTracksWithDetailsByProjectID(ctx, project.ID)
	if err != nil {
		return nil, err
	}

	if !isProjectOwner && projectShare != nil {
		share, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if err == nil {
			projectShare = &share
		}
	}

	return &ListTracksByProjectResult{
		Project:        project,
		Tracks:         dbTracks,
		IsProjectOwner: isProjectOwner,
		ProjectShare:   projectShare,
	}, nil
}

func (s *tracksService) GetTrack(ctx context.Context, userID int64, publicID string) (*GetTrackResult, error) {
	trackRecord, err := s.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	access, err := s.CheckTrackAccess(ctx, trackRecord.ID, trackRecord.ProjectID, userID)
	if err != nil {
		return nil, err
	}
	if !access.HasAccess {
		return nil, ErrForbidden
	}

	track, err := s.db.Queries.GetTrackWithDetails(ctx, sqlc.GetTrackWithDetailsParams{
		ID:     trackRecord.ID,
		UserID: trackRecord.UserID,
	})
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	result := &GetTrackResult{Track: track, Access: access}

	project, err := s.db.Queries.GetProjectByID(ctx, trackRecord.ProjectID)
	if err == nil {
		result.Project = &project

		projectOwner, err := s.db.Queries.GetUserByID(ctx, project.UserID)
		if err == nil {
			result.Owner = &projectOwner
		}
	}

	// For shared tracks, look up the folder assignment in the sharer's organization
	if project.UserID != userID {
		org, err := s.db.Queries.GetUserSharedTrackOrganization(ctx, sqlc.GetUserSharedTrackOrganizationParams{
			UserID:  userID,
			TrackID: trackRecord.ID,
		})
		if err == nil && org.FolderID.Valid {
			result.FolderID = &org.FolderID.Int64
		}
	}

	return result, nil
}

func (s *tracksService) UpdateTrack(ctx context.Context, userID int64, publicID string, input UpdateTrackInput) (sqlc.Track, error) {
	currentTrack, err := s.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
	if err == sql.ErrNoRows {
		return sqlc.Track{}, ErrNotFound
	}
	if err != nil {
		return sqlc.Track{}, err
	}

	access, err := s.CheckTrackAccess(ctx, currentTrack.ID, currentTrack.ProjectID, userID)
	if err != nil {
		return sqlc.Track{}, err
	}
	if !access.HasAccess {
		return sqlc.Track{}, ErrForbidden
	}
	if !access.CanEdit {
		return sqlc.Track{}, ErrForbidden
	}

	if input.ProjectID != nil {
		_, err := s.db.Queries.GetProject(ctx, sqlc.GetProjectParams{
			ID:     *input.ProjectID,
			UserID: userID,
		})
		if err != nil {
			return sqlc.Track{}, ErrBadRequest
		}
	}

	title := currentTrack.Title
	if input.Title != nil {
		title = *input.Title
	}
	artist := currentTrack.Artist
	if input.Artist != nil {
		artist = sql.NullString{String: *input.Artist, Valid: true}
	}
	album := currentTrack.Album
	if input.Album != nil {
		album = sql.NullString{String: *input.Album, Valid: true}
	}
	projectID := currentTrack.ProjectID
	if input.ProjectID != nil {
		projectID = *input.ProjectID
	}
	key := currentTrack.Key
	if input.Key != nil {
		key = sql.NullString{String: *input.Key, Valid: true}
	}
	bpm := currentTrack.Bpm
	if input.BPM != nil {
		bpm = sql.NullInt64{Int64: *input.BPM, Valid: true}
	}
	notes := currentTrack.Notes
	notesAuthorName := currentTrack.NotesAuthorName
	if input.Notes != nil {
		notes = sql.NullString{String: *input.Notes, Valid: true}
		if input.NotesAuthorName != nil {
			notesAuthorName = sql.NullString{String: *input.NotesAuthorName, Valid: true}
		}
	}

	var notesUpdatedAtTrigger interface{}
	if input.Notes != nil {
		notesUpdatedAtTrigger = true
	}

	track, err := s.db.Queries.UpdateTrack(ctx, sqlc.UpdateTrackParams{
		Title:           title,
		Artist:          artist,
		Album:           album,
		ProjectID:       projectID,
		Key:             key,
		Bpm:             bpm,
		Notes:           notes,
		NotesAuthorName: notesAuthorName,
		Column9:         notesUpdatedAtTrigger,
		ID:              currentTrack.ID,
		UserID:          currentTrack.UserID,
	})
	if err == sql.ErrNoRows {
		return sqlc.Track{}, ErrNotFound
	}
	return track, err
}

func (s *tracksService) DeleteTrack(ctx context.Context, userID int64, publicID string) error {
	return s.db.WithTx(ctx, func(q *sqlc.Queries) error {
		track, err := q.GetTrackByPublicIDNoFilter(ctx, publicID)
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		access, err := s.CheckTrackAccess(ctx, track.ID, track.ProjectID, userID)
		if err != nil {
			return err
		}
		if !access.HasAccess {
			return ErrForbidden
		}
		if !access.CanEdit {
			return ErrForbidden
		}

		project, err := q.GetProjectByID(ctx, track.ProjectID)
		if err != nil {
			return err
		}

		if err := q.DeleteTrack(ctx, sqlc.DeleteTrackParams{
			ID:     track.ID,
			UserID: track.UserID,
		}); err != nil {
			return err
		}

		return s.storage.DeleteTrack(ctx, storage.DeleteTrackInput{
			ProjectPublicID: project.PublicID,
			TrackID:         track.ID,
		})
	})
}

func (s *tracksService) DuplicateTrack(ctx context.Context, userID int64, publicID string) (sqlc.Track, error) {
	var duplicateTrack sqlc.Track
	err := s.db.WithTx(ctx, func(q *sqlc.Queries) error {
		originalTrack, err := q.GetTrackByPublicID(ctx, sqlc.GetTrackByPublicIDParams{
			PublicID: publicID,
			UserID:   userID,
		})
		if err == sql.ErrNoRows {
			return ErrNotFound
		}
		if err != nil {
			return err
		}

		newPublicID, err := ids.NewPublicID()
		if err != nil {
			return err
		}

		newTitle := originalTrack.Title + " (Copy)"
		duplicateTrack, err = q.CreateTrack(ctx, sqlc.CreateTrackParams{
			UserID:    userID,
			ProjectID: originalTrack.ProjectID,
			Title:     newTitle,
			Artist:    originalTrack.Artist,
			Album:     originalTrack.Album,
			PublicID:  newPublicID,
		})
		if err != nil {
			return err
		}

		versions, err := q.ListTrackVersions(ctx, originalTrack.ID)
		if err != nil {
			return err
		}

		var newActiveVersionID int64
		for _, version := range versions {
			newVersion, err := q.CreateTrackVersion(ctx, sqlc.CreateTrackVersionParams{
				TrackID:         duplicateTrack.ID,
				VersionName:     version.VersionName,
				Notes:           version.Notes,
				DurationSeconds: version.DurationSeconds,
				VersionOrder:    version.VersionOrder,
			})
			if err != nil {
				return err
			}

			if originalTrack.ActiveVersionID.Valid && originalTrack.ActiveVersionID.Int64 == version.ID {
				newActiveVersionID = newVersion.ID
			}

			files, err := q.ListTrackFilesByVersion(ctx, version.ID)
			if err != nil {
				return err
			}

			for _, file := range files {
				oldPath := file.FilePath
				oldDir := filepath.Dir(oldPath)
				fileName := filepath.Base(oldPath)
				newDir := strings.Replace(oldDir,
					fmt.Sprintf("tracks/%d/versions/%d", originalTrack.ID, version.ID),
					fmt.Sprintf("tracks/%d/versions/%d", duplicateTrack.ID, newVersion.ID), 1)
				newPath := filepath.Join(newDir, fileName)

				if err := os.MkdirAll(newDir, 0o755); err != nil {
					return err
				}
				if err := copyFile(oldPath, newPath); err != nil {
					return err
				}

				newFile, err := q.CreateTrackFile(ctx, sqlc.CreateTrackFileParams{
					VersionID:         newVersion.ID,
					Quality:           file.Quality,
					FilePath:          newPath,
					FileSize:          file.FileSize,
					Format:            file.Format,
					Bitrate:           file.Bitrate,
					ContentHash:       file.ContentHash,
					TranscodingStatus: file.TranscodingStatus,
					OriginalFilename:  file.OriginalFilename,
				})
				if err != nil {
					return err
				}

				if file.Waveform.Valid {
					if err := q.UpdateWaveform(ctx, sqlc.UpdateWaveformParams{
						Waveform: file.Waveform,
						ID:       newFile.ID,
					}); err != nil {
						return err
					}
				}
			}
		}

		if newActiveVersionID != 0 {
			if err := q.SetActiveVersion(ctx, sqlc.SetActiveVersionParams{
				ActiveVersionID: sql.NullInt64{Int64: newActiveVersionID, Valid: true},
				ID:              duplicateTrack.ID,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return duplicateTrack, err
}

func (s *tracksService) UpdateTracksOrder(ctx context.Context, userID int64, orders []TrackOrder) error {
	if len(orders) == 0 {
		return nil
	}

	firstTrack, err := s.db.Queries.GetTrackByID(ctx, orders[0].ID)
	if err != nil {
		return ErrNotFound
	}

	project, err := s.db.Queries.GetProjectByID(ctx, firstTrack.ProjectID)
	if err != nil {
		return ErrNotFound
	}

	canEdit := project.UserID == userID
	if !canEdit {
		share, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if err == sql.ErrNoRows {
			return ErrForbidden
		}
		if err != nil {
			return err
		}
		if !share.CanEdit {
			return ErrForbidden
		}
	}

	for _, o := range orders {
		track, err := s.db.Queries.GetTrackByID(ctx, o.ID)
		if err != nil || track.ProjectID != project.ID {
			return ErrBadRequest
		}
	}

	for _, o := range orders {
		if err := s.db.Queries.UpdateTrackOrder(ctx, sqlc.UpdateTrackOrderParams{
			TrackOrder: o.Order,
			ID:         o.ID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *tracksService) SearchTracks(ctx context.Context, userID int64, query string, limit int64) ([]sqlc.SearchTracksAccessibleByUserRow, error) {
	return s.db.Queries.SearchTracksAccessibleByUser(ctx, sqlc.SearchTracksAccessibleByUserParams{
		UserID:      userID,
		SearchQuery: query,
		LimitCount:  limit,
	})
}

func (s *tracksService) SaveUploadedTrack(ctx context.Context, userID int64, input SaveUploadedTrackInput) (*SaveUploadedTrackResult, error) {
	var project sqlc.Project

	if id, err := parseID(input.ProjectIDStr); err == nil {
		p, err := s.db.Queries.GetProjectByID(ctx, id)
		if err == nil {
			project = p
		}
	}
	if project.ID == 0 {
		p, err := s.db.Queries.GetProjectByPublicIDNoFilter(ctx, input.ProjectIDStr)
		if err == nil {
			project = ProjectRowToProject(p)
		}
	}
	if project.ID == 0 {
		return nil, ErrNotFound
	}

	isProjectOwner := project.UserID == userID
	if !isProjectOwner {
		share, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if err == sql.ErrNoRows {
			return nil, ErrForbidden
		}
		if err != nil {
			return nil, err
		}
		if !share.CanEdit {
			return nil, ErrForbidden
		}
	}

	publicID, err := ids.NewPublicID()
	if err != nil {
		return nil, err
	}

	maxOrderResult, err := s.db.Queries.GetMaxTrackOrderByProject(ctx, project.ID)
	if err != nil {
		return nil, err
	}
	maxOrder, _ := maxOrderResult.(int64)

	track, err := s.db.Queries.CreateTrack(ctx, sqlc.CreateTrackParams{
		UserID:    userID,
		ProjectID: project.ID,
		Title:     input.Title,
		Artist:    input.Artist,
		Album:     input.Album,
		PublicID:  publicID,
	})
	if err != nil {
		return nil, err
	}

	if err := s.db.Queries.UpdateTrackOrder(ctx, sqlc.UpdateTrackOrderParams{
		TrackOrder: maxOrder + 1,
		ID:         track.ID,
	}); err != nil {
		return nil, err
	}

	versionName := strings.TrimSuffix(input.OriginalName, filepath.Ext(input.OriginalName))
	if versionName == "" {
		versionName = "Original Upload"
	}

	version, err := s.db.Queries.CreateTrackVersion(ctx, sqlc.CreateTrackVersionParams{
		TrackID:         track.ID,
		VersionName:     versionName,
		Notes:           sql.NullString{},
		DurationSeconds: sql.NullFloat64{},
		VersionOrder:    1,
	})
	if err != nil {
		return nil, err
	}

	if err := s.db.Queries.SetActiveVersion(ctx, sqlc.SetActiveVersionParams{
		ActiveVersionID: sql.NullInt64{Int64: version.ID, Valid: true},
		ID:              track.ID,
	}); err != nil {
		return nil, err
	}

	saveResult, err := s.storage.SaveTrackSource(ctx, storage.SaveTrackSourceInput{
		ProjectPublicID: project.PublicID,
		TrackID:         track.ID,
		VersionID:       version.ID,
		OriginalName:    input.OriginalName,
		Reader:          input.Reader,
	})
	if err != nil {
		return nil, err
	}

	ext := strings.ToLower(filepath.Ext(input.OriginalName))
	format := saveResult.Format
	if format == "" {
		format = strings.TrimPrefix(ext, ".")
	}

	if _, err := s.db.Queries.CreateTrackFile(ctx, sqlc.CreateTrackFileParams{
		VersionID:         version.ID,
		Quality:           "source",
		FilePath:          saveResult.Path,
		FileSize:          saveResult.Size,
		Format:            format,
		Bitrate:           sql.NullInt64{},
		ContentHash:       sql.NullString{},
		TranscodingStatus: sql.NullString{String: "completed", Valid: true},
		OriginalFilename:  sql.NullString{String: input.OriginalName, Valid: true},
	}); err != nil {
		return nil, err
	}

	return &SaveUploadedTrackResult{
		Track:     track,
		Version:   version,
		SavedPath: saveResult.Path,
		Format:    format,
	}, nil
}

func (s *tracksService) UpdateVersionDuration(ctx context.Context, versionID int64, duration float64) error {
	return s.db.Queries.UpdateTrackVersionDuration(ctx, sqlc.UpdateTrackVersionDurationParams{
		DurationSeconds: sql.NullFloat64{Float64: duration, Valid: true},
		ID:              versionID,
	})
}

func (s *tracksService) GetTrackByPublicID(ctx context.Context, publicID string) (sqlc.Track, error) {
	return s.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
}

func (s *tracksService) GetTrackByID(ctx context.Context, trackID int64) (sqlc.Track, error) {
	return s.db.Queries.GetTrackByID(ctx, trackID)
}

func (s *tracksService) GetProjectByID(ctx context.Context, projectID int64) (sqlc.Project, error) {
	return s.db.Queries.GetProjectByID(ctx, projectID)
}

func (s *tracksService) GetUserPreferences(ctx context.Context, userID int64) (sqlc.UserPreference, error) {
	return s.db.GetUserPreferences(ctx, userID)
}

func (s *tracksService) GetCompletedTrackFile(ctx context.Context, versionID int64, quality string) (sqlc.TrackFile, error) {
	return s.db.Queries.GetCompletedTrackFile(ctx, sqlc.GetCompletedTrackFileParams{
		VersionID: versionID,
		Quality:   quality,
	})
}

// parseID attempts to parse a string as an int64.
func parseID(s string) (int64, error) {
	var id int64
	_, err := fmt.Sscanf(s, "%d", &id)
	return id, err
}

// copyFile copies src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
