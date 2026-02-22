package service

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"log/slog"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/ids"
	"bungleware/vault/internal/storage"
)

type projectService struct {
	db      *db.DB
	storage storage.Storage
}

type ProjectService interface {
	CreateProject(ctx context.Context, input CreateProjectInput) (sqlc.Project, error)
	ListProjects(ctx context.Context, userID int64) ([]sqlc.ListProjectsByUserRow, error)
	ListRootProjects(ctx context.Context, userID int64) ([]sqlc.ListRootProjectsRow, error)
	ListProjectsByFolder(ctx context.Context, userID int64, folderID int64) ([]sqlc.ListProjectsInFolderRow, error)
	GetProject(ctx context.Context, publicID string, userID int64) (sqlc.Project, error)
	UpdateProject(ctx context.Context, input UpdateProjectInput) (sqlc.Project, error)
	MoveProject(ctx context.Context, publicID string, userID int64, folderID *int64) (sqlc.Project, error)
	MoveProjectsToFolder(ctx context.Context, publicIDs []string, userID int64, folderID int64) ([]sqlc.Project, error)
	MoveProjectsToFolderWithOrder(ctx context.Context, projects []ProjectWithOrder, userID int64, folderID int64) ([]sqlc.Project, error)
	DeleteProject(ctx context.Context, publicID string, userID int64) error
	UploadCover(ctx context.Context, input UploadCoverInput) (sqlc.Project, error)
	DeleteCover(ctx context.Context, publicID string, userID int64) (sqlc.Project, error)
	GetCoverStream(ctx context.Context, publicID string, userID int64, size string) (*CoverStream, error)
	MigrateCovers(ctx context.Context) error
}

type CreateProjectInput struct {
	UserID          int64
	Name            string
	Description     *string
	QualityOverride *string
	AuthorOverride  *string
	FolderID        *int64
}

type UpdateProjectInput struct {
	UserID          int64
	PublicID        string
	Name            *string
	Description     *string
	QualityOverride *string
	AuthorOverride  *string
	Notes           *string
	NotesAuthorName *string
}

type UploadCoverInput struct {
	UserID   int64
	PublicID string
	Filename string
	Reader   io.Reader
}

type ProjectWithOrder struct {
	ProjectID   string `json:"project_id"`
	CustomOrder int64  `json:"custom_order"`
}

type CoverStream struct {
	Reader       io.ReadCloser
	Size         int64
	MimeType     string
	UpdatedAt    time.Time
	HasUpdatedAt bool
}

func NewProjectService(database *db.DB, storageAdapter storage.Storage) ProjectService {
	return &projectService{
		db:      database,
		storage: storageAdapter,
	}
}

func ProjectRowToProject(row sqlc.GetProjectByPublicIDNoFilterRow) sqlc.Project {
	return sqlc.Project{
		ID:                      row.ID,
		UserID:                  row.UserID,
		PublicID:                row.PublicID,
		Name:                    row.Name,
		Description:             row.Description,
		CoverArtPath:            row.CoverArtPath,
		CoverArtMime:            row.CoverArtMime,
		CoverArtUpdatedAt:       row.CoverArtUpdatedAt,
		FolderID:                row.FolderID,
		FolderAddedAt:           row.FolderAddedAt,
		QualityOverride:         row.QualityOverride,
		AuthorOverride:          row.AuthorOverride,
		Notes:                   row.Notes,
		NotesAuthorName:         row.NotesAuthorName,
		NotesUpdatedAt:          row.NotesUpdatedAt,
		VisibilityStatus:        row.VisibilityStatus,
		AllowEditing:            row.AllowEditing,
		AllowDownloads:          row.AllowDownloads,
		PasswordHash:            row.PasswordHash,
		OriginInstanceUrl:       row.OriginInstanceUrl,
		SharedWithInstanceUsers: row.SharedWithInstanceUsers,
		CustomOrder:             row.CustomOrder,
		CreatedAt:               row.CreatedAt,
		UpdatedAt:               row.UpdatedAt,
	}
}

var allowedCoverExtensions = map[string]bool{
	".jpg":  true,
	".jpeg": true,
	".png":  true,
	".webp": true,
}

func (s *projectService) CreateProject(ctx context.Context, input CreateProjectInput) (sqlc.Project, error) {
	if input.Name == "" {
		return sqlc.Project{}, errors.New("project name is required")
	}

	if input.QualityOverride != nil {
		qo := *input.QualityOverride
		if qo != "source" && qo != "lossless" && qo != "lossy" {
			return sqlc.Project{}, errors.New("invalid quality override value")
		}
	}

	publicID, err := ids.NewPublicID()
	if err != nil {
		return sqlc.Project{}, fmt.Errorf("failed to generate project id: %w", err)
	}

	var qualityOverride sql.NullString
	if input.QualityOverride != nil {
		qualityOverride = sql.NullString{String: *input.QualityOverride, Valid: true}
	}

	var description sql.NullString
	if input.Description != nil {
		description = sql.NullString{String: *input.Description, Valid: true}
	}

	var authorOverride sql.NullString
	if input.AuthorOverride != nil {
		trimmed := strings.TrimSpace(*input.AuthorOverride)
		if trimmed != "" {
			authorOverride = sql.NullString{String: trimmed, Valid: true}
		}
	}

	var folderID sql.NullInt64
	if input.FolderID != nil {
		folderID = sql.NullInt64{Int64: *input.FolderID, Valid: true}
	}

	return s.db.CreateProject(ctx, sqlc.CreateProjectParams{
		UserID:          input.UserID,
		Name:            input.Name,
		Description:     description,
		QualityOverride: qualityOverride,
		PublicID:        publicID,
		AuthorOverride:  authorOverride,
		FolderID:        folderID,
	})
}

func (s *projectService) ListProjects(ctx context.Context, userID int64) ([]sqlc.ListProjectsByUserRow, error) {
	return s.db.ListProjectsByUser(ctx, userID)
}

func (s *projectService) ListRootProjects(ctx context.Context, userID int64) ([]sqlc.ListRootProjectsRow, error) {
	return s.db.ListRootProjects(ctx, userID)
}

func (s *projectService) ListProjectsByFolder(ctx context.Context, userID int64, folderID int64) ([]sqlc.ListProjectsInFolderRow, error) {
	return s.db.ListProjectsInFolder(ctx, sqlc.ListProjectsInFolderParams{
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
		UserID:   userID,
	})
}

func (s *projectService) GetProject(ctx context.Context, publicID string, userID int64) (sqlc.Project, error) {
	project, err := s.db.Queries.GetProjectByPublicIDNoFilter(ctx, publicID)
	if err != nil {
		return sqlc.Project{}, err
	}

	canAccess := project.UserID == userID
	if !canAccess {
		_, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if err != sql.ErrNoRows {
			canAccess = true
		}
	}

	if !canAccess {
		return sqlc.Project{}, sql.ErrNoRows
	}

	return ProjectRowToProject(project), nil
}

func (s *projectService) checkProjectEditPermission(ctx context.Context, publicID string, userID int64) (sqlc.Project, error) {
	project, err := s.db.Queries.GetProjectByPublicIDNoFilter(ctx, publicID)
	if err != nil {
		return sqlc.Project{}, err
	}

	isOwner := project.UserID == userID
	if !isOwner {
		share, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.Project{}, sql.ErrNoRows
		}
		if err != nil {
			return sqlc.Project{}, err
		}
		if !share.CanEdit {
			return sqlc.Project{}, errors.New("editing not allowed for this shared project")
		}
	}

	return ProjectRowToProject(project), nil
}

func (s *projectService) UpdateProject(ctx context.Context, input UpdateProjectInput) (sqlc.Project, error) {
	if input.QualityOverride != nil {
		qo := *input.QualityOverride
		if qo != "source" && qo != "lossless" && qo != "lossy" {
			return sqlc.Project{}, errors.New("invalid quality override value")
		}
	}

	currentProject, err := s.db.Queries.GetProjectByPublicIDNoFilter(ctx, input.PublicID)
	if err != nil {
		return sqlc.Project{}, err
	}

	isOwner := currentProject.UserID == input.UserID
	if !isOwner {
		share, err := s.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: currentProject.ID,
			SharedTo:  input.UserID,
		})
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.Project{}, sql.ErrNoRows
		}
		if err != nil {
			return sqlc.Project{}, err
		}
		if !share.CanEdit {
			return sqlc.Project{}, errors.New("editing not allowed for this shared project")
		}
	}

	name := currentProject.Name
	if input.Name != nil {
		name = *input.Name
	}

	description := currentProject.Description
	if input.Description != nil {
		description = sql.NullString{String: *input.Description, Valid: true}
	}

	qualityOverride := currentProject.QualityOverride
	if input.QualityOverride != nil {
		qualityOverride = sql.NullString{String: *input.QualityOverride, Valid: true}
	}

	authorOverride := currentProject.AuthorOverride
	if input.AuthorOverride != nil {
		trimmed := strings.TrimSpace(*input.AuthorOverride)
		if trimmed == "" {
			authorOverride = sql.NullString{}
		} else {
			authorOverride = sql.NullString{String: trimmed, Valid: true}
		}
	}

	notes := currentProject.Notes
	notesAuthorName := currentProject.NotesAuthorName
	var notesUpdatedAtTrigger interface{}
	if input.Notes != nil {
		notes = sql.NullString{String: *input.Notes, Valid: true}
		notesUpdatedAtTrigger = true
		if input.NotesAuthorName != nil {
			notesAuthorName = sql.NullString{String: *input.NotesAuthorName, Valid: true}
		}
	}

	return s.db.UpdateProject(ctx, sqlc.UpdateProjectParams{
		Name:            name,
		Description:     description,
		QualityOverride: qualityOverride,
		AuthorOverride:  authorOverride,
		Notes:           notes,
		NotesAuthorName: notesAuthorName,
		Column7:         notesUpdatedAtTrigger,
		ID:              currentProject.ID,
		UserID:          currentProject.UserID,
	})
}

func (s *projectService) MoveProject(ctx context.Context, publicID string, userID int64, folderID *int64) (sqlc.Project, error) {
	project, err := s.db.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{
		PublicID: publicID,
		UserID:   userID,
	})
	if err != nil {
		return sqlc.Project{}, err
	}

	var newFolderID sql.NullInt64
	var customOrder int64

	if folderID != nil {
		count, err := s.db.CheckFolderExists(ctx, sqlc.CheckFolderExistsParams{
			ID:     *folderID,
			UserID: userID,
		})
		if err != nil {
			return sqlc.Project{}, err
		}
		if count == 0 {
			return sqlc.Project{}, errors.New("folder not found")
		}
		newFolderID = sql.NullInt64{Int64: *folderID, Valid: true}
		slog.Debug("[MoveProject] calculating max order for owned project in folder", "project_id", project.ID, "folder_id", *folderID)
		maxOrderResult, err := s.db.GetMaxOrderInFolder(ctx, sqlc.GetMaxOrderInFolderParams{
			UserID:   userID,
			FolderID: sql.NullInt64{Int64: *folderID, Valid: true},
		})
		if err == nil {
			if maxOrder, ok := maxOrderResult.(int64); ok {
				customOrder = maxOrder + 1
				slog.Debug("[MoveProject] calculated custom order for owned project", "project_id", project.ID, "max_order", maxOrder, "custom_order", customOrder)
			} else {
				slog.Debug("[MoveProject] Failed to cast max_order result, using 0")
			}
		} else {
			slog.Debug("[MoveProject] error getting max order, using 0", "error", err)
		}
	} else {
		slog.Debug("[MoveProject] calculating max order for owned project at root", "project_id", project.ID)
		maxOrderResult, err := s.db.GetMaxOrderAtRoot(ctx, userID)
		if err == nil {
			if maxOrder, ok := maxOrderResult.(int64); ok {
				customOrder = maxOrder + 1
				slog.Debug("[MoveProject] calculated custom order for owned project at root", "project_id", project.ID, "max_order", maxOrder, "custom_order", customOrder)
			}
		}
	}

	updated, err := s.db.UpdateProjectFolder(ctx, sqlc.UpdateProjectFolderParams{
		FolderID: newFolderID,
		Column2:  newFolderID, // Same value for the CASE WHEN condition
		ID:       project.ID,
		UserID:   userID,
	})
	if err != nil {
		return sqlc.Project{}, err
	}
	updated, err = s.db.UpdateProjectCustomOrder(ctx, sqlc.UpdateProjectCustomOrderParams{
		CustomOrder: customOrder,
		ID:          project.ID,
		UserID:      userID,
	})
	if err != nil {
		return sqlc.Project{}, err
	}

	slog.Debug("[MoveProject] successfully moved owned project", "project_id", project.ID, "folder_id", newFolderID, "custom_order", customOrder)
	return updated, nil
}

func (s *projectService) MoveProjectsToFolderWithOrder(ctx context.Context, projects []ProjectWithOrder, userID int64, folderID int64) ([]sqlc.Project, error) {
	count, err := s.db.CheckFolderExists(ctx, sqlc.CheckFolderExistsParams{
		ID:     folderID,
		UserID: userID,
	})
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, errors.New("folder not found")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	queries := sqlc.New(tx)
	newFolderID := sql.NullInt64{Int64: folderID, Valid: true}
	results := make([]sqlc.Project, 0, len(projects))
	baseTime := time.Now()

	for i, projectInfo := range projects {
		project, err := queries.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{
			PublicID: projectInfo.ProjectID,
			UserID:   userID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get project %s: %w", projectInfo.ProjectID, err)
		}

		timestamp := baseTime.Add(time.Duration(i) * time.Millisecond)
		folderAddedAt := sql.NullTime{Time: timestamp, Valid: true}
		updated, err := queries.UpdateProjectFolderWithTimestamp(ctx, sqlc.UpdateProjectFolderWithTimestampParams{
			FolderID:      newFolderID,
			FolderAddedAt: folderAddedAt,
			ID:            project.ID,
			UserID:        userID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to move project %s: %w", projectInfo.ProjectID, err)
		}
		updated, err = queries.UpdateProjectCustomOrder(ctx, sqlc.UpdateProjectCustomOrderParams{
			CustomOrder: projectInfo.CustomOrder,
			ID:          project.ID,
			UserID:      userID,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to set order for project %s: %w", projectInfo.ProjectID, err)
		}

		results = append(results, updated)
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}

	return results, nil
}

func (s *projectService) MoveProjectsToFolder(ctx context.Context, publicIDs []string, userID int64, folderID int64) ([]sqlc.Project, error) {
	projects := make([]ProjectWithOrder, len(publicIDs))
	for i, id := range publicIDs {
		projects[i] = ProjectWithOrder{
			ProjectID:   id,
			CustomOrder: int64(i),
		}
	}
	return s.MoveProjectsToFolderWithOrder(ctx, projects, userID, folderID)
}

func (s *projectService) DeleteProject(ctx context.Context, publicID string, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	queries := sqlc.New(tx)

	project, err := queries.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{
		PublicID: publicID,
		UserID:   userID,
	})
	if err != nil {
		return err
	}

	err = queries.DeleteProject(ctx, sqlc.DeleteProjectParams{
		ID:     project.ID,
		UserID: userID,
	})
	if err != nil {
		return err
	}

	if err := s.storage.DeleteProject(ctx, storage.DeleteProjectInput{
		ProjectPublicID: project.PublicID,
	}); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *projectService) UploadCover(ctx context.Context, input UploadCoverInput) (sqlc.Project, error) {
	project, err := s.checkProjectEditPermission(ctx, input.PublicID, input.UserID)
	if err != nil {
		return sqlc.Project{}, err
	}

	ext := strings.ToLower(filepath.Ext(input.Filename))
	if !allowedCoverExtensions[ext] {
		return sqlc.Project{}, errors.New("unsupported cover format")
	}

	processed, err := ProcessCoverImage(input.Reader)
	if err != nil {
		return sqlc.Project{}, fmt.Errorf("failed to process cover image: %w", err)
	}

	saveResult, err := s.storage.SaveProcessedCover(ctx, storage.SaveProcessedCoverInput{
		ProjectPublicID: project.PublicID,
		SourceExt:       ext,
		Source:          processed.Source,
		Small:           processed.Small,
		Medium:          processed.Medium,
		Large:           processed.Large,
	})
	if err != nil {
		return sqlc.Project{}, err
	}

	return s.db.UpdateProjectCover(ctx, sqlc.UpdateProjectCoverParams{
		CoverArtPath: sql.NullString{String: saveResult.SourcePath, Valid: true},
		CoverArtMime: sql.NullString{String: saveResult.SourceMime, Valid: true},
		ID:           project.ID,
	})
}

func (s *projectService) DeleteCover(ctx context.Context, publicID string, userID int64) (sqlc.Project, error) {
	project, err := s.checkProjectEditPermission(ctx, publicID, userID)
	if err != nil {
		return sqlc.Project{}, err
	}

	if project.CoverArtPath.Valid {
		if err := s.storage.DeleteProjectCover(ctx, storage.DeleteProjectCoverInput{
			ProjectPublicID: project.PublicID,
		}); err != nil {
			return sqlc.Project{}, err
		}
	}

	return s.db.ClearProjectCover(ctx, project.ID)
}

func (s *projectService) GetCoverStream(ctx context.Context, publicID string, userID int64, size string) (*CoverStream, error) {
	project, err := s.GetProject(ctx, publicID, userID)
	if err != nil {
		return nil, err
	}

	if !project.CoverArtPath.Valid {
		return nil, sql.ErrNoRows
	}

	stream, err := s.storage.OpenProjectCover(ctx, storage.OpenProjectCoverInput{
		ProjectPublicID: project.PublicID,
		Path:            project.CoverArtPath.String,
		Size:            size,
	})
	if err != nil {
		return nil, err
	}

	mime := "application/octet-stream"
	if size != "" && size != "source" {
		mime = "image/webp"
	} else if project.CoverArtMime.Valid {
		mime = project.CoverArtMime.String
	}

	result := &CoverStream{
		Reader:   stream.Reader,
		Size:     stream.Size,
		MimeType: mime,
	}

	if project.CoverArtUpdatedAt.Valid {
		result.UpdatedAt = project.CoverArtUpdatedAt.Time
		result.HasUpdatedAt = true
	}

	return result, nil
}

func (s *projectService) MigrateCovers(ctx context.Context) error {
	projects, err := s.db.ListUnprocessedCovers(ctx)
	if err != nil {
		return fmt.Errorf("failed to list unprocessed covers: %w", err)
	}

	if len(projects) == 0 {
		slog.Info("no covers to migrate")
		return nil
	}

	slog.Info("migrating covers to multi-size format", "total_projects", len(projects))

	successCount := 0
	failureCount := 0

	for i, project := range projects {
		if !project.CoverArtPath.Valid {
			continue
		}

		stream, err := s.storage.OpenProjectCover(ctx, storage.OpenProjectCoverInput{
			ProjectPublicID: project.PublicID,
			Path:            project.CoverArtPath.String,
			Size:            "source",
		})
		if err != nil {
			slog.Warn("failed to open cover for project", "project_public_id", project.PublicID, "error", err)
			failureCount++
			continue
		}

		data, err := io.ReadAll(stream.Reader)
		stream.Reader.Close()
		if err != nil {
			slog.Warn("failed to read cover for project", "project_public_id", project.PublicID, "error", err)
			failureCount++
			continue
		}

		processed, err := ProcessCoverImage(bytes.NewReader(data))
		if err != nil {
			slog.Warn("failed to process cover for project", "project_public_id", project.PublicID, "error", err)
			failureCount++
			continue
		}

		ext := filepath.Ext(project.CoverArtPath.String)
		if ext == "" {
			ext = ".jpg"
		}

		_, err = s.storage.SaveProcessedCover(ctx, storage.SaveProcessedCoverInput{
			ProjectPublicID: project.PublicID,
			SourceExt:       ext,
			Source:          processed.Source,
			Small:           processed.Small,
			Medium:          processed.Medium,
			Large:           processed.Large,
		})
		if err != nil {
			slog.Warn("failed to save processed cover for project", "project_public_id", project.PublicID, "error", err)
			failureCount++
			continue
		}

		if err := s.db.MarkCoverProcessed(ctx, project.ID); err != nil {
			slog.Warn("failed to mark cover as processed for project", "project_public_id", project.PublicID, "error", err)
			failureCount++
			continue
		}

		successCount++
		if (i+1)%10 == 0 {
			slog.Info("cover migration progress", "processed", i+1, "total", len(projects), "successful", successCount)
		}
	}

	slog.Info("cover migration complete", "total", len(projects), "successful", successCount, "failed", failureCount)
	return nil
}
