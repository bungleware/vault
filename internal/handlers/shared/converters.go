package shared

import (
	"database/sql"
	"fmt"

	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/models"
)

// ConvertProject converts a project to ProjectResponse
func ConvertProject(project sqlc.Project) ProjectResponse {
	desc := httputil.NullStringToPtr(project.Description)
	author := httputil.NullStringToPtr(project.AuthorOverride)
	notes := httputil.NullStringToPtr(project.Notes)
	notesAuthor := httputil.NullStringToPtr(project.NotesAuthorName)

	var notesUpdatedAt *string
	if project.NotesUpdatedAt.Valid {
		s := project.NotesUpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		notesUpdatedAt = &s
	}

	var quality *models.Quality
	if project.QualityOverride.Valid {
		q := models.Quality(project.QualityOverride.String)
		quality = &q
	}

	var coverURL *string
	if project.CoverArtPath.Valid {
		url := BuildCoverURL(project.PublicID, project.CoverArtUpdatedAt)
		coverURL = &url
	}

	var folderID *int64
	if project.FolderID.Valid {
		folderID = &project.FolderID.Int64
	}

	return ProjectResponse{
		ID:               project.ID,
		UserID:           project.UserID,
		PublicID:         project.PublicID,
		Name:             project.Name,
		Description:      desc,
		QualityOverride:  quality,
		AuthorOverride:   author,
		Notes:            notes,
		NotesAuthorName:  notesAuthor,
		NotesUpdatedAt:   notesUpdatedAt,
		CoverURL:         coverURL,
		FolderID:         folderID,
		VisibilityStatus: project.VisibilityStatus,
		AllowEditing:     project.AllowEditing,
		AllowDownloads:   project.AllowDownloads,
		OwnerUsername:    "",
		IsShared:         false,
		CreatedAt:        httputil.FormatNullTimeString(project.CreatedAt),
		UpdatedAt:        httputil.FormatNullTimeString(project.UpdatedAt),
	}
}

// ConvertProjectRowWithShared converts project rows (with username) to ProjectResponse
func ConvertProjectRowWithShared(projectRow interface{}, isShared bool) ProjectResponse {
	var (
		id, userID                                              int64
		publicID, name, visibilityStatus, ownerUsername         string
		description, qualityOverride, authorOverride            sql.NullString
		notes, notesAuthorName                                  sql.NullString
		coverArtPath                                            sql.NullString
		createdAt, updatedAt, coverArtUpdatedAt, notesUpdatedAt sql.NullTime
		folderID                                                sql.NullInt64
		allowEditing, allowDownloads                            bool
	)

	switch row := projectRow.(type) {
	case sqlc.ListProjectsByUserRow:
		id, userID, publicID, name = row.ID, row.UserID, row.PublicID, row.Name
		description, qualityOverride, authorOverride = row.Description, row.QualityOverride, row.AuthorOverride
		notes, notesAuthorName = row.Notes, row.NotesAuthorName
		coverArtPath, createdAt, updatedAt = row.CoverArtPath, row.CreatedAt, row.UpdatedAt
		coverArtUpdatedAt, notesUpdatedAt = row.CoverArtUpdatedAt, row.NotesUpdatedAt
		folderID, visibilityStatus = row.FolderID, row.VisibilityStatus
		allowEditing, allowDownloads, ownerUsername = row.AllowEditing, row.AllowDownloads, row.OwnerUsername
	case sqlc.ListRootProjectsRow:
		id, userID, publicID, name = row.ID, row.UserID, row.PublicID, row.Name
		description, qualityOverride, authorOverride = row.Description, row.QualityOverride, row.AuthorOverride
		notes, notesAuthorName = row.Notes, row.NotesAuthorName
		coverArtPath, createdAt, updatedAt = row.CoverArtPath, row.CreatedAt, row.UpdatedAt
		coverArtUpdatedAt, notesUpdatedAt = row.CoverArtUpdatedAt, row.NotesUpdatedAt
		folderID, visibilityStatus = row.FolderID, row.VisibilityStatus
		allowEditing, allowDownloads, ownerUsername = row.AllowEditing, row.AllowDownloads, row.OwnerUsername
	case sqlc.ListProjectsInFolderRow:
		id, userID, publicID, name = row.ID, row.UserID, row.PublicID, row.Name
		description, qualityOverride, authorOverride = row.Description, row.QualityOverride, row.AuthorOverride
		notes, notesAuthorName = row.Notes, row.NotesAuthorName
		coverArtPath, createdAt, updatedAt = row.CoverArtPath, row.CreatedAt, row.UpdatedAt
		coverArtUpdatedAt, notesUpdatedAt = row.CoverArtUpdatedAt, row.NotesUpdatedAt
		folderID, visibilityStatus = row.FolderID, row.VisibilityStatus
		allowEditing, allowDownloads, ownerUsername = row.AllowEditing, row.AllowDownloads, row.OwnerUsername
	}

	desc, author := httputil.NullStringToPtr(description), httputil.NullStringToPtr(authorOverride)
	notesPtr, notesAuthorPtr := httputil.NullStringToPtr(notes), httputil.NullStringToPtr(notesAuthorName)

	var notesUpdatedAtPtr *string
	if notesUpdatedAt.Valid {
		s := notesUpdatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		notesUpdatedAtPtr = &s
	}

	var quality *models.Quality
	if qualityOverride.Valid {
		q := models.Quality(qualityOverride.String)
		quality = &q
	}

	var coverURL *string
	if coverArtPath.Valid {
		url := BuildCoverURL(publicID, coverArtUpdatedAt)
		coverURL = &url
	}

	var folderIDPtr *int64
	if folderID.Valid {
		folderIDPtr = &folderID.Int64
	}

	return ProjectResponse{
		ID:               id,
		UserID:           userID,
		PublicID:         publicID,
		Name:             name,
		Description:      desc,
		QualityOverride:  quality,
		AuthorOverride:   author,
		Notes:            notesPtr,
		NotesAuthorName:  notesAuthorPtr,
		NotesUpdatedAt:   notesUpdatedAtPtr,
		CoverURL:         coverURL,
		FolderID:         folderIDPtr,
		VisibilityStatus: visibilityStatus,
		AllowEditing:     allowEditing,
		AllowDownloads:   allowDownloads,
		OwnerUsername:    ownerUsername,
		IsShared:         isShared,
		CreatedAt:        httputil.FormatNullTimeString(createdAt),
		UpdatedAt:        httputil.FormatNullTimeString(updatedAt),
	}
}

// ConvertProjectWithIsShared converts a project and sets the IsShared field
func ConvertProjectWithIsShared(project sqlc.Project, isShared bool) ProjectResponse {
	resp := ConvertProject(project)
	resp.IsShared = isShared
	return resp
}

// BuildCoverURL constructs the cover URL for a project
func BuildCoverURL(publicID string, updatedAt sql.NullTime) string {
	base := fmt.Sprintf("/api/projects/%s/cover", publicID)
	if updatedAt.Valid {
		return fmt.Sprintf("%s?t=%d", base, updatedAt.Time.Unix())
	}
	return base
}
