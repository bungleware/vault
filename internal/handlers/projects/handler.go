package projects

import (
	"archive/zip"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"log/slog"
	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/ids"
	"bungleware/vault/internal/service"
)

type ProjectsHandler struct {
	service service.ProjectService
	db      *db.DB
	dataDir string
}

func NewProjectsHandler(svc service.ProjectService, database *db.DB, dataDir string) *ProjectsHandler {
	return &ProjectsHandler{
		service: svc,
		db:      database,
		dataDir: dataDir,
	}
}

const maxCoverUploadSize = 20 << 20

func (h *ProjectsHandler) CreateProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	req, err := httputil.DecodeJSON[handlers.CreateProjectRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	var qualityOverride *string
	if req.QualityOverride != nil {
		s := string(*req.QualityOverride)
		qualityOverride = &s
	}

	project, err := h.service.CreateProject(r.Context(), service.CreateProjectInput{
		UserID:          int64(userID),
		Name:            req.Name,
		Description:     req.Description,
		QualityOverride: qualityOverride,
		AuthorOverride:  req.AuthorOverride,
		FolderID:        req.FolderID,
	})
	if err != nil {
		if err.Error() == "project name is required" || err.Error() == "invalid quality override value" {
			return apperr.NewBadRequest(err.Error())
		}
		return apperr.NewInternal("failed to create project", err)
	}

	return httputil.CreatedResult(w, shared.ConvertProject(project))
}

func (h *ProjectsHandler) ListProjects(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	folderIDStr := r.URL.Query().Get("folder_id")

	response := make([]shared.ProjectResponse, 0)

	switch folderIDStr {
	case "":
		projectRows, err := h.service.ListProjects(r.Context(), int64(userID))
		if err != nil {
			return apperr.NewInternal("failed to query projects", err)
		}

		for _, row := range projectRows {
			response = append(response, shared.ConvertProjectRowWithShared(row, false))
		}
	case "root":
		rootRows, err := h.service.ListRootProjects(r.Context(), int64(userID))
		if err != nil {
			return apperr.NewInternal("failed to query projects", err)
		}

		for _, row := range rootRows {
			response = append(response, shared.ConvertProjectRowWithShared(row, false))
		}
	default:
		folderID, parseErr := strconv.ParseInt(folderIDStr, 10, 64)
		if parseErr != nil {
			return apperr.NewBadRequest("invalid folder_id")
		}
		folderRows, err := h.service.ListProjectsByFolder(r.Context(), int64(userID), folderID)
		if err != nil {
			return apperr.NewInternal("failed to query projects", err)
		}

		for _, row := range folderRows {
			response = append(response, shared.ConvertProjectRowWithShared(row, false))
		}
	}

	var sharedProjects []sqlc.Project
	if folderIDStr == "root" || folderIDStr == "" {
		allSharedProjects, err := h.db.Queries.ListProjectsSharedWithUser(r.Context(), int64(userID))
		if err == nil {
			allOrgs, _ := h.db.ListUserSharedProjectOrganizations(r.Context(), int64(userID))
			orgMap := make(map[int64]sqlc.UserSharedProjectOrganization)
			for _, org := range allOrgs {
				orgMap[org.ProjectID] = org
			}

			for _, project := range allSharedProjects {
				org, hasOrg := orgMap[project.ID]
				if !hasOrg || !org.FolderID.Valid {
					sharedProjects = append(sharedProjects, project)
				}
			}
		}
	}

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/json")

	for _, p := range sharedProjects {
		pr := shared.ConvertProjectWithIsShared(p, true) // Shared projects are always shared
		pr.FolderID = nil
		share, err := h.db.Queries.GetUserProjectShare(r.Context(), sqlc.GetUserProjectShareParams{
			ProjectID: p.ID,
			SharedTo:  int64(userID),
		})
		if err == nil {
			sharedByUser, err := h.db.Queries.GetUserByID(r.Context(), share.SharedBy)
			if err == nil {
				pr.SharedByUsername = &sharedByUser.Username
			}
			pr.AllowEditing = share.CanEdit
			pr.AllowDownloads = share.CanDownload
		}
		response = append(response, pr)
	}

	return httputil.OKResult(w, response)
}

func (h *ProjectsHandler) GetProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")
	ctx := r.Context()

	projectByPublic, err := h.db.GetProjectByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "project not found", "failed to query project"); err != nil {
		return err
	}

	hasAccess := false
	isOwner := projectByPublic.UserID == int64(userID)

	if isOwner {
		hasAccess = true
	} else {
		projectShares, err := h.db.ListUsersProjectIsSharedWith(ctx, projectByPublic.ID)
		if err == nil {
			for _, share := range projectShares {
				if share.SharedTo == int64(userID) {
					hasAccess = true
					break
				}
			}
		}

		if !hasAccess {
			tracks, err := h.db.ListTracksByProjectID(ctx, projectByPublic.ID)
			if err == nil {
				for _, track := range tracks {
					trackShares, err := h.db.ListUsersTrackIsSharedWith(ctx, track.ID)
					if err == nil {
						for _, share := range trackShares {
							if share.SharedTo == int64(userID) {
								hasAccess = true
								break
							}
						}
					}
					if hasAccess {
						break
					}
				}
			}
		}
	}

	if !hasAccess {
		return apperr.NewForbidden("access denied")
	}

	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	return httputil.OKResult(w, shared.ConvertProjectWithIsShared(
		service.ProjectRowToProject(projectByPublic),
		projectByPublic.IsShared == 1,
	))
}

func (h *ProjectsHandler) UpdateProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	req, err := httputil.DecodeJSON[handlers.UpdateProjectRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	var qualityOverride *string
	if req.QualityOverride != nil {
		s := string(*req.QualityOverride)
		qualityOverride = &s
	}

	project, err := h.service.UpdateProject(r.Context(), service.UpdateProjectInput{
		UserID:          int64(userID),
		PublicID:        publicID,
		Name:            req.Name,
		Description:     req.Description,
		QualityOverride: qualityOverride,
		AuthorOverride:  req.AuthorOverride,
		Notes:           req.Notes,
		NotesAuthorName: req.NotesAuthorName,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return apperr.NewNotFound("project not found")
	}
	if err != nil {
		if err.Error() == "invalid quality override value" {
			return apperr.NewBadRequest(err.Error())
		}
		return apperr.NewInternal("failed to update project", err)
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	return httputil.OKResult(w, shared.ConvertProject(project))
}

func (h *ProjectsHandler) DeleteProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	err = h.service.DeleteProject(r.Context(), publicID, int64(userID))
	if err := httputil.HandleDBError(err, "project not found", "failed to delete project"); err != nil {
		return err
	}

	return httputil.NoContentResult(w)
}

func (h *ProjectsHandler) DuplicateProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")
	ctx := r.Context()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.NewInternal("failed to start transaction", err)
	}
	defer tx.Rollback()

	queries := sqlc.New(tx)

	originalProject, err := queries.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{
		PublicID: publicID,
		UserID:   int64(userID),
	})
	if err := httputil.HandleDBError(err, "project not found", "failed to fetch project"); err != nil {
		return err
	}

	newPublicID, err := ids.NewPublicID()
	if err != nil {
		return apperr.NewInternal("failed to generate project id", err)
	}

	newName := originalProject.Name + " (Copy)"
	duplicateProject, err := queries.CreateProject(ctx, sqlc.CreateProjectParams{
		UserID:          int64(userID),
		Name:            newName,
		Description:     originalProject.Description,
		QualityOverride: originalProject.QualityOverride,
		PublicID:        newPublicID,
		AuthorOverride:  originalProject.AuthorOverride,
	})
	if err != nil {
		return apperr.NewInternal("failed to create duplicate project", err)
	}

	if originalProject.FolderID.Valid {
		duplicateProject, err = queries.UpdateProjectFolderWithTimestamp(ctx, sqlc.UpdateProjectFolderWithTimestampParams{
			FolderID:      originalProject.FolderID,
			FolderAddedAt: originalProject.FolderAddedAt,
			ID:            duplicateProject.ID,
			UserID:        int64(userID),
		})
		if err != nil {
			return apperr.NewInternal("failed to set project folder", err)
		}
	}

	if originalProject.CoverArtPath.Valid {
		oldCoverPath := originalProject.CoverArtPath.String
		oldCoverDir := filepath.Dir(oldCoverPath)
		newCoverDir := strings.Replace(oldCoverDir, originalProject.PublicID, duplicateProject.PublicID, 1)
		if err := os.MkdirAll(newCoverDir, 0o755); err != nil {
			return apperr.NewInternal("failed to create project directory", err)
		}
		newCoverPath := filepath.Join(newCoverDir, filepath.Base(oldCoverPath))
		if err := copyFileForProject(oldCoverPath, newCoverPath); err == nil {
			_, err = queries.UpdateProjectCover(ctx, sqlc.UpdateProjectCoverParams{
				CoverArtPath: sql.NullString{String: newCoverPath, Valid: true},
				CoverArtMime: originalProject.CoverArtMime,
				ID:           duplicateProject.ID,
			})
			if err != nil {
				slog.Debug("failed to update cover path for duplicate project", "error", err)
			}
		}
	}

	tracks, err := queries.ListPlainTracksByProject(ctx, sqlc.ListPlainTracksByProjectParams{
		UserID:    int64(userID),
		ProjectID: originalProject.ID,
	})
	if err != nil {
		return apperr.NewInternal("failed to list tracks", err)
	}

	for _, track := range tracks {
		trackPublicID, err := ids.NewPublicID()
		if err != nil {
			return apperr.NewInternal("failed to generate track id", err)
		}

		duplicateTrack, err := queries.CreateTrack(ctx, sqlc.CreateTrackParams{
			UserID:    int64(userID),
			ProjectID: duplicateProject.ID,
			Title:     track.Title,
			Artist:    track.Artist,
			Album:     track.Album,
			PublicID:  trackPublicID,
		})
		if err != nil {
			return apperr.NewInternal("failed to create duplicate track", err)
		}

		versions, err := queries.ListTrackVersions(ctx, track.ID)
		if err != nil {
			return apperr.NewInternal("failed to list versions", err)
		}

		var newActiveVersionID int64

		for _, version := range versions {
			newVersion, err := queries.CreateTrackVersion(ctx, sqlc.CreateTrackVersionParams{
				TrackID:         duplicateTrack.ID,
				VersionName:     version.VersionName,
				Notes:           version.Notes,
				DurationSeconds: version.DurationSeconds,
				VersionOrder:    version.VersionOrder,
			})
			if err != nil {
				return apperr.NewInternal("failed to create duplicate version", err)
			}

			if track.ActiveVersionID.Valid && track.ActiveVersionID.Int64 == version.ID {
				newActiveVersionID = newVersion.ID
			}

			files, err := queries.ListTrackFilesByVersion(ctx, version.ID)
			if err != nil {
				return apperr.NewInternal("failed to list track files", err)
			}

			for _, file := range files {
				oldPath := file.FilePath
				oldDir := filepath.Dir(oldPath)
				fileName := filepath.Base(oldPath)
				newDir := strings.Replace(oldDir,
					fmt.Sprintf("tracks/%d/versions/%d", track.ID, version.ID),
					fmt.Sprintf("tracks/%d/versions/%d", duplicateTrack.ID, newVersion.ID), 1)
				newPath := filepath.Join(newDir, fileName)

				if err := os.MkdirAll(newDir, 0o755); err != nil {
					return apperr.NewInternal("failed to create version directory", err)
				}

				if err := copyFileForProject(oldPath, newPath); err != nil {
					return apperr.NewInternal("failed to copy file", err)
				}

				_, err := queries.CreateTrackFile(ctx, sqlc.CreateTrackFileParams{
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
					return apperr.NewInternal("failed to create file record", err)
				}
			}
		}

		if newActiveVersionID != 0 {
			err = queries.SetActiveVersion(ctx, sqlc.SetActiveVersionParams{
				ActiveVersionID: sql.NullInt64{Int64: newActiveVersionID, Valid: true},
				ID:              duplicateTrack.ID,
			})
			if err != nil {
				return apperr.NewInternal("failed to set active version", err)
			}
		}

		_, err = queries.UpdateTrack(ctx, sqlc.UpdateTrackParams{
			Title:     track.Title,
			Artist:    track.Artist,
			Album:     track.Album,
			ProjectID: duplicateProject.ID,
			Key:       track.Key,
			Bpm:       track.Bpm,
			ID:        duplicateTrack.ID,
			UserID:    int64(userID),
		})
		if err != nil {
			return apperr.NewInternal("failed to update track metadata", err)
		}

		err = queries.UpdateTrackOrder(ctx, sqlc.UpdateTrackOrderParams{
			TrackOrder: track.TrackOrder,
			ID:         duplicateTrack.ID,
		})
		if err != nil {
			slog.Debug("failed to update track order", "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return apperr.NewInternal("failed to finalize duplication", err)
	}

	finalProject, err := h.service.GetProject(ctx, duplicateProject.PublicID, int64(userID))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		return httputil.CreatedResult(w, shared.ConvertProject(duplicateProject))
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	return httputil.CreatedResult(w, shared.ConvertProject(finalProject))
}

func (h *ProjectsHandler) ExportProject(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")
	ctx := r.Context()

	project, err := h.service.GetProject(ctx, publicID, int64(userID))
	if err := httputil.HandleDBError(err, "project not found", "failed to fetch project"); err != nil {
		return err
	}

	queries := h.db.Queries

	if project.UserID != int64(userID) {
		projectShare, err := queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  int64(userID),
		})
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewForbidden("access denied")
		}
		if err != nil {
			return apperr.NewInternal("failed to check permissions", err)
		}
		if !projectShare.CanDownload {
			return apperr.NewForbidden("downloads not allowed for this project")
		}
	}

	tracks, err := queries.ListPlainTracksByProject(ctx, sqlc.ListPlainTracksByProjectParams{
		UserID:    int64(userID),
		ProjectID: project.ID,
	})
	if err != nil {
		return apperr.NewInternal("failed to list tracks", err)
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zip"`, sanitizeFilename(project.Name)))

	// Create zip writer
	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	if project.CoverArtPath.Valid {
		// Cover art path is stored as absolute path in database
		coverPath := project.CoverArtPath.String
		if _, err := os.Stat(coverPath); err == nil {
			ext := filepath.Ext(coverPath)
			if err := addFileToZip(zipWriter, coverPath, "cover"+ext); err != nil {
				slog.Debug("failed to add cover to zip", "error", err)
			}
		}
	}

	usedNames := make(map[string]int)

	for _, track := range tracks {
		if !track.ActiveVersionID.Valid {
			continue
		}

		sourceFile, err := queries.GetTrackFile(ctx, sqlc.GetTrackFileParams{
			VersionID: track.ActiveVersionID.Int64,
			Quality:   "source",
		})
		if err != nil {
			continue
		}

		filePath := sourceFile.FilePath
		if _, err := os.Stat(filePath); err != nil {
			continue
		}

		baseName := sanitizeFilename(track.Title)
		ext := filepath.Ext(sourceFile.FilePath)
		if ext == "" {
			ext = "." + sourceFile.Format
		}
		zipName := baseName + ext

		if count, exists := usedNames[zipName]; exists {
			usedNames[zipName] = count + 1
			zipName = fmt.Sprintf("%s (%d)%s", baseName, count+1, ext)
		} else {
			usedNames[zipName] = 1
		}

		if err := addFileToZip(zipWriter, filePath, zipName); err != nil {
			slog.Debug("failed to add track to zip", "track_title", track.Title, "error", err)
			continue
		}
	}
	return nil
}
