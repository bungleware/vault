package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
)

type FoldersHandler struct {
	db *db.DB
}

func NewFoldersHandler(database *db.DB) *FoldersHandler {
	return &FoldersHandler{db: database}
}

func (h *FoldersHandler) CreateFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	var req CreateFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Name == "" {
		return apperr.NewBadRequest("folder name is required")
	}

	var parentID sql.NullInt64
	if req.ParentID != nil {
		count, err := h.db.CheckFolderExists(r.Context(), sqlc.CheckFolderExistsParams{
			ID:     *req.ParentID,
			UserID: int64(userID),
		})
		if err != nil {
			return apperr.NewInternal("failed to verify parent folder", err)
		}
		if count == 0 {
			return apperr.NewNotFound("parent folder not found")
		}
		parentID = sql.NullInt64{Int64: *req.ParentID, Valid: true}
	}

	var folderOrder int64 = 0
	if req.ParentID != nil {
		count, err := h.db.CountSubfoldersInFolder(r.Context(), parentID)
		if err == nil {
			folderOrder = count
		}
	} else {
		folders, err := h.db.ListFoldersByUser(r.Context(), int64(userID))
		if err == nil {
			folderOrder = int64(len(folders))
		}
	}

	folder, err := h.db.CreateFolder(r.Context(), sqlc.CreateFolderParams{
		UserID:      int64(userID),
		ParentID:    parentID,
		Name:        req.Name,
		FolderOrder: folderOrder,
	})
	if err != nil {
		return apperr.NewInternal("failed to create folder", err)
	}

	return httputil.CreatedResult(w, convertFolder(folder))
}

// ListFolders returns folders for the current user. Query param parent_id (optional): if omitted, returns root folders.
func (h *FoldersHandler) ListFolders(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	parentIDStr := r.URL.Query().Get("parent_id")

	var folders []sqlc.Folder

	if parentIDStr == "" {
		var err error
		folders, err = h.db.ListFoldersByUser(r.Context(), int64(userID))
		if err != nil {
			return apperr.NewInternal("failed to query folders", err)
		}
	} else {
		parentID, parseErr := strconv.ParseInt(parentIDStr, 10, 64)
		if parseErr != nil {
			return apperr.NewBadRequest("invalid parent_id")
		}
		var err error
		folders, err = h.db.ListFoldersByParent(r.Context(), sqlc.ListFoldersByParentParams{
			UserID:   int64(userID),
			ParentID: sql.NullInt64{Int64: parentID, Valid: true},
		})
		if err != nil {
			return apperr.NewInternal("failed to query folders", err)
		}
	}

	response := make([]FolderResponse, len(folders))
	for i, folder := range folders {
		response[i] = convertFolder(folder)
	}
	return httputil.OKResult(w, response)
}

func (h *FoldersHandler) ListAllFolders(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	folders, err := h.db.ListAllFoldersByUser(r.Context(), int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query folders", err)
	}

	response := make([]FolderResponse, len(folders))
	for i, folder := range folders {
		response[i] = convertFolder(folder)
	}
	return httputil.OKResult(w, response)
}

func (h *FoldersHandler) GetFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	id, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	folder, err := h.db.GetFolder(r.Context(), sqlc.GetFolderParams{
		ID:     id,
		UserID: int64(userID),
	})
	if err := httputil.HandleDBError(err, "folder not found", "failed to query folder"); err != nil {
		return err
	}

	return httputil.OKResult(w, convertFolder(folder))
}

func (h *FoldersHandler) UpdateFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	id, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	currentFolder, err := h.db.GetFolder(r.Context(), sqlc.GetFolderParams{
		ID:     id,
		UserID: int64(userID),
	})
	if err := httputil.HandleDBError(err, "folder not found", "failed to query folder"); err != nil {
		return err
	}

	var req UpdateFolderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	name := currentFolder.Name
	if req.Name != nil {
		name = *req.Name
	}

	parentID := currentFolder.ParentID
	if req.ParentID != nil {
		if *req.ParentID == 0 {
			parentID = sql.NullInt64{Valid: false}
		} else {
			count, verifyErr := h.db.CheckFolderExists(r.Context(), sqlc.CheckFolderExistsParams{
				ID:     *req.ParentID,
				UserID: int64(userID),
			})
			if verifyErr != nil {
				return apperr.NewInternal("failed to verify parent folder", verifyErr)
			}
			if count == 0 {
				return apperr.NewNotFound("parent folder not found")
			}
			if *req.ParentID == id {
				return apperr.NewBadRequest("cannot move folder into itself")
			}
			parentID = sql.NullInt64{Int64: *req.ParentID, Valid: true}
		}
	}

	folder, err := h.db.UpdateFolder(r.Context(), sqlc.UpdateFolderParams{
		Name:        name,
		ParentID:    parentID,
		FolderOrder: currentFolder.FolderOrder,
		ID:          id,
		UserID:      int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to update folder", err)
	}

	return httputil.OKResult(w, convertFolder(folder))
}

func (h *FoldersHandler) deleteFolderRecursive(ctx context.Context, folderID, userID int64) error {
	projects, err := h.db.ListProjectsInFolder(ctx, sqlc.ListProjectsInFolderParams{
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
		UserID:   userID,
	})
	if err != nil {
		return err
	}

	for _, project := range projects {
		_, err := h.db.UpdateProjectFolder(ctx, sqlc.UpdateProjectFolderParams{
			FolderID: sql.NullInt64{Valid: false},
			Column2:  nil,
			ID:       project.ID,
			UserID:   userID,
		})
		if err != nil {
			return err
		}
	}

	sharedOrgs, err := h.db.ListSharedProjectOrganizationsInFolder(ctx, sqlc.ListSharedProjectOrganizationsInFolderParams{
		UserID:   userID,
		FolderID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err == nil {
		for _, org := range sharedOrgs {
			_, err := h.db.UpsertSharedProjectOrganization(ctx, sqlc.UpsertSharedProjectOrganizationParams{
				UserID:      userID,
				ProjectID:   org.ProjectID,
				FolderID:    sql.NullInt64{Valid: false},
				CustomOrder: org.CustomOrder,
			})
			if err != nil {
				return err
			}
		}
	}

	subfolders, err := h.db.ListFoldersByParent(ctx, sqlc.ListFoldersByParentParams{
		UserID:   userID,
		ParentID: sql.NullInt64{Int64: folderID, Valid: true},
	})
	if err != nil {
		return err
	}

	for _, subfolder := range subfolders {
		if err := h.deleteFolderRecursive(ctx, subfolder.ID, userID); err != nil {
			return err
		}
	}

	return h.db.DeleteFolder(ctx, sqlc.DeleteFolderParams{
		ID:     folderID,
		UserID: userID,
	})
}

func (h *FoldersHandler) DeleteFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	id, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	err = h.deleteFolderRecursive(r.Context(), id, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to delete folder", err)
	}

	return httputil.NoContentResult(w)
}

// EmptyFolder moves all projects and subfolders to the folder's parent (or root if at root).
func (h *FoldersHandler) EmptyFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	id, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	// Verify folder exists and belongs to user
	folder, err := h.db.GetFolder(r.Context(), sqlc.GetFolderParams{
		ID:     id,
		UserID: int64(userID),
	})
	if err := httputil.HandleDBError(err, "folder not found", "failed to query folder"); err != nil {
		return err
	}

	var targetParentID sql.NullInt64
	if folder.ParentID.Valid {
		targetParentID = folder.ParentID
	} else {
		targetParentID = sql.NullInt64{Valid: false}
	}

	projects, err := h.db.ListProjectsInFolder(r.Context(), sqlc.ListProjectsInFolderParams{
		FolderID: sql.NullInt64{Int64: id, Valid: true},
		UserID:   int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to query projects in folder", err)
	}

	for _, project := range projects {
		_, err := h.db.UpdateProjectFolder(r.Context(), sqlc.UpdateProjectFolderParams{
			FolderID: targetParentID,
			Column2:  nil,
			ID:       project.ID,
			UserID:   int64(userID),
		})
		if err != nil {
			return apperr.NewInternal("failed to move projects out of folder", err)
		}
	}

	sharedOrgs, err := h.db.ListSharedProjectOrganizationsInFolder(r.Context(), sqlc.ListSharedProjectOrganizationsInFolderParams{
		UserID:   int64(userID),
		FolderID: sql.NullInt64{Int64: id, Valid: true},
	})
	if err == nil {
		for _, org := range sharedOrgs {
			_, err := h.db.UpsertSharedProjectOrganization(r.Context(), sqlc.UpsertSharedProjectOrganizationParams{
				UserID:      int64(userID),
				ProjectID:   org.ProjectID,
				FolderID:    targetParentID,
				CustomOrder: org.CustomOrder,
			})
			if err != nil {
				return apperr.NewInternal("failed to move shared projects out of folder", err)
			}
		}
	}

	subfolders, err := h.db.ListFoldersByParent(r.Context(), sqlc.ListFoldersByParentParams{
		UserID:   int64(userID),
		ParentID: sql.NullInt64{Int64: id, Valid: true},
	})
	if err != nil {
		return apperr.NewInternal("failed to query subfolders", err)
	}

	for _, subfolder := range subfolders {
		_, err := h.db.UpdateFolderParent(r.Context(), sqlc.UpdateFolderParentParams{
			ParentID: targetParentID,
			ID:       subfolder.ID,
			UserID:   int64(userID),
		})
		if err != nil {
			return apperr.NewInternal("failed to move subfolders out of folder", err)
		}
	}

	err = h.db.DeleteFolder(r.Context(), sqlc.DeleteFolderParams{
		ID:     id,
		UserID: int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to delete folder", err)
	}

	return httputil.NoContentResult(w)
}

func (h *FoldersHandler) GetFolderContents(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	id, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	folder, err := h.db.GetFolder(r.Context(), sqlc.GetFolderParams{
		ID:     id,
		UserID: int64(userID),
	})
	if err := httputil.HandleDBError(err, "folder not found", "failed to query folder"); err != nil {
		return err
	}

	subfolders, err := h.db.ListFoldersByParent(r.Context(), sqlc.ListFoldersByParentParams{
		UserID:   int64(userID),
		ParentID: sql.NullInt64{Int64: id, Valid: true},
	})
	if err != nil {
		return apperr.NewInternal("failed to query subfolders", err)
	}

	projects, err := h.db.ListProjectsInFolder(r.Context(), sqlc.ListProjectsInFolderParams{
		FolderID: sql.NullInt64{Int64: id, Valid: true},
		UserID:   int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to query projects", err)
	}

	sharedOrgs, err := h.db.ListSharedProjectOrganizationsInFolder(r.Context(), sqlc.ListSharedProjectOrganizationsInFolderParams{
		UserID:   int64(userID),
		FolderID: sql.NullInt64{Int64: id, Valid: true},
	})
	if err != nil && err != sql.ErrNoRows {
		return apperr.NewInternal("failed to query shared projects", err)
	}

	sharedProjects := make([]sqlc.Project, 0, len(sharedOrgs))
	for _, org := range sharedOrgs {
		project, err := h.db.Queries.GetProjectByID(r.Context(), org.ProjectID)
		if err != nil {
			continue
		}
		sharedProjects = append(sharedProjects, project)
	}

	folderResponses := make([]FolderResponse, len(subfolders))
	for i, f := range subfolders {
		folderResponses[i] = convertFolder(f)
	}

	sharedOrgMap := make(map[int64]sqlc.UserSharedProjectOrganization)
	for _, org := range sharedOrgs {
		sharedOrgMap[org.ProjectID] = org
	}

	type projectWithOrder struct {
		project  shared.ProjectResponse
		order    int64
		isShared bool
	}

	allProjects := make([]projectWithOrder, 0, len(projects)+len(sharedProjects))

	for _, p := range projects {
		pr := shared.ConvertProjectRowWithShared(p, false)
		pr.CustomOrder = &p.CustomOrder
		allProjects = append(allProjects, projectWithOrder{
			project:  pr,
			order:    p.CustomOrder,
			isShared: false,
		})
	}

	for _, p := range sharedProjects {
		pr := shared.ConvertProject(p)
		org := sharedOrgMap[p.ID]

		// Shared project folder_id comes from organization table, not project (owner's folder)
		if org.FolderID.Valid {
			pr.FolderID = &org.FolderID.Int64
		} else {
			pr.FolderID = nil
		}
		pr.IsShared = true
		pr.CustomOrder = &org.CustomOrder

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

		allProjects = append(allProjects, projectWithOrder{
			project:  pr,
			order:    org.CustomOrder,
			isShared: true,
		})
	}

	sort.Slice(allProjects, func(i, j int) bool {
		return allProjects[i].order < allProjects[j].order
	})

	projectResponses := make([]shared.ProjectResponse, len(allProjects))
	for i, p := range allProjects {
		projectResponses[i] = p.project
	}

	sharedTrackOrgs, err := h.db.Queries.ListSharedTrackOrganizationsInFolder(r.Context(), sqlc.ListSharedTrackOrganizationsInFolderParams{
		UserID:   int64(userID),
		FolderID: sql.NullInt64{Int64: id, Valid: true},
	})
	if err != nil && err != sql.ErrNoRows {
		return apperr.NewInternal("failed to query shared track organizations", err)
	}

	sharedTracksInFolder := make([]shared.SharedTrackResponse, 0, len(sharedTrackOrgs))
	for _, trackOrg := range sharedTrackOrgs {
		track, err := h.db.Queries.GetTrackByID(r.Context(), trackOrg.TrackID)
		if err != nil {
			continue
		}

		project, err := h.db.Queries.GetProjectByID(r.Context(), track.ProjectID)
		if err != nil {
			continue
		}

		shares, err := h.db.ListUsersTrackIsSharedWith(r.Context(), track.ID)
		if err != nil || len(shares) == 0 {
			continue
		}

		var shareRecord sqlc.UserTrackShare
		for _, share := range shares {
			if share.SharedTo == int64(userID) {
				shareRecord = share
				break
			}
		}

		sharedByUser, err := h.db.GetUserByID(r.Context(), shareRecord.SharedBy)
		if err != nil {
			continue
		}

		var waveform string
		var duration float64
		if track.ActiveVersionID.Valid {
			version, err := h.db.GetTrackVersion(r.Context(), track.ActiveVersionID.Int64)
			if err == nil && version.DurationSeconds.Valid {
				duration = version.DurationSeconds.Float64
				files, err := h.db.ListTrackFilesByVersion(r.Context(), track.ActiveVersionID.Int64)
				if err == nil && len(files) > 0 {
					for _, file := range files {
						if file.Waveform.Valid && file.Waveform.String != "" {
							waveform = file.Waveform.String
							break
						}
					}
				}
			}
		}

		coverURL := ""
		if project.CoverArtPath.Valid && project.CoverArtPath.String != "" {
			coverURL = fmt.Sprintf("/api/projects/%s/cover", project.PublicID)
		}

		folderID := &trackOrg.FolderID.Int64

		var artist string
		if track.Artist.Valid {
			artist = track.Artist.String
		}

		resp := shared.SharedTrackResponse{
			ID:               track.ID,
			PublicID:         track.PublicID,
			Title:            track.Title,
			Artist:           artist,
			CoverURL:         coverURL,
			ProjectName:      project.Name,
			Waveform:         waveform,
			DurationSeconds:  duration,
			SharedByUsername: sharedByUser.Username,
			CanDownload:      shareRecord.CanDownload,
			FolderID:         folderID,
			CustomOrder:      &trackOrg.CustomOrder,
		}
		sharedTracksInFolder = append(sharedTracksInFolder, resp)
	}

	response := FolderContentsResponse{
		Folder:       convertFolder(folder),
		Folders:      folderResponses,
		Projects:     projectResponses,
		SharedTracks: sharedTracksInFolder,
	}

	return httputil.OKResult(w, response)
}

func convertFolder(folder sqlc.Folder) FolderResponse {
	var parentID *int64
	if folder.ParentID.Valid {
		parentID = &folder.ParentID.Int64
	}

	return FolderResponse{
		ID:          folder.ID,
		Name:        folder.Name,
		ParentID:    parentID,
		FolderOrder: folder.FolderOrder,
		CreatedAt:   httputil.FormatNullTimeString(folder.CreatedAt),
		UpdatedAt:   httputil.FormatNullTimeString(folder.UpdatedAt),
	}
}
