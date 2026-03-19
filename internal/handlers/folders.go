package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
	sqlc "bungleware/vault/internal/db/sqlc"
)

type FoldersHandler struct {
	svc service.FoldersService
}

func NewFoldersHandler(svc service.FoldersService) *FoldersHandler {
	return &FoldersHandler{svc: svc}
}

func (h *FoldersHandler) CreateFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	req, err := httputil.DecodeJSON[CreateFolderRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Name == "" {
		return apperr.NewBadRequest("folder name is required")
	}

	folder, err := h.svc.CreateFolder(r.Context(), int64(userID), req.Name, req.ParentID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("parent folder not found")
		}
		return apperr.NewInternal("failed to create folder", err)
	}

	return httputil.CreatedResult(w, convertFolder(folder))
}

func (h *FoldersHandler) ListFolders(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	parentIDStr := r.URL.Query().Get("parent_id")

	var folders []sqlc.Folder

	if parentIDStr == "" {
		folders, err = h.svc.ListFoldersByUser(r.Context(), int64(userID))
		if err != nil {
			return apperr.NewInternal("failed to query folders", err)
		}
	} else {
		parentID, parseErr := strconv.ParseInt(parentIDStr, 10, 64)
		if parseErr != nil {
			return apperr.NewBadRequest("invalid parent_id")
		}
		folders, err = h.svc.ListFoldersByParent(r.Context(), int64(userID), parentID)
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

	folders, err := h.svc.ListAllFoldersByUser(r.Context(), int64(userID))
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

	folder, err := h.svc.GetFolder(r.Context(), id, int64(userID))
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

	req, err := httputil.DecodeJSON[UpdateFolderRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	folder, err := h.svc.UpdateFolder(r.Context(), id, int64(userID), req.Name, req.ParentID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("folder not found")
		}
		if errors.Is(err, service.ErrBadRequest) {
			return apperr.NewBadRequest("cannot move folder into itself")
		}
		return apperr.NewInternal("failed to update folder", err)
	}

	return httputil.OKResult(w, convertFolder(folder))
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

	if err := h.svc.DeleteFolderRecursive(r.Context(), id, int64(userID)); err != nil {
		return apperr.NewInternal("failed to delete folder", err)
	}

	return httputil.NoContentResult(w)
}

func (h *FoldersHandler) EmptyFolder(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	id, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	if err := h.svc.EmptyFolder(r.Context(), id, int64(userID)); err != nil {
		if err := httputil.HandleDBError(err, "folder not found", "failed to empty folder"); err != nil {
			return err
		}
		return apperr.NewInternal("failed to empty folder", err)
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

	contents, err := h.svc.GetFolderContents(r.Context(), id, int64(userID))
	if err := httputil.HandleDBError(err, "folder not found", "failed to get folder contents"); err != nil {
		return err
	}

	folderResponses := make([]FolderResponse, len(contents.Subfolders))
	for i, f := range contents.Subfolders {
		folderResponses[i] = convertFolder(f)
	}

	type projectWithOrder struct {
		project shared.ProjectResponse
		order   int64
	}
	allProjects := make([]projectWithOrder, 0, len(contents.OwnedProjects)+len(contents.SharedProjects))

	for _, p := range contents.OwnedProjects {
		pr := shared.ConvertProjectRowWithShared(p, false)
		pr.CustomOrder = &p.CustomOrder
		allProjects = append(allProjects, projectWithOrder{project: pr, order: p.CustomOrder})
	}

	for _, sp := range contents.SharedProjects {
		pr := shared.ConvertProject(sp.Project)
		if sp.Org.FolderID.Valid {
			pr.FolderID = &sp.Org.FolderID.Int64
		} else {
			pr.FolderID = nil
		}
		pr.IsShared = true
		pr.CustomOrder = &sp.Org.CustomOrder
		if sp.SharedByUsername != "" {
			pr.SharedByUsername = &sp.SharedByUsername
		}
		pr.AllowEditing = sp.AllowEditing
		pr.AllowDownloads = sp.AllowDownloads
		allProjects = append(allProjects, projectWithOrder{project: pr, order: sp.Org.CustomOrder})
	}

	sort.Slice(allProjects, func(i, j int) bool {
		return allProjects[i].order < allProjects[j].order
	})

	projectResponses := make([]shared.ProjectResponse, len(allProjects))
	for i, p := range allProjects {
		projectResponses[i] = p.project
	}

	sharedTracksInFolder := make([]shared.SharedTrackResponse, 0, len(contents.SharedTracks))
	for _, st := range contents.SharedTracks {
		coverURL := ""
		if st.Project.CoverArtPath.Valid && st.Project.CoverArtPath.String != "" {
			coverURL = fmt.Sprintf("/api/projects/%s/cover", st.Project.PublicID)
		}

		folderID := &st.Org.FolderID.Int64

		var artist string
		if st.Track.Artist.Valid {
			artist = st.Track.Artist.String
		}

		sharedTracksInFolder = append(sharedTracksInFolder, shared.SharedTrackResponse{
			ID:               st.Track.ID,
			PublicID:         st.Track.PublicID,
			Title:            st.Track.Title,
			Artist:           artist,
			CoverURL:         coverURL,
			ProjectName:      st.Project.Name,
			Waveform:         st.Waveform,
			DurationSeconds:  st.DurationSeconds,
			SharedByUsername: st.SharedByUsername,
			CanDownload:      st.CanDownload,
			FolderID:         folderID,
			CustomOrder:      &st.Org.CustomOrder,
		})
	}

	return httputil.OKResult(w, FolderContentsResponse{
		Folder:       convertFolder(contents.Folder),
		Folders:      folderResponses,
		Projects:     projectResponses,
		SharedTracks: sharedTracksInFolder,
	})
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
