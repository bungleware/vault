package sharing

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

type ShareWithUsersRequest struct {
	UserIDs     []int64 `json:"user_ids"`
	CanEdit     bool    `json:"can_edit"`
	CanDownload bool    `json:"can_download"`
}

type updateSharePermissionsReq struct {
	CanEdit     bool `json:"can_edit"`
	CanDownload bool `json:"can_download"`
}

func (h *SharingHandler) ShareProjectWithUsers(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	publicID := r.PathValue("id")
	if publicID == "" {
		return apperr.NewBadRequest("invalid project id")
	}

	req, err := httputil.DecodeJSON[ShareWithUsersRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	project, successCount, err := h.svc.ShareProjectWithUsers(r.Context(), int64(userID), publicID, service.ShareWithUsersInput{
		UserIDs:     req.UserIDs,
		CanEdit:     req.CanEdit,
		CanDownload: req.CanDownload,
	})
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("project not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("unauthorized")
		}
		if errors.Is(err, service.ErrBadRequest) {
			return apperr.NewBadRequest("no users were shared with")
		}
		return apperr.NewInternal("failed to share with users", err)
	}
	return httputil.CreatedResult(w, map[string]interface{}{
		"message": fmt.Sprintf("project shared with %d user(s)", successCount),
		"project": project,
	})
}

func (h *SharingHandler) ShareTrackWithUsers(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	publicID := r.PathValue("id")
	if publicID == "" {
		return apperr.NewBadRequest("invalid track id")
	}

	req, err := httputil.DecodeJSON[ShareWithUsersRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	track, successCount, err := h.svc.ShareTrackWithUsers(r.Context(), int64(userID), publicID, service.ShareWithUsersInput{
		UserIDs:     req.UserIDs,
		CanEdit:     req.CanEdit,
		CanDownload: req.CanDownload,
	})
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("track not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			slog.WarnContext(r.Context(), "Share track failed: user does not have permission",
				"user_id", userID, "track_id", publicID)
			return apperr.NewForbidden("unauthorized")
		}
		if errors.Is(err, service.ErrBadRequest) {
			return apperr.NewBadRequest("no users were shared with")
		}
		return apperr.NewInternal("failed to share with users", err)
	}
	return httputil.CreatedResult(w, map[string]interface{}{
		"message": fmt.Sprintf("track shared with %d user(s)", successCount),
		"track":   track,
	})
}

func (h *SharingHandler) ListProjectsSharedWithMe(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	projects, err := h.svc.ListProjectsSharedWithMe(r.Context(), int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to list shared projects", err)
	}

	response := make([]shared.ProjectResponse, len(projects))
	for i, info := range projects {
		projectResponse := shared.ConvertProject(info.Project)
		projectResponse.SharedByUsername = &info.OwnerUsername
		projectResponse.AllowEditing = info.AllowEditing
		projectResponse.AllowDownloads = info.AllowDownloads
		response[i] = projectResponse
	}
	return httputil.OKResult(w, response)
}

func (h *SharingHandler) ListTracksSharedWithMe(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tracks, err := h.svc.ListTracksSharedWithMe(r.Context(), int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to list shared tracks", err)
	}

	result := make([]shared.SharedTrackResponse, len(tracks))
	for i, t := range tracks {
		result[i] = shared.SharedTrackResponse{
			ID:               t.ID,
			PublicID:         t.PublicID,
			Title:            t.Title,
			Artist:           t.Artist,
			CoverURL:         t.CoverURL,
			ProjectName:      t.ProjectName,
			Waveform:         t.Waveform,
			DurationSeconds:  t.DurationSeconds,
			SharedByUsername: t.SharedByUsername,
			CanDownload:      t.CanDownload,
			FolderID:         t.FolderID,
			CustomOrder:      t.CustomOrder,
		}
	}
	return httputil.OKResult(w, result)
}

func (h *SharingHandler) RevokeProjectShare(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	shareID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}
	if err := h.svc.RevokeProjectShare(r.Context(), int64(userID), shareID); err != nil {
		return apperr.NewInternal("failed to revoke share", err)
	}
	return httputil.NoContentResult(w)
}

func (h *SharingHandler) RevokeTrackShare(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	shareID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}
	if err := h.svc.RevokeTrackShare(r.Context(), int64(userID), shareID); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("share not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("unauthorized")
		}
		return apperr.NewInternal("failed to revoke share", err)
	}
	return httputil.NoContentResult(w)
}

func (h *SharingHandler) ListProjectShareUsers(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	publicID := r.PathValue("id")
	if publicID == "" {
		return apperr.NewBadRequest("invalid project id")
	}

	shares, err := h.svc.ListProjectShareUsers(r.Context(), int64(userID), publicID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("project not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("unauthorized")
		}
		return apperr.NewInternal("failed to list shares", err)
	}
	return httputil.OKResult(w, shares)
}

func (h *SharingHandler) ListTrackShareUsers(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	publicID := r.PathValue("id")
	if publicID == "" {
		return apperr.NewBadRequest("invalid track id")
	}

	shares, err := h.svc.ListTrackShareUsers(r.Context(), int64(userID), publicID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("track not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			slog.WarnContext(r.Context(), "List track shares failed: no permission",
				"user_id", userID, "track_id", publicID)
			return apperr.NewForbidden("unauthorized")
		}
		return apperr.NewInternal("failed to list shares", err)
	}
	return httputil.OKResult(w, shares)
}

func (h *SharingHandler) UpdateProjectSharePermissions(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	shareID, err := httputil.PathInt64(r, "shareId")
	if err != nil {
		return apperr.NewBadRequest("invalid share id")
	}

	req, err := httputil.DecodeJSON[updateSharePermissionsReq](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	share, err := h.svc.UpdateProjectSharePermissions(r.Context(), int64(userID), shareID, req.CanEdit, req.CanDownload)
	if err != nil {
		return apperr.NewInternal("failed to update share", err)
	}
	return httputil.OKResult(w, share)
}

func (h *SharingHandler) UpdateTrackSharePermissions(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	shareID, err := httputil.PathInt64(r, "shareId")
	if err != nil {
		return apperr.NewBadRequest("invalid share id")
	}

	req, err := httputil.DecodeJSON[updateSharePermissionsReq](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	share, err := h.svc.UpdateTrackSharePermissions(r.Context(), int64(userID), shareID, req.CanEdit, req.CanDownload)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("share not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("unauthorized")
		}
		return apperr.NewInternal("failed to update share", err)
	}
	return httputil.OKResult(w, share)
}
