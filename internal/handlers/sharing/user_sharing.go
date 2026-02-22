package sharing

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
)

type ShareWithUsersRequest struct {
	UserIDs     []int64 `json:"user_ids"`
	CanEdit     bool    `json:"can_edit"`
	CanDownload bool    `json:"can_download"`
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

	var req ShareWithUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}
	ctx := r.Context()

	project, err := h.db.Queries.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{
		PublicID: publicID,
		UserID:   int64(userID),
	})
	if err := httputil.HandleDBError(err, "project not found", "failed to verify project"); err != nil {
		return err
	}
	if project.UserID != int64(userID) {
		return apperr.NewForbidden("unauthorized")
	}

	var successCount int
	var lastErr error
	for _, userToShareWithID := range req.UserIDs {
		_, err := h.db.Queries.CreateUserProjectShare(ctx, sqlc.CreateUserProjectShareParams{
			ProjectID:   project.ID,
			SharedBy:    int64(userID),
			SharedTo:    userToShareWithID,
			CanEdit:     req.CanEdit,
			CanDownload: req.CanDownload,
		})
		if err != nil {
			lastErr = err
			continue
		}
		successCount++
	}
	if successCount == 0 {
		if lastErr != nil {
			return apperr.NewInternal("failed to share with users", lastErr)
		}
		return apperr.NewBadRequest("no users were shared with")
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

	var req ShareWithUsersRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}
	ctx := r.Context()

	track, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to query track"); err != nil {
		return err
	}

	canShare, err := h.canManageTrackShares(ctx, track, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check permissions", err)
	}
	if !canShare {
		slog.WarnContext(r.Context(), "Share track failed: user does not have permission to manage track shares",
			"user_id", userID, "track_id", publicID, "track_owner_id", track.UserID, "project_id", track.ProjectID)
		return apperr.NewForbidden("unauthorized")
	}

	var successCount int
	var lastErr error
	for _, userToShareWithID := range req.UserIDs {
		_, err := h.db.Queries.CreateUserTrackShare(ctx, sqlc.CreateUserTrackShareParams{
			TrackID:     track.ID,
			SharedBy:    int64(userID),
			SharedTo:    userToShareWithID,
			CanEdit:     req.CanEdit,
			CanDownload: req.CanDownload,
		})
		if err != nil {
			lastErr = err
			continue
		}
		successCount++
	}
	if successCount == 0 {
		if lastErr != nil {
			return apperr.NewInternal("failed to share with users", lastErr)
		}
		return apperr.NewBadRequest("no users were shared with")
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
	ctx := r.Context()

	projects, err := h.db.Queries.ListProjectsSharedWithUser(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to list shared projects", err)
	}

	response := make([]shared.ProjectResponse, len(projects))
	for i, project := range projects {
		projectResponse := shared.ConvertProject(project)
		owner, err := h.db.Queries.GetUserByID(ctx, project.UserID)
		if err == nil {
			projectResponse.SharedByUsername = &owner.Username
		}
		share, err := h.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  int64(userID),
		})
		if err == nil {
			projectResponse.AllowEditing = share.CanEdit
			projectResponse.AllowDownloads = share.CanDownload
		}
		response[i] = projectResponse
	}
	return httputil.OKResult(w, response)
}

func (h *SharingHandler) ListTracksSharedWithMe(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	ctx := r.Context()

	allTracks, err := h.db.Queries.ListTracksSharedWithUser(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to list shared tracks", err)
	}
	sharedProjects, err := h.db.Queries.ListProjectsSharedWithUser(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to list shared projects", err)
	}

	sharedProjectIDs := make(map[int64]bool)
	for _, project := range sharedProjects {
		sharedProjectIDs[project.ID] = true
	}

	enrichedTracks := make([]shared.SharedTrackResponse, 0)
	for _, track := range allTracks {
		if sharedProjectIDs[track.ProjectID] {
			continue
		}
		project, err := h.db.Queries.GetProjectByID(ctx, track.ProjectID)
		if err != nil {
			continue
		}
		shares, err := h.db.ListUsersTrackIsSharedWith(ctx, track.ID)
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

		sharedByUser, err := h.db.GetUserByID(ctx, shareRecord.SharedBy)
		if err != nil {
			continue
		}

		var waveform string
		var duration float64
		if track.ActiveVersionID.Valid {
			version, err := h.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
			if err == nil && version.DurationSeconds.Valid {
				duration = version.DurationSeconds.Float64
				files, err := h.db.ListTrackFilesByVersion(ctx, track.ActiveVersionID.Int64)
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

		var folderID *int64
		var customOrder *int64
		org, err := h.db.Queries.GetUserSharedTrackOrganization(ctx, sqlc.GetUserSharedTrackOrganizationParams{
			UserID: int64(userID), TrackID: track.ID,
		})
		if err == nil {
			if org.FolderID.Valid {
				folderID = &org.FolderID.Int64
			}
			customOrder = &org.CustomOrder
		}

		var artist string
		if track.Artist.Valid {
			artist = track.Artist.String
		}

		enrichedTracks = append(enrichedTracks, shared.SharedTrackResponse{
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
			CustomOrder:      customOrder,
		})
	}

	return httputil.OKResult(w, enrichedTracks)
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
	err = h.db.Queries.DeleteUserProjectShare(r.Context(), sqlc.DeleteUserProjectShareParams{
		ID: shareID, SharedBy: int64(userID),
	})
	if err != nil {
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

	ctx := r.Context()
	share, err := h.db.Queries.GetUserTrackShareByID(ctx, shareID)
	if err := httputil.HandleDBError(err, "share not found", "failed to query share"); err != nil {
		return err
	}
	track, err := h.db.Queries.GetTrackByID(ctx, share.TrackID)
	if err != nil {
		return apperr.NewInternal("failed to query track", err)
	}
	canManage, err := h.canManageTrackShares(ctx, track, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check permissions", err)
	}
	if !canManage {
		return apperr.NewForbidden("unauthorized")
	}
	if err := h.db.Queries.DeleteUserTrackShareByShareID(ctx, shareID); err != nil {
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
	ctx := r.Context()

	project, err := h.db.Queries.GetProjectByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "project not found", "failed to query project"); err != nil {
		return err
	}
	if project.UserID != int64(userID) {
		return apperr.NewForbidden("unauthorized")
	}
	shares, err := h.db.Queries.ListUsersProjectIsSharedWith(ctx, project.ID)
	if err != nil {
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
	ctx := r.Context()

	track, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to query track"); err != nil {
		return err
	}
	canView, err := h.canManageTrackShares(ctx, track, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check permissions", err)
	}
	if !canView {
		slog.WarnContext(r.Context(), "List track shares failed: user does not have permission to manage track shares",
			"user_id", userID, "track_id", publicID, "track_owner_id", track.UserID, "project_id", track.ProjectID)
		return apperr.NewForbidden("unauthorized")
	}
	shares, err := h.db.Queries.ListUsersTrackIsSharedWith(ctx, track.ID)
	if err != nil {
		return apperr.NewInternal("failed to list shares", err)
	}
	return httputil.OKResult(w, shares)
}

func (h *SharingHandler) UpdateProjectSharePermissions(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	shareIDStr := r.PathValue("shareId")
	if shareIDStr == "" {
		return apperr.NewBadRequest("invalid share id")
	}
	shareID, err := strconv.ParseInt(shareIDStr, 10, 64)
	if err != nil {
		return apperr.NewBadRequest("invalid share id")
	}
	var req struct {
		CanEdit     bool `json:"can_edit"`
		CanDownload bool `json:"can_download"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	share, err := h.db.Queries.UpdateUserProjectShare(r.Context(), sqlc.UpdateUserProjectShareParams{
		CanEdit: req.CanEdit, CanDownload: req.CanDownload, ID: shareID, SharedBy: int64(userID),
	})
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
	shareIDStr := r.PathValue("shareId")
	if shareIDStr == "" {
		return apperr.NewBadRequest("invalid share id")
	}
	shareID, err := strconv.ParseInt(shareIDStr, 10, 64)
	if err != nil {
		return apperr.NewBadRequest("invalid share id")
	}
	var req struct {
		CanEdit     bool `json:"can_edit"`
		CanDownload bool `json:"can_download"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()
	existingShare, err := h.db.Queries.GetUserTrackShareByID(ctx, shareID)
	if err := httputil.HandleDBError(err, "share not found", "failed to query share"); err != nil {
		return err
	}
	track, err := h.db.Queries.GetTrackByID(ctx, existingShare.TrackID)
	if err != nil {
		return apperr.NewInternal("failed to query track", err)
	}
	canManage, err := h.canManageTrackShares(ctx, track, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check permissions", err)
	}
	if !canManage {
		return apperr.NewForbidden("unauthorized")
	}
	share, err := h.db.Queries.UpdateUserTrackShareByID(ctx, sqlc.UpdateUserTrackShareByIDParams{
		CanEdit: req.CanEdit, CanDownload: req.CanDownload, ID: shareID,
	})
	if err != nil {
		return apperr.NewInternal("failed to update share", err)
	}
	return httputil.OKResult(w, share)
}
