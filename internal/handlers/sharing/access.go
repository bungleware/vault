package sharing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/httputil"

	"golang.org/x/crypto/bcrypt"
)

func (h *SharingHandler) AcceptShare(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token is required")
	}

	var req handlers.AcceptShareRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	var shareType string
	var shareTokenID int64
	var canEdit bool
	var canDownload bool

	trackShareToken, err := h.db.GetShareToken(ctx, token)
	if err == nil {
		shareType = "track"
		shareTokenID = trackShareToken.ID
		canEdit = trackShareToken.AllowEditing
		canDownload = trackShareToken.AllowDownloads

		if trackShareToken.PasswordHash.Valid {
			if req.Password == "" {
				return apperr.NewUnauthorized("password required")
			}
			if err := bcrypt.CompareHashAndPassword([]byte(trackShareToken.PasswordHash.String), []byte(req.Password)); err != nil {
				return apperr.NewUnauthorized("invalid password")
			}
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		projectShareToken, err := h.db.GetProjectShareToken(ctx, token)
		if err := httputil.HandleDBError(err, "invalid token", "failed to query token"); err != nil {
			return err
		}

		shareType = "project"
		shareTokenID = projectShareToken.ID
		canEdit = projectShareToken.AllowEditing
		canDownload = projectShareToken.AllowDownloads

		if projectShareToken.PasswordHash.Valid {
			if req.Password == "" {
				return apperr.NewUnauthorized("password required")
			}
			if err := bcrypt.CompareHashAndPassword([]byte(projectShareToken.PasswordHash.String), []byte(req.Password)); err != nil {
				return apperr.NewUnauthorized("invalid password")
			}
		}
	} else {
		return apperr.NewInternal("failed to query token", err)
	}

	var userInstanceURL sql.NullString
	if req.UserInstanceURL != nil {
		userInstanceURL = sql.NullString{String: *req.UserInstanceURL, Valid: true}
	}

	shareAccess, err := h.db.CreateShareAccess(ctx, sqlc.CreateShareAccessParams{
		ShareType:         shareType,
		ShareTokenID:      shareTokenID,
		UserID:            int64(userID),
		UserInstanceUrl:   userInstanceURL,
		FederationTokenID: sql.NullInt64{},
		CanEdit:           canEdit,
		CanDownload:       canDownload,
	})
	if err != nil {
		return apperr.NewInternal("failed to create share access", err)
	}

	return httputil.OKResult(w, shareAccess)
}

func (h *SharingHandler) ListSharedWithMe(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	ctx := r.Context()

	shareAccess, err := h.db.ListShareAccessByUser(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query shared content", err)
	}

	return httputil.OKResult(w, shareAccess)
}

func (h *SharingHandler) LeaveShare(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	shareAccessID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	ctx := r.Context()

	err = h.db.DeleteShareAccess(ctx, sqlc.DeleteShareAccessParams{
		ID:     shareAccessID,
		UserID: int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to leave share", err)
	}

	return httputil.NoContentResult(w)
}

func (h *SharingHandler) LeaveSharedProject(w http.ResponseWriter, r *http.Request) error {
	slog.Info("LeaveSharedProject called", "method", r.Method, "path", r.URL.Path)

	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	projectPublicID := r.PathValue("id")
	slog.Info("LeaveSharedProject project ID", "publicID", projectPublicID)

	if projectPublicID == "" {
		slog.Error("LeaveSharedProject project ID is empty")
		return apperr.NewBadRequest("project ID required")
	}

	ctx := r.Context()

	project, err := h.db.GetProjectByPublicIDNoFilter(ctx, projectPublicID)
	if errors.Is(err, sql.ErrNoRows) {
		slog.Error("LeaveSharedProject project not found", "publicID", projectPublicID)
		return apperr.NewNotFound("project not found")
	}
	if err != nil {
		slog.Error("LeaveSharedProject failed to query project", "error", err)
		return apperr.NewInternal("failed to query project", err)
	}

	slog.Info("LeaveSharedProject found project", "projectID", project.ID, "userID", userID)

	projectShare, err := h.db.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
		ProjectID: project.ID,
		SharedTo:  int64(userID),
	})

	if errors.Is(err, sql.ErrNoRows) {
		slog.Info("No project share found, checking for track shares", "projectID", project.ID, "userID", userID)
		tracks, err := h.db.Queries.ListTracksByProjectID(ctx, project.ID)
		if err != nil {
			slog.Error("Failed to get tracks for project", "error", err)
			return apperr.NewInternal("failed to query tracks", err)
		}

		deletedCount := 0
		for _, track := range tracks {
			err = h.db.Queries.DeleteUserTrackShareByID(ctx, sqlc.DeleteUserTrackShareByIDParams{
				TrackID:  track.ID,
				SharedTo: int64(userID),
			})
			if err != nil && err != sql.ErrNoRows {
				slog.Error("Failed to delete track share", "trackID", track.ID, "error", err)
			} else if err == nil {
				deletedCount++
			}
		}

		if deletedCount == 0 {
			slog.Warn("No track shares found to delete", "projectID", project.ID, "userID", userID)
			return apperr.NewNotFound("no shares found for this project")
		}

		slog.Info("Deleted track shares", "count", deletedCount, "projectID", project.ID, "userID", userID)
		return httputil.NoContentResult(w)
	}

	if err != nil {
		return apperr.NewInternal("failed to query share access", err)
	}

	slog.Info("Deleting project share", "shareID", projectShare.ID)
	err = h.db.Queries.DeleteUserProjectShareByID(ctx, sqlc.DeleteUserProjectShareByIDParams{
		ProjectID: project.ID,
		SharedTo:  int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to leave project", err)
	}

	return httputil.NoContentResult(w)
}

func (h *SharingHandler) LeaveSharedTrack(w http.ResponseWriter, r *http.Request) error {
	slog.Info("LeaveSharedTrack called", "method", r.Method, "path", r.URL.Path)

	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	trackIDStr := r.PathValue("id")
	slog.Info("LeaveSharedTrack track ID", "id", trackIDStr)

	if trackIDStr == "" {
		slog.Error("LeaveSharedTrack track ID is empty")
		return apperr.NewBadRequest("track ID required")
	}

	ctx := r.Context()

	trackID, err := strconv.ParseInt(trackIDStr, 10, 64)
	if err != nil {
		track, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, trackIDStr)
		if errors.Is(err, sql.ErrNoRows) {
			slog.Error("LeaveSharedTrack track not found", "id", trackIDStr)
			return apperr.NewNotFound("track not found")
		}
		if err != nil {
			slog.Error("LeaveSharedTrack failed to query track", "error", err)
			return apperr.NewInternal("failed to query track", err)
		}
		trackID = track.ID
	}

	slog.Info("LeaveSharedTrack found track", "trackID", trackID, "userID", userID)

	err = h.db.Queries.DeleteUserTrackShareByID(ctx, sqlc.DeleteUserTrackShareByIDParams{
		TrackID:  trackID,
		SharedTo: int64(userID),
	})
	if errors.Is(err, sql.ErrNoRows) {
		slog.Warn("No track share found to delete", "trackID", trackID, "userID", userID)
		return apperr.NewNotFound("no share found for this track")
	}
	if err != nil {
		slog.Error("Failed to delete track share", "trackID", trackID, "error", err)
		return apperr.NewInternal("failed to leave track", err)
	}

	slog.Info("Successfully left shared track", "trackID", trackID, "userID", userID)
	return httputil.NoContentResult(w)
}
