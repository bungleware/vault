package sharing

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/httputil"
)

func (h *SharingHandler) UpdateTrackVisibility(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	trackID := r.PathValue("id")

	var req handlers.UpdateVisibilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.VisibilityStatus != "private" && req.VisibilityStatus != "invite_only" && req.VisibilityStatus != "public" {
		return apperr.NewBadRequest("invalid visibility status")
	}

	ctx := r.Context()

	track, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, trackID)
	if err := httputil.HandleDBError(err, "track not found", "failed to query track"); err != nil {
		return err
	}

	canManage, err := h.canManageTrackShares(ctx, track, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check permissions", err)
	}
	if !canManage {
		return apperr.NewForbidden("unauthorized")
	}

	passwordHash, err := hashSharePassword(req.Password)
	if err != nil {
		return apperr.NewInternal("failed to hash password", err)
	}

	updatedTrack, err := h.db.Queries.UpdateTrackVisibilityByPublicIDNoUserFilter(ctx, sqlc.UpdateTrackVisibilityByPublicIDNoUserFilterParams{
		VisibilityStatus: req.VisibilityStatus,
		AllowEditing:     req.AllowEditing,
		AllowDownloads:   req.AllowDownloads,
		PasswordHash:     passwordHash,
		PublicID:         trackID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		slog.Warn("track not found for visibility update",
			"track_id", trackID,
			"user_id", userID)
		return apperr.NewNotFound("track not found")
	}
	if err != nil {
		slog.Error("failed to update track visibility",
			"error", err,
			"track_id", trackID,
			"user_id", userID,
			"visibility", req.VisibilityStatus)
		return apperr.NewInternal("failed to update track visibility", err)
	}

	return httputil.OKResult(w, updatedTrack)
}

func (h *SharingHandler) UpdateProjectVisibility(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	projectID := r.PathValue("id")

	var req handlers.UpdateVisibilityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.VisibilityStatus != "private" && req.VisibilityStatus != "invite_only" && req.VisibilityStatus != "public" {
		return apperr.NewBadRequest("invalid visibility status")
	}

	ctx := r.Context()

	passwordHash, err := hashSharePassword(req.Password)
	if err != nil {
		return apperr.NewInternal("failed to hash password", err)
	}

	project, err := h.db.UpdateProjectVisibilityByPublicID(ctx, sqlc.UpdateProjectVisibilityByPublicIDParams{
		VisibilityStatus: req.VisibilityStatus,
		AllowEditing:     req.AllowEditing,
		AllowDownloads:   req.AllowDownloads,
		PasswordHash:     passwordHash,
		PublicID:         projectID,
		UserID:           int64(userID),
	})
	if errors.Is(err, sql.ErrNoRows) {
		slog.Warn("project not found for visibility update",
			"project_id", projectID,
			"user_id", userID)
		return apperr.NewNotFound("project not found")
	}
	if err != nil {
		slog.Error("failed to update project visibility",
			"error", err,
			"project_id", projectID,
			"user_id", userID,
			"visibility", req.VisibilityStatus)
		return apperr.NewInternal("failed to update project visibility", err)
	}

	return httputil.OKResult(w, project)
}
