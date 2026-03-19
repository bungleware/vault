package sharing

import (
	"errors"
	"log/slog"
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

func (h *SharingHandler) UpdateTrackVisibility(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	trackID := r.PathValue("id")

	req, err := httputil.DecodeJSON[handlers.UpdateVisibilityRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.VisibilityStatus != "private" && req.VisibilityStatus != "invite_only" && req.VisibilityStatus != "public" {
		return apperr.NewBadRequest("invalid visibility status")
	}

	updated, err := h.svc.UpdateTrackVisibility(r.Context(), int64(userID), trackID, service.UpdateVisibilityInput{
		VisibilityStatus: req.VisibilityStatus,
		AllowEditing:     req.AllowEditing,
		AllowDownloads:   req.AllowDownloads,
		Password:         req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			slog.Warn("track not found for visibility update", "track_id", trackID, "user_id", userID)
			return apperr.NewNotFound("track not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("unauthorized")
		}
		slog.Error("failed to update track visibility", "error", err, "track_id", trackID, "user_id", userID)
		return apperr.NewInternal("failed to update track visibility", err)
	}
	return httputil.OKResult(w, updated)
}

func (h *SharingHandler) UpdateProjectVisibility(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	projectID := r.PathValue("id")

	req, err := httputil.DecodeJSON[handlers.UpdateVisibilityRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.VisibilityStatus != "private" && req.VisibilityStatus != "invite_only" && req.VisibilityStatus != "public" {
		return apperr.NewBadRequest("invalid visibility status")
	}

	updated, err := h.svc.UpdateProjectVisibility(r.Context(), int64(userID), projectID, service.UpdateVisibilityInput{
		VisibilityStatus: req.VisibilityStatus,
		AllowEditing:     req.AllowEditing,
		AllowDownloads:   req.AllowDownloads,
		Password:         req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			slog.Warn("project not found for visibility update", "project_id", projectID, "user_id", userID)
			return apperr.NewNotFound("project not found")
		}
		slog.Error("failed to update project visibility", "error", err, "project_id", projectID, "user_id", userID)
		return apperr.NewInternal("failed to update project visibility", err)
	}
	return httputil.OKResult(w, updated)
}
