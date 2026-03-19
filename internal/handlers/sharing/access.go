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

func (h *SharingHandler) AcceptShare(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token is required")
	}

	req, err := httputil.DecodeJSON[handlers.AcceptShareRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	shareAccess, err := h.svc.AcceptShare(r.Context(), int64(userID), token, req.Password, req.UserInstanceURL)
	if err != nil {
		if errors.Is(err, service.ErrShareExpired) {
			return apperr.NewForbidden("share token expired")
		}
		if errors.Is(err, service.ErrAccessLimitReached) {
			return apperr.NewForbidden("max access count reached")
		}
		if errors.Is(err, service.ErrPasswordRequired) {
			return apperr.NewUnauthorized("password required")
		}
		if errors.Is(err, service.ErrInvalidPassword) {
			return apperr.NewUnauthorized("invalid password")
		}
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("invalid token")
		}
		return apperr.NewInternal("failed to create share access", err)
	}
	return httputil.OKResult(w, shareAccess)
}

func (h *SharingHandler) ListSharedWithMe(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	shareAccess, err := h.svc.ListSharedWithMe(r.Context(), int64(userID))
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

	if err := h.svc.LeaveShare(r.Context(), int64(userID), shareAccessID); err != nil {
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
	if projectPublicID == "" {
		return apperr.NewBadRequest("project ID required")
	}

	if err := h.svc.LeaveSharedProject(r.Context(), int64(userID), projectPublicID); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound(err.Error())
		}
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
	if trackIDStr == "" {
		return apperr.NewBadRequest("track ID required")
	}

	if err := h.svc.LeaveSharedTrack(r.Context(), int64(userID), trackIDStr); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound(err.Error())
		}
		return apperr.NewInternal("failed to leave track", err)
	}
	return httputil.NoContentResult(w)
}
