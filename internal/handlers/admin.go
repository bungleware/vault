package handlers

import (
	"errors"
	"net/http"
	"time"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

type AdminHandler struct {
	svc service.AdminService
}

func NewAdminHandler(svc service.AdminService) *AdminHandler {
	return &AdminHandler{svc: svc}
}

func (h *AdminHandler) ListAllUsersPublic(w http.ResponseWriter, r *http.Request) error {
	users, err := h.svc.ListAllUsers(r.Context())
	if err != nil {
		return apperr.NewInternal("failed to list users", err)
	}

	userResponses := make([]UserResponse, 0, len(users))
	for _, u := range users {
		userResponses = append(userResponses, UserResponse{
			ID:        u.ID,
			Username:  u.Username,
			Email:     u.Email,
			IsAdmin:   u.IsAdmin,
			IsOwner:   u.IsOwner,
			CreatedAt: u.CreatedAt.Time,
		})
	}

	return httputil.OKResult(w, userResponses)
}

func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) error {
	users, err := h.svc.ListAllUsers(r.Context())
	if err != nil {
		return apperr.NewInternal("failed to list users", err)
	}

	userResponses := make([]UserResponse, 0, len(users))
	for _, u := range users {
		userResponses = append(userResponses, UserResponse{
			ID:        u.ID,
			Username:  u.Username,
			Email:     u.Email,
			IsAdmin:   u.IsAdmin,
			IsOwner:   u.IsOwner,
			CreatedAt: u.CreatedAt.Time,
		})
	}

	return httputil.OKResult(w, userResponses)
}

func (h *AdminHandler) CreateInvite(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	req, err := httputil.DecodeJSON[CreateInviteRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	email := ""
	if req.Email != nil {
		email = *req.Email
	}

	result, err := h.svc.CreateInvite(r.Context(), int64(userID), email)
	if err != nil {
		return apperr.NewInternal("failed to create invite", err)
	}

	return httputil.OKResult(w, map[string]interface{}{
		"id":    result.ID,
		"token": result.Token,
		"email": result.Email,
	})
}

func (h *AdminHandler) UpdateUserRole(w http.ResponseWriter, r *http.Request) error {
	adminID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	req, err := httputil.DecodeJSON[UpdateUserRoleRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	user, err := h.svc.UpdateUserRole(r.Context(), int64(adminID), req.UserID, req.IsAdmin)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("user not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("operation not allowed")
		}
		return apperr.NewInternal("failed to update user role", err)
	}

	return httputil.OKResult(w, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		IsAdmin:   user.IsAdmin,
		IsOwner:   user.IsOwner,
		CreatedAt: user.CreatedAt.Time,
	})
}

func (h *AdminHandler) RenameUser(w http.ResponseWriter, r *http.Request) error {
	adminID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	req, err := httputil.DecodeJSON[RenameUserRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Username == "" {
		return apperr.NewBadRequest("username is required")
	}

	user, err := h.svc.RenameUser(r.Context(), int64(adminID), req.UserID, req.Username)
	if err != nil {
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("users can only rename themselves")
		}
		if errors.Is(err, service.ErrConflict) {
			return apperr.NewConflict("username already exists or user not found")
		}
		return apperr.NewInternal("failed to rename user", err)
	}

	return httputil.OKResult(w, UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		IsAdmin:   user.IsAdmin,
		IsOwner:   user.IsOwner,
		CreatedAt: user.CreatedAt.Time,
	})
}

func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) error {
	adminID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	userID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	err = h.svc.DeleteUser(r.Context(), int64(adminID), userID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("user not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("operation not allowed")
		}
		return apperr.NewInternal("failed to delete user", err)
	}

	httputil.NoContent(w)
	return nil
}

func (h *AdminHandler) CreateResetLink(w http.ResponseWriter, r *http.Request) error {
	adminID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	req, err := httputil.DecodeJSON[CreateResetLinkRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.UserID == 0 {
		return apperr.NewBadRequest("user_id is required")
	}

	result, err := h.svc.CreateResetLink(r.Context(), int64(adminID), req.UserID)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("user not found")
		}
		if errors.Is(err, service.ErrForbidden) {
			return apperr.NewForbidden("operation not allowed")
		}
		return apperr.NewInternal("failed to create reset link", err)
	}

	return httputil.OKResult(w, map[string]interface{}{
		"id":    result.ID,
		"token": result.Token,
		"email": result.Email,
	})
}

type UserResponse struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	IsAdmin   bool      `json:"is_admin"`
	IsOwner   bool      `json:"is_owner"`
	CreatedAt time.Time `json:"created_at"`
}

type CreateInviteRequest struct {
	Email *string `json:"email,omitempty"`
}

type UpdateUserRoleRequest struct {
	UserID  int64 `json:"user_id"`
	IsAdmin bool  `json:"is_admin"`
}

type RenameUserRequest struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
}

type CreateResetLinkRequest struct {
	UserID int64 `json:"user_id"`
}
