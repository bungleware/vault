package handlers

import (
	"database/sql"
	"net/http"
	"time"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
)

type AdminHandler struct {
	db         *db.DB
	authConfig auth.Config
}

func NewAdminHandler(database *db.DB, authConfig auth.Config) *AdminHandler {
	return &AdminHandler{
		db:         database,
		authConfig: authConfig,
	}
}

func (h *AdminHandler) ListAllUsersPublic(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	_, err = h.db.Queries.GetUserByID(ctx, int64(userID))
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	users, err := h.db.Queries.ListAllUsers(ctx)
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
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	user, err := h.db.Queries.GetUserByID(ctx, int64(userID))
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if !user.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	users, err := h.db.Queries.ListAllUsers(ctx)
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

	ctx := r.Context()

	user, err := h.db.Queries.GetUserByID(ctx, int64(userID))
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if !user.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	req, err := httputil.DecodeJSON[CreateInviteRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return apperr.NewInternal("failed to generate token", err)
	}

	email := ""
	if req.Email != nil {
		email = *req.Email
	}

	inviteToken, err := h.db.Queries.CreateInviteToken(ctx, sqlc.CreateInviteTokenParams{
		TokenHash: auth.HashToken(token, h.authConfig.TokenPepper),
		TokenType: "invite",
		CreatedBy: user.ID,
		Email:     email,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	})

	if err != nil {
		return apperr.NewInternal("failed to create invite", err)
	}

	return httputil.OKResult(w, map[string]interface{}{
		"id":    inviteToken.ID,
		"token": token,
		"email": inviteToken.Email,
	})
}

func (h *AdminHandler) UpdateUserRole(w http.ResponseWriter, r *http.Request) error {
	adminID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	admin, err := h.db.Queries.GetUserByID(ctx, int64(adminID))
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if !admin.IsOwner {
		return apperr.NewForbidden("owner access required")
	}

	req, err := httputil.DecodeJSON[UpdateUserRoleRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	targetUser, err := h.db.Queries.GetUserByID(ctx, req.UserID)
	if err != nil {
		return apperr.NewNotFound("target user not found")
	}

	if targetUser.IsOwner && !req.IsAdmin {
		return apperr.NewForbidden("owner must always be admin")
	}

	user, err := h.db.Queries.UpdateUserRole(ctx, sqlc.UpdateUserRoleParams{
		IsAdmin: req.IsAdmin,
		ID:      req.UserID,
	})

	if err != nil {
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

	ctx := r.Context()

	admin, err := h.db.Queries.GetUserByID(ctx, int64(adminID))
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if !admin.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	req, err := httputil.DecodeJSON[RenameUserRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Username == "" {
		return apperr.NewBadRequest("username is required")
	}

	if int64(adminID) != req.UserID {
		return apperr.NewForbidden("users can only rename themselves")
	}

	user, err := h.db.Queries.UpdateUsername(ctx, sqlc.UpdateUsernameParams{
		Username: req.Username,
		ID:       req.UserID,
	})

	if err != nil {
		return apperr.NewConflict("username already exists or user not found")
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

	ctx := r.Context()

	admin, err := h.db.Queries.GetUserByID(ctx, int64(adminID))
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if !admin.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	userID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	targetUser, err := h.db.Queries.GetUserByID(ctx, userID)
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if targetUser.IsOwner {
		return apperr.NewForbidden("cannot delete the owner user")
	}

	users, err := h.db.Queries.ListAllUsers(ctx)
	if err != nil {
		return apperr.NewInternal("failed to check user count", err)
	}

	adminCount := 0
	for _, u := range users {
		if u.IsAdmin {
			adminCount++
		}
	}

	if adminCount <= 1 && admin.ID == userID {
		return apperr.NewForbidden("cannot delete the last admin user")
	}

	err = h.db.Queries.DeleteUserByID(ctx, userID)
	if err != nil {
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

	ctx := r.Context()

	admin, err := h.db.Queries.GetUserByID(ctx, int64(adminID))
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if !admin.IsAdmin {
		return apperr.NewForbidden("admin access required")
	}

	req, err := httputil.DecodeJSON[CreateResetLinkRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.UserID == 0 {
		return apperr.NewBadRequest("user_id is required")
	}

	user, err := h.db.Queries.GetUserByID(ctx, req.UserID)
	if err != nil {
		return apperr.NewNotFound("user not found")
	}

	if user.IsOwner && !admin.IsOwner && admin.ID != user.ID {
		return apperr.NewForbidden("only owner can reset the owner's password")
	}

	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return apperr.NewInternal("failed to generate token", err)
	}

	resetToken, err := h.db.Queries.CreateResetToken(ctx, sqlc.CreateResetTokenParams{
		TokenHash: auth.HashToken(token, h.authConfig.TokenPepper),
		TokenType: "reset",
		UserID: sql.NullInt64{
			Int64: user.ID,
			Valid: true,
		},
		CreatedBy: admin.ID,
		Email:     user.Email,
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	if err != nil {
		return apperr.NewInternal("failed to create reset link", err)
	}

	return httputil.OKResult(w, map[string]interface{}{
		"id":    resetToken.ID,
		"token": token,
		"email": resetToken.Email,
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
