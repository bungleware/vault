package handlers

import (
	"database/sql"
	"net"
	"net/http"
	"unicode"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/httputil"
	authsvc "bungleware/vault/internal/service"
)

type AuthHandler struct {
	authService authsvc.AuthService
	authConfig  auth.Config
}

func NewAuthHandler(authService authsvc.AuthService, authConfig auth.Config) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		authConfig:  authConfig,
	}
}

func validatePasswordComplexity(password string) error {
	if len(password) < 8 {
		return apperr.NewBadRequest("password must be at least 8 characters")
	}
	var hasUpper, hasLower, hasDigit bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsDigit(c):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return apperr.NewBadRequest("password must contain at least one uppercase letter, one lowercase letter, and one digit")
	}
	return nil
}

func mapAuthError(err error) error {
	if err == nil {
		return nil
	}

	switch err {
	case authsvc.ErrInvalidCredentials:
		return apperr.NewUnauthorized("invalid credentials")
	case authsvc.ErrUserExists:
		return apperr.NewConflict("username or email already exists")
	case authsvc.ErrInvalidToken:
		return apperr.NewUnauthorized("invalid or expired token")
	case authsvc.ErrTokenUsed:
		return apperr.NewUnauthorized("token already used")
	case authsvc.ErrTokenExpired:
		return apperr.NewUnauthorized("token expired")
	case authsvc.ErrInvalidTokenType:
		return apperr.NewUnauthorized("invalid token type")
	case authsvc.ErrRegistrationClosed:
		return apperr.NewForbidden("registration is closed; use an invite link")
	default:
		return apperr.NewInternal("authentication error", err)
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) error {
	req, err := httputil.DecodeJSON[RegisterRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		return apperr.NewBadRequest("username, email, and password are required")
	}

	if err := validatePasswordComplexity(req.Password); err != nil {
		return err
	}

	result, err := h.authService.Register(r.Context(), authsvc.RegisterInput{
		Username:     req.Username,
		Email:        req.Email,
		Password:     req.Password,
		InstanceName: req.InstanceName,
	})
	if err != nil {
		return mapAuthError(err)
	}

	meta := sessionMetaFromRequest(r)
	session, err := h.authService.CreateSession(r.Context(), int(result.User.ID), result.User.Username, meta)
	if err != nil {
		return apperr.NewInternal("failed to create session", err)
	}

	httputil.SetAuthCookies(w, session.AccessToken, session.RefreshToken, session.CSRFToken, h.authConfig)

	return httputil.CreatedResult(w, map[string]interface{}{
		"user": serviceUserToResponse(result.User),
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) error {
	req, err := httputil.DecodeJSON[LoginRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Username == "" || req.Password == "" {
		return apperr.NewBadRequest("username and password are required")
	}

	user, err := h.authService.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		return mapAuthError(err)
	}

	meta := sessionMetaFromRequest(r)
	session, err := h.authService.CreateSession(r.Context(), int(user.ID), user.Username, meta)
	if err != nil {
		return apperr.NewInternal("failed to create session", err)
	}

	httputil.SetAuthCookies(w, session.AccessToken, session.RefreshToken, session.CSRFToken, h.authConfig)

	return httputil.OKResult(w, map[string]interface{}{
		"user": serviceUserToResponse(user),
	})
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	user, err := h.authService.Me(r.Context(), int64(userID))
	if err == sql.ErrNoRows {
		return apperr.NewNotFound("user not found")
	}
	if err != nil {
		return mapAuthError(err)
	}

	return httputil.OKResult(w, serviceUserToResponse(user))
}

func (h *AuthHandler) CheckUsersExists(w http.ResponseWriter, r *http.Request) error {
	usersExist, err := h.authService.CheckUsersExist(r.Context())
	if err != nil {
		return apperr.NewInternal("failed to check users", err)
	}

	return httputil.OKResult(w, map[string]interface{}{
		"users_exist": usersExist,
	})
}

func (h *AuthHandler) UpdateUsername(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	req, err := httputil.DecodeJSON[UpdateUsernameRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Username == "" {
		return apperr.NewBadRequest("username is required")
	}

	updatedUser, err := h.authService.UpdateUsername(r.Context(), int64(userID), req.Username)
	if err != nil {
		if err.Error() == "username already exists" {
			return apperr.NewConflict("username already exists")
		}
		return mapAuthError(err)
	}

	return httputil.OKResult(w, serviceUserToResponse(updatedUser))
}

func (h *AuthHandler) RegisterWithInvite(w http.ResponseWriter, r *http.Request) error {
	req, err := httputil.DecodeJSON[RegisterWithInviteRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Username == "" || req.Password == "" || req.InviteToken == "" {
		return apperr.NewBadRequest("username, password, and invite_token are required")
	}

	if err := validatePasswordComplexity(req.Password); err != nil {
		return err
	}

	result, err := h.authService.RegisterWithInvite(r.Context(), authsvc.RegisterWithInviteInput{
		Username:    req.Username,
		Email:       req.Email,
		Password:    req.Password,
		InviteToken: req.InviteToken,
	})
	if err != nil {
		return mapAuthError(err)
	}

	meta := sessionMetaFromRequest(r)
	session, err := h.authService.CreateSession(r.Context(), int(result.User.ID), result.User.Username, meta)
	if err != nil {
		return apperr.NewInternal("failed to create session", err)
	}

	httputil.SetAuthCookies(w, session.AccessToken, session.RefreshToken, session.CSRFToken, h.authConfig)

	return httputil.CreatedResult(w, map[string]interface{}{
		"user": serviceUserToResponse(result.User),
	})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) error {
	req, err := httputil.DecodeJSON[ResetPasswordRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Password == "" || req.ResetToken == "" {
		return apperr.NewBadRequest("password and reset_token are required")
	}

	if err := validatePasswordComplexity(req.Password); err != nil {
		return err
	}

	if err := h.authService.ResetPassword(r.Context(), req.ResetToken, req.Password); err != nil {
		return mapAuthError(err)
	}

	return httputil.OKResult(w, map[string]interface{}{
		"message": "password reset successfully",
	})
}

func (h *AuthHandler) ValidateResetToken(w http.ResponseWriter, r *http.Request) error {
	token := r.URL.Query().Get("token")
	if token == "" {
		return apperr.NewBadRequest("token is required")
	}

	valid, err := h.authService.ValidateResetToken(r.Context(), token)
	if err != nil {
		return mapAuthError(err)
	}

	return httputil.OKResult(w, map[string]bool{"valid": valid})
}

func (h *AuthHandler) ValidateInviteToken(w http.ResponseWriter, r *http.Request) error {
	token := r.URL.Query().Get("token")
	if token == "" {
		return apperr.NewBadRequest("token is required")
	}

	valid, err := h.authService.ValidateInviteToken(r.Context(), token)
	if err != nil {
		return mapAuthError(err)
	}

	return httputil.OKResult(w, map[string]bool{"valid": valid})
}

func (h *AuthHandler) DeleteSelf(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	user, err := h.authService.Me(ctx, int64(userID))
	if err != nil {
		if err == sql.ErrNoRows {
			return apperr.NewNotFound("user not found")
		}
		return apperr.NewInternal("failed to get user", err)
	}

	if user.IsAdmin {
		return apperr.NewForbidden("admin users cannot delete their own account")
	}

	if user.IsOwner {
		return apperr.NewForbidden("owner cannot delete their own account")
	}

	req, err := httputil.DecodeJSON[DeleteSelfRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Password == "" {
		return apperr.NewBadRequest("password is required for account deletion")
	}

	// Verify password before deletion
	_, err = h.authService.VerifyCredentials(ctx, user.Username, req.Password)
	if err != nil {
		return apperr.NewUnauthorized("incorrect password")
	}

	err = h.authService.DeleteUser(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to delete account", err)
	}

	httputil.ClearAuthCookies(w, h.authConfig)
	httputil.NoContent(w)
	return nil
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) error {
	refreshCookie, err := r.Cookie(auth.RefreshTokenCookieName)
	if err != nil || refreshCookie.Value == "" {
		return apperr.NewUnauthorized("missing refresh token")
	}

	meta := sessionMetaFromRequest(r)
	session, err := h.authService.RefreshSession(r.Context(), refreshCookie.Value, meta)
	if err != nil {
		return mapAuthError(err)
	}

	httputil.SetAuthCookies(w, session.AccessToken, session.RefreshToken, session.CSRFToken, h.authConfig)
	return httputil.OKResult(w, map[string]interface{}{
		"user": serviceUserToResponse(session.User),
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) error {
	refreshCookie, _ := r.Cookie(auth.RefreshTokenCookieName)
	if refreshCookie != nil {
		_ = h.authService.RevokeRefreshToken(r.Context(), refreshCookie.Value)
	}

	httputil.ClearAuthCookies(w, h.authConfig)
	return httputil.OKResult(w, map[string]interface{}{
		"status": "ok",
	})
}

func sessionMetaFromRequest(r *http.Request) authsvc.SessionMeta {
	userAgent := r.Header.Get("User-Agent")
	ip := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		ip = host
	}
	return authsvc.SessionMeta{UserAgent: userAgent, IP: ip}
}

func serviceUserToResponse(user *authsvc.User) map[string]interface{} {
	response := map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
		"email":    user.Email,
		"is_admin": user.IsAdmin,
		"is_owner": user.IsOwner,
	}

	if user.CreatedAt != nil {
		response["created_at"] = *user.CreatedAt
	}
	if user.UpdatedAt != nil {
		response["updated_at"] = *user.UpdatedAt
	}

	return response
}
