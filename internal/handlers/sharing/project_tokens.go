package sharing

import (
	"errors"
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/sqlutil"
)

func (h *SharingHandler) CreateProjectShareToken(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	projectIDStr := r.PathValue("id")
	if projectIDStr == "" {
		return apperr.NewBadRequest("project ID required")
	}

	req, err := httputil.DecodeJSON[handlers.CreateProjectShareTokenRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	var maxAccessCount *int64
	if req.MaxAccessCount != nil {
		mac := int64(*req.MaxAccessCount)
		maxAccessCount = &mac
	}

	shareToken, err := h.svc.CreateProjectShareToken(r.Context(), int64(userID), projectIDStr, service.CreateProjectShareTokenInput{
		Password:       req.Password,
		ExpiresAt:      req.ExpiresAt,
		MaxAccessCount: maxAccessCount,
		AllowEditing:   req.AllowEditing,
		AllowDownloads: req.AllowDownloads,
		VisibilityType: req.VisibilityType,
	})
	if err != nil {
		return mapSharingErr(err)
	}

	response := &handlers.ProjectShareTokenResponse{
		ID:                 shareToken.ID,
		Token:              shareToken.Token,
		UserID:             shareToken.UserID,
		ProjectID:          shareToken.ProjectID,
		ExpiresAt:          sqlutil.TimePtr(shareToken.ExpiresAt),
		MaxAccessCount:     sqlutil.Int64Ptr(shareToken.MaxAccessCount),
		CurrentAccessCount: shareToken.CurrentAccessCount.Int64,
		AllowEditing:       shareToken.AllowEditing,
		AllowDownloads:     shareToken.AllowDownloads,
		HasPassword:        shareToken.PasswordHash.Valid,
		VisibilityType:     shareToken.VisibilityType,
		CreatedAt:          shareToken.CreatedAt.Time,
		ShareURL:           h.buildShareURL(r, shareToken.Token),
	}
	return httputil.CreatedResult(w, response)
}

func (h *SharingHandler) ListProjectShareTokens(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tokens, err := h.svc.ListProjectShareTokens(r.Context(), int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query tokens", err)
	}

	response := make([]*handlers.ProjectShareTokenResponse, len(tokens))
	for i, token := range tokens {
		response[i] = &handlers.ProjectShareTokenResponse{
			ID:                 token.ID,
			Token:              token.Token,
			UserID:             token.UserID,
			ProjectID:          token.ProjectID,
			ProjectPublicID:    token.ProjectPublicID,
			ExpiresAt:          sqlutil.TimePtr(token.ExpiresAt),
			MaxAccessCount:     sqlutil.Int64Ptr(token.MaxAccessCount),
			CurrentAccessCount: token.CurrentAccessCount.Int64,
			AllowEditing:       token.AllowEditing,
			AllowDownloads:     token.AllowDownloads,
			HasPassword:        token.PasswordHash.Valid,
			VisibilityType:     token.VisibilityType,
			CreatedAt:          token.CreatedAt.Time,
			UpdatedAt:          sqlutil.TimePtr(token.UpdatedAt),
			ShareURL:           h.buildShareURL(r, token.Token),
		}
	}
	return httputil.OKResult(w, response)
}

func (h *SharingHandler) UpdateProjectShareToken(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tokenID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	req, err := httputil.DecodeJSON[handlers.CreateProjectShareTokenRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	result, err := h.svc.UpdateProjectShareToken(r.Context(), int64(userID), tokenID, service.UpdateShareTokenInput{
		AllowEditing:   req.AllowEditing,
		AllowDownloads: req.AllowDownloads,
		Password:       req.Password,
	})
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("share token not found")
		}
		return apperr.NewInternal("failed to update token", err)
	}

	response := &handlers.ProjectShareTokenResponse{
		ID:                 result.Token.ID,
		Token:              result.Token.Token,
		UserID:             result.Token.UserID,
		ProjectID:          result.Token.ProjectID,
		ProjectPublicID:    result.ProjectPublicID,
		AllowEditing:       result.Token.AllowEditing,
		AllowDownloads:     result.Token.AllowDownloads,
		HasPassword:        result.Token.PasswordHash.Valid,
		VisibilityType:     result.Token.VisibilityType,
		CreatedAt:          result.Token.CreatedAt.Time,
		UpdatedAt:          sqlutil.TimePtr(result.Token.UpdatedAt),
		ShareURL:           h.buildShareURL(r, result.Token.Token),
		ExpiresAt:          sqlutil.TimePtr(result.Token.ExpiresAt),
		MaxAccessCount:     sqlutil.Int64Ptr(result.Token.MaxAccessCount),
		CurrentAccessCount: result.Token.CurrentAccessCount.Int64,
	}
	return httputil.OKResult(w, response)
}

func (h *SharingHandler) DeleteProjectShareToken(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tokenID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	if err := h.svc.DeleteProjectShareToken(r.Context(), int64(userID), tokenID); err != nil {
		return apperr.NewInternal("failed to delete token", err)
	}
	return httputil.NoContentResult(w)
}
