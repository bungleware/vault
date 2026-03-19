package sharing

import (
	"errors"
	"log/slog"
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/sqlutil"
)

func (h *SharingHandler) CreateShareToken(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	trackIDStr := r.PathValue("id")
	if trackIDStr == "" {
		return apperr.NewBadRequest("track ID required")
	}

	req, err := httputil.DecodeJSON[handlers.CreateShareTokenRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	var versionID *int64
	if req.VersionID != nil {
		id := int64(*req.VersionID)
		versionID = &id
	}
	var maxAccessCount *int64
	if req.MaxAccessCount != nil {
		mac := int64(*req.MaxAccessCount)
		maxAccessCount = &mac
	}

	shareToken, err := h.svc.CreateTrackShareToken(r.Context(), int64(userID), trackIDStr, service.CreateTrackShareTokenInput{
		VersionID:      versionID,
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

	response := &handlers.ShareTokenResponse{
		ID:                 shareToken.ID,
		Token:              shareToken.Token,
		UserID:             shareToken.UserID,
		TrackID:            shareToken.TrackID,
		VersionID:          sqlutil.Int64Ptr(shareToken.VersionID),
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

func (h *SharingHandler) ValidateShareToken(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token is required")
	}

	password := r.URL.Query().Get("password")
	ctx := r.Context()

	// Try track share first.
	result, err := h.svc.ValidateTrackShare(ctx, token, password)
	if err == nil {
		return h.writeTrackShareResponse(w, r, result)
	}
	if !errors.Is(err, service.ErrNotFound) {
		return h.writeShareValidationError(w, err)
	}

	// Fall back to project share.
	pResult, err := h.svc.ValidateProjectShare(ctx, token, password)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return apperr.NewNotFound("invalid token")
		}
		return h.writeShareValidationError(w, err)
	}
	return h.writeProjectShareResponse(w, r, pResult)
}

func (h *SharingHandler) writeShareValidationError(w http.ResponseWriter, err error) error {
	switch {
	case errors.Is(err, service.ErrPasswordRequired):
		return httputil.OKResult(w, &handlers.ValidateShareResponse{Valid: false, PasswordRequired: true})
	case errors.Is(err, service.ErrInvalidPassword):
		return httputil.OKResult(w, &handlers.ValidateShareResponse{Valid: false, PasswordRequired: true, Error: "invalid password"})
	case errors.Is(err, service.ErrShareExpired):
		return httputil.OKResult(w, &handlers.ValidateShareResponse{Valid: false, Error: "token expired"})
	case errors.Is(err, service.ErrAccessLimitReached):
		return httputil.OKResult(w, &handlers.ValidateShareResponse{Valid: false, Error: "max access count reached"})
	default:
		return apperr.NewInternal("failed to validate token", err)
	}
}

func (h *SharingHandler) writeTrackShareResponse(w http.ResponseWriter, r *http.Request, result *service.ValidateTrackShareResult) error {
	slog.InfoContext(r.Context(), "Share token accessed",
		"token_type", "track",
		"track_id", result.Track.ID,
		"has_password", result.Token.PasswordHash.Valid,
		"ip", r.RemoteAddr,
	)

	var coverURL *string
	if result.Project.CoverArtPath.Valid && result.Project.CoverArtPath.String != "" {
		url := h.buildShareCoverURL(r, result.Token.Token)
		coverURL = &url
	}

	var artist *string
	if result.Project.AuthorOverride.Valid && result.Project.AuthorOverride.String != "" {
		artist = &result.Project.AuthorOverride.String
	} else if result.Track.Artist.Valid && result.Track.Artist.String != "" {
		artist = &result.Track.Artist.String
	} else {
		artist = &result.User.Username
	}

	trackDetail := &handlers.SharedTrackDetail{
		ID:               result.Track.ID,
		UserID:           result.Track.UserID,
		ProjectID:        result.Track.ProjectID,
		PublicID:         result.Track.PublicID,
		Title:            result.Track.Title,
		Artist:           artist,
		Album:            sqlutil.StringPtr(result.Track.Album),
		Key:              sqlutil.StringPtr(result.Track.Key),
		BPM:              sqlutil.Int64Ptr(result.Track.Bpm),
		Waveform:         sqlutil.StringPtr(result.Track.Waveform),
		ActiveVersionID:  sqlutil.Int64Ptr(result.Track.ActiveVersionID),
		TrackOrder:       result.Track.TrackOrder,
		VisibilityStatus: result.Track.VisibilityStatus,
		CoverURL:         coverURL,
		CreatedAt:        result.Track.CreatedAt.Time,
		UpdatedAt:        sqlutil.TimePtr(result.Track.UpdatedAt),
	}
	projectDetail := &handlers.SharedProjectDetail{
		ID:             result.Project.ID,
		PublicID:       result.Project.PublicID,
		Name:           result.Project.Name,
		UserID:         result.Project.UserID,
		AuthorOverride: sqlutil.StringPtr(result.Project.AuthorOverride),
		CoverURL:       coverURL,
		CreatedAt:      result.Project.CreatedAt.Time,
		UpdatedAt:      sqlutil.TimePtr(result.Project.UpdatedAt),
	}

	return httputil.OKResult(w, &handlers.ValidateShareResponse{
		Valid:          true,
		Track:          trackDetail,
		Project:        projectDetail,
		Version:        result.Version,
		AllowEditing:   result.AllowEditing,
		AllowDownloads: result.AllowDownloads,
	})
}

type updateSharedTrackReq struct {
	Title    string `json:"title"`
	Password string `json:"password,omitempty"`
}

func (h *SharingHandler) UpdateSharedTrackFromToken(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")

	req, err := httputil.DecodeJSON[updateSharedTrackReq](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request")
	}

	trackID, err := httputil.PathInt64(r, "trackId")
	if err != nil {
		return apperr.NewBadRequest("invalid track id")
	}

	updated, err := h.svc.UpdateSharedTrackFromToken(r.Context(), token, trackID, req.Title, req.Password)
	if err != nil {
		return mapSharingErr(err)
	}
	return httputil.OKResult(w, updated)
}

func (h *SharingHandler) ListShareTokens(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tokens, err := h.svc.ListTrackShareTokens(r.Context(), int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query tokens", err)
	}

	response := make([]*handlers.ShareTokenResponse, len(tokens))
	for i, token := range tokens {
		response[i] = &handlers.ShareTokenResponse{
			ID:                 token.ID,
			Token:              token.Token,
			UserID:             token.UserID,
			TrackID:            token.TrackID,
			TrackPublicID:      token.TrackPublicID,
			VersionID:          sqlutil.Int64Ptr(token.VersionID),
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

func (h *SharingHandler) UpdateShareToken(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tokenID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	req, err := httputil.DecodeJSON[handlers.CreateShareTokenRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	result, err := h.svc.UpdateTrackShareToken(r.Context(), int64(userID), tokenID, service.UpdateShareTokenInput{
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

	shareURL := h.buildShareURL(r, result.Token.Token)
	response := &handlers.ShareTokenResponse{
		ID:                 result.Token.ID,
		Token:              result.Token.Token,
		UserID:             result.Token.UserID,
		TrackID:            result.Token.TrackID,
		TrackPublicID:      result.TrackPublicID,
		AllowEditing:       result.Token.AllowEditing,
		AllowDownloads:     result.Token.AllowDownloads,
		HasPassword:        result.Token.PasswordHash.Valid,
		VisibilityType:     result.Token.VisibilityType,
		CreatedAt:          result.Token.CreatedAt.Time,
		UpdatedAt:          sqlutil.TimePtr(result.Token.UpdatedAt),
		ShareURL:           shareURL,
		ExpiresAt:          sqlutil.TimePtr(result.Token.ExpiresAt),
		MaxAccessCount:     sqlutil.Int64Ptr(result.Token.MaxAccessCount),
		CurrentAccessCount: result.Token.CurrentAccessCount.Int64,
		VersionID:          sqlutil.Int64Ptr(result.Token.VersionID),
	}
	return httputil.OKResult(w, response)
}

func (h *SharingHandler) DeleteShareToken(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tokenID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	if err := h.svc.DeleteTrackShareToken(r.Context(), int64(userID), tokenID); err != nil {
		return apperr.NewInternal("failed to delete token", err)
	}
	return httputil.NoContentResult(w)
}

// writeProjectShareResponse is defined here since ValidateShareToken calls it.
func (h *SharingHandler) writeProjectShareResponse(w http.ResponseWriter, r *http.Request, result *service.ValidateProjectShareResult) error {
	slog.InfoContext(r.Context(), "Share token accessed",
		"token_type", "project",
		"project_id", result.Token.ProjectID,
		"has_password", result.Token.PasswordHash.Valid,
		"ip", r.RemoteAddr,
	)

	var coverURL *string
	if result.Project.CoverArtPath.Valid && result.Project.CoverArtPath.String != "" {
		url := result.Project.CoverArtPath.String
		coverURL = &url
	}

	var author string
	if result.Project.AuthorOverride.Valid && result.Project.AuthorOverride.String != "" {
		author = result.Project.AuthorOverride.String
	} else {
		author = result.User.Username
	}

	projectDetail := &handlers.SharedProjectDetail{
		ID:             result.Project.ID,
		PublicID:       result.Project.PublicID,
		Name:           result.Project.Name,
		UserID:         result.Project.UserID,
		AuthorOverride: &author,
		CoverURL:       coverURL,
		CreatedAt:      result.Project.CreatedAt.Time,
		UpdatedAt:      sqlutil.TimePtr(result.Project.UpdatedAt),
	}

	// Build typed track list
	tracks := make([]handlers.SharedProjectTrack, len(result.Tracks))
	for i, t := range result.Tracks {
		var activeVersionName *string
		if t.ActiveVersionName != "" {
			activeVersionName = &t.ActiveVersionName
		}
		tracks[i] = handlers.SharedProjectTrack{
			ID:                           t.ID,
			UserID:                       t.UserID,
			ProjectID:                    t.ProjectID,
			PublicID:                     t.PublicID,
			Title:                        t.Title,
			TrackOrder:                   t.TrackOrder,
			VisibilityStatus:             t.VisibilityStatus,
			ActiveVersionID:              sqlutil.Int64Ptr(t.ActiveVersionID),
			ActiveVersionName:            activeVersionName,
			ActiveVersionDurationSeconds: sqlutil.Float64Ptr(t.ActiveVersionDurationSeconds),
			Waveform:                     sqlutil.StringPtr(t.Waveform),
			LossyTranscodingStatus:       sqlutil.StringPtr(t.LossyTranscodingStatus),
			Artist:                       sqlutil.StringPtr(t.Artist),
			Album:                        sqlutil.StringPtr(t.Album),
			Key:                          sqlutil.StringPtr(t.Key),
			BPM:                          sqlutil.Int64Ptr(t.Bpm),
			CreatedAt:                    sqlutil.TimePtr(t.CreatedAt),
			UpdatedAt:                    sqlutil.TimePtr(t.UpdatedAt),
		}
	}

	return httputil.OKResult(w, &handlers.ValidateShareResponse{
		Valid:          true,
		Project:        projectDetail,
		Tracks:         tracks,
		AllowEditing:   result.AllowEditing,
		AllowDownloads: result.AllowDownloads,
	})
}

