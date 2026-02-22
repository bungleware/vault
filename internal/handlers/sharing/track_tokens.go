package sharing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/auth"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/sqlutil"

	"golang.org/x/crypto/bcrypt"
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

	var req handlers.CreateShareTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	track, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, trackIDStr)
	if err := httputil.HandleDBError(err, "track not found", "failed to verify track"); err != nil {
		return err
	}

	canManage, err := h.canManageTrackShares(ctx, track, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check permissions", err)
	}
	if !canManage {
		return apperr.NewForbidden("unauthorized")
	}

	trackID := track.ID

	if req.VersionID != nil {
		version, err := h.db.GetTrackVersion(ctx, int64(*req.VersionID))
		if err := httputil.HandleDBError(err, "version not found", "failed to verify version"); err != nil {
			return err
		}
		if version.TrackID != trackID {
			return apperr.NewBadRequest("version does not belong to track")
		}
	}

	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return apperr.NewInternal("failed to generate token", err)
	}

	passwordHash, err := hashSharePassword(req.Password)
	if err != nil {
		return apperr.NewInternal("failed to hash password", err)
	}

	var versionID sql.NullInt64
	if req.VersionID != nil {
		versionID = sql.NullInt64{Int64: int64(*req.VersionID), Valid: true}
	}

	var expiresAt sql.NullTime
	if req.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *req.ExpiresAt, Valid: true}
	}

	var maxAccessCount sql.NullInt64
	if req.MaxAccessCount != nil {
		maxAccessCount = sql.NullInt64{Int64: int64(*req.MaxAccessCount), Valid: true}
	}

	visibilityType := "invite_only"
	if req.VisibilityType != nil {
		visibilityType = *req.VisibilityType
	}

	shareToken, err := h.db.CreateShareToken(ctx, sqlc.CreateShareTokenParams{
		Token:          token,
		UserID:         int64(userID),
		TrackID:        trackID,
		VersionID:      versionID,
		ExpiresAt:      expiresAt,
		MaxAccessCount: maxAccessCount,
		AllowEditing:   req.AllowEditing != nil && *req.AllowEditing,
		AllowDownloads: req.AllowDownloads == nil || *req.AllowDownloads, // Default true
		PasswordHash:   passwordHash,
		VisibilityType: visibilityType,
	})
	if err != nil {
		return apperr.NewInternal("failed to create share token", err)
	}

	shareURL := buildShareURL(r, token)

	response := &handlers.ShareTokenResponse{
		ID:                 shareToken.ID,
		Token:              shareToken.Token,
		UserID:             shareToken.UserID,
		TrackID:            shareToken.TrackID,
		VersionID:          shareToken.VersionID,
		ExpiresAt:          shareToken.ExpiresAt,
		MaxAccessCount:     shareToken.MaxAccessCount,
		CurrentAccessCount: shareToken.CurrentAccessCount.Int64,
		AllowEditing:       shareToken.AllowEditing,
		AllowDownloads:     shareToken.AllowDownloads,
		HasPassword:        shareToken.PasswordHash.Valid,
		VisibilityType:     shareToken.VisibilityType,
		CreatedAt:          shareToken.CreatedAt.Time,
		ShareURL:           shareURL,
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

	shareToken, err := h.db.GetShareToken(ctx, token)
	if err == nil {
		return h.validateTrackShare(w, r, shareToken, password, ctx)
	}

	if errors.Is(err, sql.ErrNoRows) {
		projectShareToken, err := h.db.GetProjectShareToken(ctx, token)
		if err := httputil.HandleDBError(err, "invalid token", "failed to query token"); err != nil {
			return err
		}
		return h.validateProjectShare(w, r, projectShareToken, password, ctx)
	}

	return apperr.NewInternal("failed to query token", err)
}

func (h *SharingHandler) validateTrackShare(w http.ResponseWriter, r *http.Request, shareToken sqlc.ShareToken, password string, ctx context.Context) error {
	if shareToken.PasswordHash.Valid {
		if password == "" {
			return httputil.OKResult(w, &handlers.ValidateShareResponse{
				Valid:            false,
				PasswordRequired: true,
			})
		}
		if err := bcrypt.CompareHashAndPassword([]byte(shareToken.PasswordHash.String), []byte(password)); err != nil {
			return httputil.OKResult(w, &handlers.ValidateShareResponse{
				Valid:            false,
				PasswordRequired: true,
				Error:            "invalid password",
			})
		}
	}

	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return httputil.OKResult(w, &handlers.ValidateShareResponse{
			Valid: false,
			Error: "token expired",
		})
	}

	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return httputil.OKResult(w, &handlers.ValidateShareResponse{
			Valid: false,
			Error: "max access count reached",
		})
	}

	trackDetails, err := h.db.GetTrackWithDetails(ctx, sqlc.GetTrackWithDetailsParams{
		ID:     shareToken.TrackID,
		UserID: shareToken.UserID,
	})
	if err != nil {
		return apperr.NewInternal("failed to query track", err)
	}

	project, err := h.db.GetProjectByID(ctx, trackDetails.ProjectID)
	if err != nil {
		return apperr.NewInternal("failed to query project", err)
	}

	user, err := h.db.GetUserByID(ctx, shareToken.UserID)
	if err != nil {
		return apperr.NewInternal("failed to query user", err)
	}

	var version *sqlc.TrackVersion
	versionID := shareToken.VersionID
	if !versionID.Valid && trackDetails.ActiveVersionID.Valid {
		versionID = trackDetails.ActiveVersionID
	}

	if versionID.Valid {
		v, err := h.db.GetTrackVersion(ctx, versionID.Int64)
		if err == nil {
			version = &v
		}
	}

	h.db.IncrementAccessCount(ctx, shareToken.ID)

	slog.InfoContext(ctx, "Share token accessed",
		"token_type", "track",
		"track_id", trackDetails.ID,
		"has_password", shareToken.PasswordHash.Valid,
		"ip", r.RemoteAddr,
	)

	var coverURL *string
	if project.CoverArtPath.Valid && project.CoverArtPath.String != "" {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		url := fmt.Sprintf("%s://%s/api/share/%s/cover", scheme, r.Host, shareToken.Token)
		coverURL = &url
	}

	var artist *string
	if project.AuthorOverride.Valid && project.AuthorOverride.String != "" {
		artist = &project.AuthorOverride.String
	} else if trackDetails.Artist.Valid && trackDetails.Artist.String != "" {
		artist = &trackDetails.Artist.String
	} else {
		artist = &user.Username
	}

	trackDetail := &handlers.SharedTrackDetail{
		ID:               trackDetails.ID,
		UserID:           trackDetails.UserID,
		ProjectID:        trackDetails.ProjectID,
		PublicID:         trackDetails.PublicID,
		Title:            trackDetails.Title,
		Artist:           artist,
		Album:            sqlutil.StringPtr(trackDetails.Album),
		Key:              sqlutil.StringPtr(trackDetails.Key),
		BPM:              sqlutil.Int64Ptr(trackDetails.Bpm),
		Waveform:         sqlutil.StringPtr(trackDetails.Waveform),
		ActiveVersionID:  sqlutil.Int64Ptr(trackDetails.ActiveVersionID),
		TrackOrder:       trackDetails.TrackOrder,
		VisibilityStatus: trackDetails.VisibilityStatus,
		CoverURL:         coverURL,
		CreatedAt:        trackDetails.CreatedAt.Time,
		UpdatedAt:        trackDetails.UpdatedAt.Time,
	}

	projectDetail := &handlers.SharedProjectDetail{
		ID:             project.ID,
		PublicID:       project.PublicID,
		Name:           project.Name,
		UserID:         project.UserID,
		AuthorOverride: sqlutil.StringPtr(project.AuthorOverride),
		CoverURL:       coverURL,
		CreatedAt:      project.CreatedAt.Time,
		UpdatedAt:      project.UpdatedAt.Time,
	}

	response := &handlers.ValidateShareResponse{
		Valid:          true,
		Track:          trackDetail,
		Project:        projectDetail,
		Version:        version,
		AllowEditing:   shareToken.AllowEditing,
		AllowDownloads: shareToken.AllowDownloads,
	}

	return httputil.OKResult(w, response)
}

func (h *SharingHandler) UpdateSharedTrackFromToken(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	token := r.PathValue("token")
	trackID := r.PathValue("trackId")

	shareToken, err := h.db.Queries.GetShareToken(ctx, token)
	if err != nil {
		return apperr.NewUnauthorized("invalid share token")
	}

	if !shareToken.AllowEditing {
		return apperr.NewForbidden("editing not allowed")
	}

	var req struct {
		Title string `json:"title"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request")
	}

	trackIDInt, err := strconv.ParseInt(trackID, 10, 64)
	if err != nil {
		return apperr.NewBadRequest("invalid track id")
	}

	track, err := h.db.Queries.GetTrackByID(ctx, trackIDInt)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	updatedTrack, err := h.db.Queries.UpdateTrack(ctx, sqlc.UpdateTrackParams{
		ID:    track.ID,
		Title: req.Title,
	})
	if err != nil {
		return apperr.NewInternal("failed to update track", err)
	}

	return httputil.OKResult(w, updatedTrack)
}

func (h *SharingHandler) ListShareTokens(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	ctx := r.Context()

	tokens, err := h.db.ListShareTokensWithTrackInfo(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query tokens", err)
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host

	response := make([]*handlers.ShareTokenResponse, len(tokens))
	for i, token := range tokens {
		response[i] = &handlers.ShareTokenResponse{
			ID:                 token.ID,
			Token:              token.Token,
			UserID:             token.UserID,
			TrackID:            token.TrackID,
			TrackPublicID:      token.TrackPublicID,
			VersionID:          token.VersionID,
			ExpiresAt:          token.ExpiresAt,
			MaxAccessCount:     token.MaxAccessCount,
			CurrentAccessCount: token.CurrentAccessCount.Int64,
			AllowEditing:       token.AllowEditing,
			AllowDownloads:     token.AllowDownloads,
			HasPassword:        token.PasswordHash.Valid,
			VisibilityType:     token.VisibilityType,
			CreatedAt:          token.CreatedAt.Time,
			UpdatedAt:          token.UpdatedAt.Time,
			ShareURL:           scheme + "://" + host + "/share/" + token.Token,
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

	var req handlers.CreateShareTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	existingToken, err := h.db.GetShareTokenByID(ctx, sqlc.GetShareTokenByIDParams{
		ID:     tokenID,
		UserID: int64(userID),
	})
	if err := httputil.HandleDBError(err, "share token not found", "failed to get token"); err != nil {
		return err
	}

	if existingToken.UserID != int64(userID) {
		return apperr.NewForbidden("unauthorized")
	}

	passwordHash, err := hashSharePassword(req.Password)
	if err != nil {
		return apperr.NewInternal("failed to hash password", err)
	}

	updatedToken, err := h.db.UpdateShareToken(ctx, sqlc.UpdateShareTokenParams{
		ExpiresAt:      existingToken.ExpiresAt,
		MaxAccessCount: existingToken.MaxAccessCount,
		AllowEditing:   req.AllowEditing != nil && *req.AllowEditing,
		AllowDownloads: req.AllowDownloads != nil && *req.AllowDownloads,
		PasswordHash:   passwordHash,
		VisibilityType: existingToken.VisibilityType,
		ID:             tokenID,
		UserID:         int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to update token", err)
	}

	track, err := h.db.GetTrackByID(ctx, updatedToken.TrackID)
	if err != nil {
		return apperr.NewInternal("failed to get track", err)
	}

	shareURL := buildShareURL(r, updatedToken.Token)

	response := &handlers.ShareTokenResponse{
		ID:                 updatedToken.ID,
		Token:              updatedToken.Token,
		UserID:             updatedToken.UserID,
		TrackID:            updatedToken.TrackID,
		TrackPublicID:      track.PublicID,
		AllowEditing:       updatedToken.AllowEditing,
		AllowDownloads:     updatedToken.AllowDownloads,
		HasPassword:        updatedToken.PasswordHash.Valid,
		VisibilityType:     updatedToken.VisibilityType,
		CreatedAt:          updatedToken.CreatedAt.Time,
		UpdatedAt:          updatedToken.UpdatedAt.Time,
		ShareURL:           shareURL,
		ExpiresAt:          updatedToken.ExpiresAt,
		MaxAccessCount:     updatedToken.MaxAccessCount,
		CurrentAccessCount: updatedToken.CurrentAccessCount.Int64,
		VersionID:          updatedToken.VersionID,
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

	ctx := r.Context()

	err = h.db.DeleteShareToken(ctx, sqlc.DeleteShareTokenParams{
		ID:     tokenID,
		UserID: int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to delete token", err)
	}

	return httputil.NoContentResult(w)
}
