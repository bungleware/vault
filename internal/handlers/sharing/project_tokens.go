package sharing

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/auth"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers"
	"bungleware/vault/internal/httputil"

	"golang.org/x/crypto/bcrypt"
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

	var req handlers.CreateProjectShareTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()
	project, err := h.db.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{
		PublicID: projectIDStr,
		UserID:   int64(userID),
	})
	if err := httputil.HandleDBError(err, "project not found", "failed to verify project ownership"); err != nil {
		return err
	}
	if project.UserID != int64(userID) {
		return apperr.NewForbidden("unauthorized")
	}

	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return apperr.NewInternal("failed to generate token", err)
	}

	passwordHash, err := hashSharePassword(req.Password)
	if err != nil {
		return apperr.NewInternal("failed to hash password", err)
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

	shareToken, err := h.db.CreateProjectShareToken(ctx, sqlc.CreateProjectShareTokenParams{
		Token:          token,
		UserID:         int64(userID),
		ProjectID:      project.ID,
		ExpiresAt:      expiresAt,
		MaxAccessCount: maxAccessCount,
		AllowEditing:   req.AllowEditing != nil && *req.AllowEditing,
		AllowDownloads: req.AllowDownloads == nil || *req.AllowDownloads,
		PasswordHash:   passwordHash,
		VisibilityType: visibilityType,
	})
	if err != nil {
		return apperr.NewInternal("failed to create share token", err)
	}

	response := &handlers.ProjectShareTokenResponse{
		ID:                 shareToken.ID,
		Token:              shareToken.Token,
		UserID:             shareToken.UserID,
		ProjectID:          shareToken.ProjectID,
		ExpiresAt:          shareToken.ExpiresAt,
		MaxAccessCount:     shareToken.MaxAccessCount,
		CurrentAccessCount: shareToken.CurrentAccessCount.Int64,
		AllowEditing:       shareToken.AllowEditing,
		AllowDownloads:     shareToken.AllowDownloads,
		HasPassword:        shareToken.PasswordHash.Valid,
		VisibilityType:     shareToken.VisibilityType,
		CreatedAt:          shareToken.CreatedAt.Time,
		ShareURL:           buildShareURL(r, token),
	}
	return httputil.CreatedResult(w, response)
}

func (h *SharingHandler) ValidateProjectShareToken(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token is required")
	}
	password := r.URL.Query().Get("password")
	ctx := r.Context()

	shareToken, err := h.db.GetProjectShareToken(ctx, token)
	if err := httputil.HandleDBError(err, "invalid token", "failed to query token"); err != nil {
		return err
	}

	if shareToken.PasswordHash.Valid {
		if password == "" {
			return httputil.OKResult(w, map[string]interface{}{"valid": false, "password_required": true})
		}
		if err := bcrypt.CompareHashAndPassword([]byte(shareToken.PasswordHash.String), []byte(password)); err != nil {
			return httputil.OKResult(w, map[string]interface{}{"valid": false, "password_required": true, "error": "invalid password"})
		}
	}

	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return httputil.OKResult(w, map[string]interface{}{"valid": false, "error": "token expired"})
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return httputil.OKResult(w, map[string]interface{}{"valid": false, "error": "max access count reached"})
	}

	project, err := h.db.GetProjectByID(ctx, shareToken.ProjectID)
	if err != nil {
		return apperr.NewInternal("failed to query project", err)
	}
	h.db.IncrementProjectAccessCount(ctx, shareToken.ID)

	return httputil.OKResult(w, map[string]interface{}{
		"valid":           true,
		"project":         project,
		"allow_editing":   shareToken.AllowEditing,
		"allow_downloads": shareToken.AllowDownloads,
	})
}

func (h *SharingHandler) ListProjectShareTokens(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}
	ctx := r.Context()

	tokens, err := h.db.ListProjectShareTokensWithProjectInfo(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query tokens", err)
	}

	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host

	response := make([]*handlers.ProjectShareTokenResponse, len(tokens))
	for i, token := range tokens {
		response[i] = &handlers.ProjectShareTokenResponse{
			ID:                 token.ID,
			Token:              token.Token,
			UserID:             token.UserID,
			ProjectID:          token.ProjectID,
			ProjectPublicID:    token.ProjectPublicID,
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

func (h *SharingHandler) UpdateProjectShareToken(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	tokenID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	var req handlers.CreateProjectShareTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return apperr.NewBadRequest("invalid request body")
	}
	ctx := r.Context()

	existingToken, err := h.db.GetProjectShareTokenByID(ctx, sqlc.GetProjectShareTokenByIDParams{
		ID: tokenID, UserID: int64(userID),
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

	updatedToken, err := h.db.UpdateProjectShareToken(ctx, sqlc.UpdateProjectShareTokenParams{
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

	project, err := h.db.GetProject(ctx, sqlc.GetProjectParams{ID: updatedToken.ProjectID, UserID: int64(userID)})
	if err != nil {
		return apperr.NewInternal("failed to get project", err)
	}

	response := &handlers.ProjectShareTokenResponse{
		ID:                 updatedToken.ID,
		Token:              updatedToken.Token,
		UserID:             updatedToken.UserID,
		ProjectID:          updatedToken.ProjectID,
		ProjectPublicID:    project.PublicID,
		AllowEditing:       updatedToken.AllowEditing,
		AllowDownloads:     updatedToken.AllowDownloads,
		HasPassword:        updatedToken.PasswordHash.Valid,
		VisibilityType:     updatedToken.VisibilityType,
		CreatedAt:          updatedToken.CreatedAt.Time,
		UpdatedAt:          updatedToken.UpdatedAt.Time,
		ShareURL:           buildShareURL(r, updatedToken.Token),
		ExpiresAt:          updatedToken.ExpiresAt,
		MaxAccessCount:     updatedToken.MaxAccessCount,
		CurrentAccessCount: updatedToken.CurrentAccessCount.Int64,
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

	err = h.db.DeleteProjectShareToken(r.Context(), sqlc.DeleteProjectShareTokenParams{
		ID: tokenID, UserID: int64(userID),
	})
	if err != nil {
		return apperr.NewInternal("failed to delete token", err)
	}
	return httputil.NoContentResult(w)
}

func (h *SharingHandler) validateProjectShare(w http.ResponseWriter, r *http.Request, shareToken sqlc.ProjectShareToken, password string, ctx context.Context) error {
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
		return httputil.OKResult(w, &handlers.ValidateShareResponse{Valid: false, Error: "token expired"})
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return httputil.OKResult(w, &handlers.ValidateShareResponse{Valid: false, Error: "max access count reached"})
	}

	project, err := h.db.GetProjectByID(ctx, shareToken.ProjectID)
	if err != nil {
		return apperr.NewInternal("failed to query project", err)
	}
	tracksRaw, err := h.db.ListTracksWithDetailsByProjectID(ctx, shareToken.ProjectID)
	if err != nil {
		tracksRaw = []sqlc.ListTracksWithDetailsByProjectIDRow{}
	}

	user, err := h.db.GetUserByID(ctx, project.UserID)
	if err != nil {
		return apperr.NewInternal("failed to get user", err)
	}

	h.db.IncrementProjectAccessCount(ctx, shareToken.ID)

	slog.InfoContext(ctx, "Share token accessed",
		"token_type", "project",
		"project_id", shareToken.ProjectID,
		"has_password", shareToken.PasswordHash.Valid,
		"ip", r.RemoteAddr,
	)

	var coverURL *string
	if project.CoverArtPath.Valid && project.CoverArtPath.String != "" {
		url := project.CoverArtPath.String
		coverURL = &url
	}

	var author string
	if project.AuthorOverride.Valid && project.AuthorOverride.String != "" {
		author = project.AuthorOverride.String
	} else {
		author = user.Username
	}

	projectDetail := &handlers.SharedProjectDetail{
		ID:             project.ID,
		PublicID:       project.PublicID,
		Name:           project.Name,
		UserID:         project.UserID,
		AuthorOverride: &author,
		CoverURL:       coverURL,
		CreatedAt:      project.CreatedAt.Time,
		UpdatedAt:      project.UpdatedAt.Time,
	}

	tracks := make([]map[string]interface{}, len(tracksRaw))
	for i, t := range tracksRaw {
		tracks[i] = map[string]interface{}{
			"id":                              t.ID,
			"user_id":                         t.UserID,
			"project_id":                      t.ProjectID,
			"public_id":                       t.PublicID,
			"title":                           t.Title,
			"track_order":                     t.TrackOrder,
			"visibility_status":               t.VisibilityStatus,
			"active_version_id":               nil,
			"active_version_name":             t.ActiveVersionName,
			"active_version_duration_seconds": nil,
			"waveform":                        nil,
			"lossy_transcoding_status":        nil,
			"artist":                          nil,
			"album":                           nil,
			"key":                             nil,
			"bpm":                             nil,
			"created_at":                      nil,
			"updated_at":                      nil,
		}
		if t.Artist.Valid {
			tracks[i]["artist"] = t.Artist.String
		}
		if t.Album.Valid {
			tracks[i]["album"] = t.Album.String
		}
		if t.Key.Valid {
			tracks[i]["key"] = t.Key.String
		}
		if t.Bpm.Valid {
			tracks[i]["bpm"] = t.Bpm.Int64
		}
		if t.ActiveVersionID.Valid {
			tracks[i]["active_version_id"] = t.ActiveVersionID.Int64
		}
		if t.ActiveVersionDurationSeconds.Valid {
			tracks[i]["active_version_duration_seconds"] = t.ActiveVersionDurationSeconds.Float64
		}
		if t.Waveform.Valid {
			tracks[i]["waveform"] = t.Waveform.String
		}
		if t.LossyTranscodingStatus.Valid {
			tracks[i]["lossy_transcoding_status"] = t.LossyTranscodingStatus.String
		}
		if t.CreatedAt.Valid {
			tracks[i]["created_at"] = t.CreatedAt.Time
		}
		if t.UpdatedAt.Valid {
			tracks[i]["updated_at"] = t.UpdatedAt.Time
		}
	}

	return httputil.OKResult(w, &handlers.ValidateShareResponse{
		Valid:          true,
		Project:        projectDetail,
		Tracks:         tracks,
		AllowEditing:   shareToken.AllowEditing,
		AllowDownloads: shareToken.AllowDownloads,
	})
}
