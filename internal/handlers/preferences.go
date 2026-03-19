package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

type PreferencesResponse struct {
	UserID             int64     `json:"user_id"`
	DefaultQuality     string    `json:"default_quality"`
	DiscColors         *[]string `json:"disc_colors,omitempty"`
	ColorSpread        *int      `json:"color_spread,omitempty"`
	GradientSpread     *int      `json:"gradient_spread,omitempty"`
	ColorShiftRotation *int      `json:"color_shift_rotation,omitempty"`
	CreatedAt          string    `json:"created_at"`
	UpdatedAt          string    `json:"updated_at"`
}

type PreferencesHandler struct {
	svc service.PreferencesService
}

func NewPreferencesHandler(svc service.PreferencesService) *PreferencesHandler {
	return &PreferencesHandler{svc: svc}
}

func toPreferencesResponse(prefs sqlc.UserPreference) PreferencesResponse {
	resp := PreferencesResponse{
		UserID:         prefs.UserID,
		DefaultQuality: prefs.DefaultQuality,
		CreatedAt:      prefs.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt:      prefs.UpdatedAt.Time.Format(time.RFC3339),
	}

	if prefs.DiscColors.Valid && prefs.DiscColors.String != "" {
		var colors []string
		if err := json.Unmarshal([]byte(prefs.DiscColors.String), &colors); err == nil {
			resp.DiscColors = &colors
		}
	}

	if prefs.ColorSpread.Valid {
		spread := int(prefs.ColorSpread.Int64)
		resp.ColorSpread = &spread
	}

	if prefs.GradientSpread.Valid {
		gradSpread := int(prefs.GradientSpread.Int64)
		resp.GradientSpread = &gradSpread
	}

	if prefs.ColorShiftRotation.Valid {
		shift := int(prefs.ColorShiftRotation.Int64)
		resp.ColorShiftRotation = &shift
	}

	return resp
}

func (h *PreferencesHandler) GetPreferences(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	prefs, err := h.svc.GetUserPreferences(r.Context(), int64(userID))
	if err := httputil.HandleDBError(err, "preferences not found", "failed to get preferences"); err != nil {
		return err
	}

	return httputil.OKResult(w, toPreferencesResponse(prefs))
}

func (h *PreferencesHandler) UpdatePreferences(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	req, err := httputil.DecodeJSON[UpdatePreferencesRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.DefaultQuality != nil {
		if *req.DefaultQuality != "source" &&
			*req.DefaultQuality != "lossless" &&
			*req.DefaultQuality != "lossy" {
			return apperr.NewBadRequest("invalid quality value")
		}
	}

	params := sqlc.UpdateUserPreferencesParams{
		UserID: int64(userID),
	}

	if req.DefaultQuality != nil {
		params.DefaultQuality = sql.NullString{String: string(*req.DefaultQuality), Valid: true}
	}

	if req.DiscColors != nil {
		colorsJSON, err := json.Marshal(*req.DiscColors)
		if err != nil {
			return apperr.NewBadRequest("invalid disc colors")
		}
		params.DiscColors = sql.NullString{String: string(colorsJSON), Valid: true}
	}

	if req.ColorSpread != nil {
		params.ColorSpread = sql.NullInt64{Int64: int64(*req.ColorSpread), Valid: true}
	}

	if req.GradientSpread != nil {
		params.GradientSpread = sql.NullInt64{Int64: int64(*req.GradientSpread), Valid: true}
	}

	if req.ColorShiftRotation != nil {
		params.ColorShiftRotation = sql.NullInt64{Int64: int64(*req.ColorShiftRotation), Valid: true}
	}

	prefs, err := h.svc.UpdateUserPreferences(r.Context(), params)
	if err != nil {
		return apperr.NewInternal("failed to update preferences", err)
	}

	return httputil.OKResult(w, toPreferencesResponse(prefs))
}
