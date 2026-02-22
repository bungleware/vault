package handlers

import (
	"net/http"
	"net/url"
	"strconv"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/middleware"
)

type MediaHandler struct {
	config auth.Config
}

func NewMediaHandler(config auth.Config) *MediaHandler {
	return &MediaHandler{config: config}
}

func (h *MediaHandler) StreamURL(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	trackID := r.PathValue("id")
	if trackID == "" {
		return apperr.NewBadRequest("track id is required")
	}

	query := url.Values{}
	query.Set("user_id", strconv.Itoa(userID))

	quality := r.URL.Query().Get("quality")
	if quality != "" {
		query.Set("quality", quality)
	}
	versionID := r.URL.Query().Get("version_id")
	if versionID != "" {
		query.Set("version_id", versionID)
	}

	path := "/api/stream/" + trackID
	url, err := middleware.BuildSignedURL("", path, query, h.config.SignedURLSecret, h.config.SignedURLExpiration)
	if err != nil {
		return apperr.NewInternal("failed to build signed url", err)
	}

	return httputil.OKResult(w, map[string]string{"url": url})
}

func (h *MediaHandler) ProjectCoverURL(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	projectID := r.PathValue("id")
	if projectID == "" {
		return apperr.NewBadRequest("project id is required")
	}

	query := url.Values{}
	query.Set("user_id", strconv.Itoa(userID))

	size := r.URL.Query().Get("size")
	if size != "" {
		query.Set("size", size)
	}

	path := "/api/projects/" + projectID + "/cover"
	url, err := middleware.BuildSignedURL("", path, query, h.config.SignedURLSecret, h.config.SignedURLExpiration)
	if err != nil {
		return apperr.NewInternal("failed to build signed url", err)
	}

	return httputil.OKResult(w, map[string]string{"url": url})
}
