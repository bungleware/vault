package sharing

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/storage"
)

type SharingHandler struct {
	svc     service.SharingService
	storage storage.Storage
	baseURL string
	dataDir string
}

func NewSharingHandler(svc service.SharingService, storageAdapter storage.Storage, baseURL string, dataDir string) *SharingHandler {
	return &SharingHandler{svc: svc, storage: storageAdapter, baseURL: baseURL, dataDir: dataDir}
}

func (h *SharingHandler) buildShareURL(r *http.Request, token string) string {
	if h.baseURL != "" {
		return fmt.Sprintf("%s/share/%s", strings.TrimRight(h.baseURL, "/"), token)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/share/%s", scheme, r.Host, token)
}

func (h *SharingHandler) buildShareCoverURL(r *http.Request, token string) string {
	if h.baseURL != "" {
		return fmt.Sprintf("%s/api/share/%s/cover", strings.TrimRight(h.baseURL, "/"), token)
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/api/share/%s/cover", scheme, r.Host, token)
}

// validateFilePath ensures the path is within the data directory.
func (h *SharingHandler) validateFilePath(filePath string) error {
	cleanPath := filepath.Clean(filePath)
	cleanDataDir := filepath.Clean(h.dataDir)
	if !strings.HasPrefix(cleanPath, cleanDataDir+string(filepath.Separator)) {
		return apperr.NewForbidden("invalid file path")
	}
	return nil
}

// mapSharingErr maps service sentinel errors to HTTP errors for streaming/download handlers.
// Note: ErrPasswordRequired/ErrInvalidPassword/ErrShareExpired/ErrAccessLimitReached map to Forbidden
// in streaming/download context (not to a {valid:false} body — those are for the validate endpoint only).
func mapSharingErr(err error) error {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return apperr.NewNotFound(err.Error())
	case errors.Is(err, service.ErrForbidden):
		return apperr.NewForbidden(err.Error())
	case errors.Is(err, service.ErrBadRequest):
		return apperr.NewBadRequest(err.Error())
	case errors.Is(err, service.ErrShareExpired):
		return apperr.NewForbidden("share token expired")
	case errors.Is(err, service.ErrAccessLimitReached):
		return apperr.NewForbidden("max access count reached")
	case errors.Is(err, service.ErrDownloadNotAllowed):
		return apperr.NewForbidden("downloads not allowed for this share")
	case errors.Is(err, service.ErrPasswordRequired):
		return apperr.NewUnauthorized("password required")
	case errors.Is(err, service.ErrInvalidPassword):
		return apperr.NewUnauthorized("invalid password")
	default:
		return apperr.NewInternal("internal error", err)
	}
}
