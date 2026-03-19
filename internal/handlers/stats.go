package handlers

import (
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
)

type StatsHandler struct {
	svc       service.StatsService
	version   string
	commitSHA string
}

func NewStatsHandler(svc service.StatsService, version, commitSHA string) *StatsHandler {
	return &StatsHandler{svc: svc, version: version, commitSHA: commitSHA}
}

func (h *StatsHandler) GetStorageStats(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	stats, err := h.svc.GetStorageStats(r.Context(), int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query storage stats", err)
	}

	return httputil.OKResult(w, StorageStatsResponse{
		TotalSizeBytes:    stats.TotalSizeBytes,
		SourceSizeBytes:   stats.SourceSizeBytes,
		LosslessSizeBytes: stats.LosslessSizeBytes,
		LossySizeBytes:    stats.LossySizeBytes,
		FileCount:         stats.FileCount,
		ProjectCount:      stats.ProjectCount,
		TrackCount:        stats.TrackCount,
	})
}

func (h *StatsHandler) GetGlobalStorageStats(w http.ResponseWriter, r *http.Request) error {
	stats, err := h.svc.GetGlobalStorageStats(r.Context())
	if err != nil {
		return apperr.NewInternal("failed to query storage stats", err)
	}

	return httputil.OKResult(w, StorageStatsResponse{
		TotalSizeBytes:    stats.TotalSizeBytes,
		SourceSizeBytes:   stats.SourceSizeBytes,
		LosslessSizeBytes: stats.LosslessSizeBytes,
		LossySizeBytes:    stats.LossySizeBytes,
		FileCount:         stats.FileCount,
		ProjectCount:      stats.ProjectCount,
		TrackCount:        stats.TrackCount,
	})
}

func (h *StatsHandler) GetInstanceInfo(w http.ResponseWriter, r *http.Request) error {
	settings, err := h.svc.GetInstanceSettings(r.Context())
	if err != nil {
		return apperr.NewInternal("failed to get instance settings", err)
	}

	var createdAt *string
	if settings.CreatedAt.Valid {
		formatted := settings.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		createdAt = &formatted
	}

	return httputil.OKResult(w, InstanceInfoResponse{
		Version:   h.version,
		CommitSHA: h.commitSHA,
		Name:      settings.Name,
		CreatedAt: createdAt,
	})
}

func (h *StatsHandler) GetInstanceVersion(w http.ResponseWriter, r *http.Request) error {
	return httputil.OKResult(w, InstanceVersionResponse{Version: h.version})
}

func (h *StatsHandler) UpdateInstanceName(w http.ResponseWriter, r *http.Request) error {
	req, err := httputil.DecodeJSON[UpdateInstanceNameRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Name == "" {
		return apperr.NewBadRequest("instance name is required")
	}

	settings, err := h.svc.UpdateInstanceName(r.Context(), req.Name)
	if err != nil {
		return apperr.NewInternal("failed to update instance name", err)
	}

	var createdAt *string
	if settings.CreatedAt.Valid {
		formatted := settings.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		createdAt = &formatted
	}

	return httputil.OKResult(w, InstanceInfoResponse{
		Version:   h.version,
		CommitSHA: h.commitSHA,
		Name:      settings.Name,
		CreatedAt: createdAt,
	})
}
