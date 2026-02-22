package handlers

import (
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/db"
	"bungleware/vault/internal/httputil"
)

type StatsHandler struct {
	db        *db.DB
	commitSHA string
}

func NewStatsHandler(database *db.DB, commitSHA string) *StatsHandler {
	return &StatsHandler{db: database, commitSHA: commitSHA}
}

func (h *StatsHandler) GetStorageStats(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("unauthorized")
	}

	ctx := r.Context()

	stats, err := h.db.GetStorageStatsByUser(ctx, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to query storage stats", err)
	}

	totalSize, _ := stats.TotalSizeBytes.(int64)
	sourceSize, _ := stats.SourceSizeBytes.(int64)
	losslessSize, _ := stats.LosslessSizeBytes.(int64)
	lossySize, _ := stats.LossySizeBytes.(int64)

	response := StorageStatsResponse{
		TotalSizeBytes:    totalSize,
		SourceSizeBytes:   sourceSize,
		LosslessSizeBytes: losslessSize,
		LossySizeBytes:    lossySize,
		FileCount:         stats.FileCount,
		ProjectCount:      stats.ProjectCount,
		TrackCount:        stats.TrackCount,
	}

	return httputil.OKResult(w, response)
}

func (h *StatsHandler) GetInstanceInfo(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	settings, err := h.db.GetInstanceSettings(ctx)
	if err != nil {
		return apperr.NewInternal("failed to get instance settings", err)
	}

	var createdAt *string
	if settings.CreatedAt.Valid {
		formatted := settings.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		createdAt = &formatted
	}

	response := InstanceInfoResponse{
		Version:   "dev",
		CommitSHA: h.commitSHA,
		Name:      settings.Name,
		CreatedAt: createdAt,
	}

	return httputil.OKResult(w, response)
}

func (h *StatsHandler) GetInstanceVersion(w http.ResponseWriter, r *http.Request) error {
	response := InstanceVersionResponse{
		Version:   "dev",
		CommitSHA: h.commitSHA,
	}

	return httputil.OKResult(w, response)
}

func (h *StatsHandler) GetGlobalStorageStats(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	stats, err := h.db.GetGlobalStorageStats(ctx)
	if err != nil {
		return apperr.NewInternal("failed to query storage stats", err)
	}

	totalSize, _ := stats.TotalSizeBytes.(int64)
	sourceSize, _ := stats.SourceSizeBytes.(int64)
	losslessSize, _ := stats.LosslessSizeBytes.(int64)
	lossySize, _ := stats.LossySizeBytes.(int64)

	response := StorageStatsResponse{
		TotalSizeBytes:    totalSize,
		SourceSizeBytes:   sourceSize,
		LosslessSizeBytes: losslessSize,
		LossySizeBytes:    lossySize,
		FileCount:         stats.FileCount,
		ProjectCount:      stats.ProjectCount,
		TrackCount:        stats.TrackCount,
	}

	return httputil.OKResult(w, response)
}

func (h *StatsHandler) UpdateInstanceName(w http.ResponseWriter, r *http.Request) error {
	req, err := httputil.DecodeJSON[UpdateInstanceNameRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	if req.Name == "" {
		return apperr.NewBadRequest("instance name is required")
	}

	ctx := r.Context()

	settings, err := h.db.UpdateInstanceName(ctx, req.Name)
	if err != nil {
		return apperr.NewInternal("failed to update instance name", err)
	}

	var createdAt *string
	if settings.CreatedAt.Valid {
		formatted := settings.CreatedAt.Time.Format("2006-01-02T15:04:05Z07:00")
		createdAt = &formatted
	}

	response := InstanceInfoResponse{
		Version:   "dev",
		CommitSHA: h.commitSHA,
		Name:      settings.Name,
		CreatedAt: createdAt,
	}

	return httputil.OKResult(w, response)
}
