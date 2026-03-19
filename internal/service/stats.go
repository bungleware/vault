package service

import (
	"context"

	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
)

// StorageStats holds pre-converted storage statistics (no interface{} fields).
type StorageStats struct {
	TotalSizeBytes    int64
	SourceSizeBytes   int64
	LosslessSizeBytes int64
	LossySizeBytes    int64
	FileCount         int64
	ProjectCount      int64
	TrackCount        int64
}

type StatsService interface {
	GetStorageStats(ctx context.Context, userID int64) (StorageStats, error)
	GetGlobalStorageStats(ctx context.Context) (StorageStats, error)
	GetInstanceSettings(ctx context.Context) (sqlc.InstanceSetting, error)
	UpdateInstanceName(ctx context.Context, name string) (sqlc.InstanceSetting, error)
}

type statsService struct {
	db *db.DB
}

func NewStatsService(database *db.DB) StatsService {
	return &statsService{db: database}
}

func toInt64(v interface{}) int64 {
	n, _ := v.(int64)
	return n
}

func (s *statsService) GetStorageStats(ctx context.Context, userID int64) (StorageStats, error) {
	row, err := s.db.GetStorageStatsByUser(ctx, userID)
	if err != nil {
		return StorageStats{}, err
	}
	return StorageStats{
		TotalSizeBytes:    toInt64(row.TotalSizeBytes),
		SourceSizeBytes:   toInt64(row.SourceSizeBytes),
		LosslessSizeBytes: toInt64(row.LosslessSizeBytes),
		LossySizeBytes:    toInt64(row.LossySizeBytes),
		FileCount:         row.FileCount,
		ProjectCount:      row.ProjectCount,
		TrackCount:        row.TrackCount,
	}, nil
}

func (s *statsService) GetGlobalStorageStats(ctx context.Context) (StorageStats, error) {
	row, err := s.db.GetGlobalStorageStats(ctx)
	if err != nil {
		return StorageStats{}, err
	}
	return StorageStats{
		TotalSizeBytes:    toInt64(row.TotalSizeBytes),
		SourceSizeBytes:   toInt64(row.SourceSizeBytes),
		LosslessSizeBytes: toInt64(row.LosslessSizeBytes),
		LossySizeBytes:    toInt64(row.LossySizeBytes),
		FileCount:         row.FileCount,
		ProjectCount:      row.ProjectCount,
		TrackCount:        row.TrackCount,
	}, nil
}

func (s *statsService) GetInstanceSettings(ctx context.Context) (sqlc.InstanceSetting, error) {
	return s.db.GetInstanceSettings(ctx)
}

func (s *statsService) UpdateInstanceName(ctx context.Context, name string) (sqlc.InstanceSetting, error) {
	return s.db.UpdateInstanceName(ctx, name)
}

