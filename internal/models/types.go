package models

import "time"

type Quality string

const (
	QualitySource   Quality = "source"
	QualityLossless Quality = "lossless"
	QualityLossy    Quality = "lossy"
)

func (q Quality) IsValid() bool {
	return q == QualitySource || q == QualityLossless || q == QualityLossy
}

func (q Quality) String() string {
	return string(q)
}

type TranscodingStatus string

const (
	TranscodingPending    TranscodingStatus = "pending"
	TranscodingProcessing TranscodingStatus = "processing"
	TranscodingCompleted  TranscodingStatus = "completed"
	TranscodingFailed     TranscodingStatus = "failed"
)

type User struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
