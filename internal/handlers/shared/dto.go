package shared

import (
	"bungleware/vault/internal/models"
)

// ProjectResponse is the JSON response structure for projects
type ProjectResponse struct {
	ID               int64           `json:"id"`
	UserID           int64           `json:"user_id"`
	PublicID         string          `json:"public_id"`
	Name             string          `json:"name"`
	Description      *string         `json:"description,omitempty"`
	QualityOverride  *models.Quality `json:"quality_override,omitempty"`
	AuthorOverride   *string         `json:"author_override,omitempty"`
	Notes            *string         `json:"notes,omitempty"`
	NotesAuthorName  *string         `json:"notes_author_name,omitempty"`
	NotesUpdatedAt   *string         `json:"notes_updated_at,omitempty"`
	CoverURL         *string         `json:"cover_url,omitempty"`
	FolderID         *int64          `json:"folder_id,omitempty"`
	VisibilityStatus string          `json:"visibility_status"`
	AllowEditing     bool            `json:"allow_editing"`
	AllowDownloads   bool            `json:"allow_downloads"`
	SharedByUsername *string         `json:"shared_by_username,omitempty"`
	OwnerUsername    string          `json:"owner_username"`
	IsShared         bool            `json:"is_shared"`
	CustomOrder      *int64          `json:"custom_order,omitempty"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
}

// SharedTrackResponse is the response structure for shared tracks
type SharedTrackResponse struct {
	ID               int64   `json:"id"`
	PublicID         string  `json:"public_id"`
	Title            string  `json:"title"`
	Artist           string  `json:"artist"`
	CoverURL         string  `json:"cover_url"`
	ProjectName      string  `json:"project_name"`
	Waveform         string  `json:"waveform"`
	DurationSeconds  float64 `json:"duration_seconds"`
	SharedByUsername string  `json:"shared_by_username"`
	CanDownload      bool    `json:"can_download"`
	FolderID         *int64  `json:"folder_id,omitempty"`
	CustomOrder      *int64  `json:"custom_order,omitempty"`
}

// TrackResponse is a JSON-friendly representation of a track
type TrackResponse struct {
	ID                           int64    `json:"id"`
	UserID                       int64    `json:"user_id"`
	ProjectID                    int64    `json:"project_id"`
	PublicID                     string   `json:"public_id"`
	Title                        string   `json:"title"`
	Artist                       *string  `json:"artist,omitempty"`
	Album                        *string  `json:"album,omitempty"`
	Key                          *string  `json:"key,omitempty"`
	Bpm                          *int64   `json:"bpm,omitempty"`
	Notes                        *string  `json:"notes,omitempty"`
	NotesAuthorName              *string  `json:"notes_author_name,omitempty"`
	NotesUpdatedAt               *string  `json:"notes_updated_at,omitempty"`
	ActiveVersionID              *int64   `json:"active_version_id,omitempty"`
	ActiveVersionDurationSeconds *float64 `json:"active_version_duration_seconds,omitempty"`
	TrackOrder                   int64    `json:"track_order"`
	VisibilityStatus             string   `json:"visibility_status"`
	CreatedAt                    string   `json:"created_at"`
	UpdatedAt                    string   `json:"updated_at"`
	Waveform                     *string  `json:"waveform,omitempty"`
	LossyTranscodingStatus       *string  `json:"lossy_transcoding_status,omitempty"`
}

// TrackListResponse is for list endpoints that include additional fields
type TrackListResponse struct {
	TrackResponse
	ActiveVersionName *string `json:"active_version_name,omitempty"`
	ProjectName       *string `json:"project_name,omitempty"`
	IsShared          bool    `json:"is_shared"`
	CanEdit           *bool   `json:"can_edit,omitempty"`
	CanDownload       *bool   `json:"can_download,omitempty"`
}

// UpdateTrackRequest for updating track metadata
type UpdateTrackRequest struct {
	Title           *string `json:"title,omitempty"`
	Artist          *string `json:"artist,omitempty"`
	Album           *string `json:"album,omitempty"`
	ProjectID       *int    `json:"project_id,omitempty"`
	Key             *string `json:"key,omitempty"`
	BPM             *int    `json:"bpm,omitempty"`
	Notes           *string `json:"notes,omitempty"`
	NotesAuthorName *string `json:"notes_author_name,omitempty"`
}
