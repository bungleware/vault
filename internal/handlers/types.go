package handlers

import (
	"time"

	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/models"
	"bungleware/vault/internal/service"
)

type RegisterRequest struct {
	Username     string  `json:"username"`
	Email        string  `json:"email"`
	Password     string  `json:"password"`
	InstanceName *string `json:"instance_name,omitempty"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type UpdateUsernameRequest struct {
	Username string `json:"username"`
}

type RegisterWithInviteRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	InviteToken string `json:"invite_token"`
}

type ResetPasswordRequest struct {
	Password   string `json:"password"`
	ResetToken string `json:"reset_token"`
}

type DeleteSelfRequest struct {
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string      `json:"token"`
	User  models.User `json:"user"`
}

type UpdatePreferencesRequest struct {
	DefaultQuality     *models.Quality `json:"default_quality,omitempty"`
	DiscColors         *[]string       `json:"disc_colors,omitempty"`
	ColorSpread        *int            `json:"color_spread,omitempty"`
	GradientSpread     *int            `json:"gradient_spread,omitempty"`
	ColorShiftRotation *int            `json:"color_shift_rotation,omitempty"`
}

type CreateProjectRequest struct {
	Name            string          `json:"name"`
	Description     *string         `json:"description,omitempty"`
	QualityOverride *models.Quality `json:"quality_override,omitempty"`
	AuthorOverride  *string         `json:"author_override,omitempty"`
	FolderID        *int64          `json:"folder_id,omitempty"`
}

type UpdateProjectRequest struct {
	Name            *string         `json:"name,omitempty"`
	Description     *string         `json:"description,omitempty"`
	QualityOverride *models.Quality `json:"quality_override,omitempty"`
	AuthorOverride  *string         `json:"author_override,omitempty"`
	Notes           *string         `json:"notes,omitempty"`
	NotesAuthorName *string         `json:"notes_author_name,omitempty"`
}

type ProjectResponse = shared.ProjectResponse

type CreateFolderRequest struct {
	Name     string `json:"name"`
	ParentID *int64 `json:"parent_id,omitempty"`
}

type UpdateFolderRequest struct {
	Name     *string `json:"name,omitempty"`
	ParentID *int64  `json:"parent_id,omitempty"`
}

type FolderResponse struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	ParentID    *int64 `json:"parent_id,omitempty"`
	FolderOrder int64  `json:"folder_order"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type FolderContentsResponse struct {
	Folder       FolderResponse               `json:"folder"`
	Folders      []FolderResponse             `json:"folders"`
	Projects     []shared.ProjectResponse     `json:"projects"`
	SharedTracks []shared.SharedTrackResponse `json:"shared_tracks"`
}

type MoveProjectRequest struct {
	FolderID *int64 `json:"folder_id"`
}

type MoveProjectsToFolderRequest struct {
	ProjectIDs []string                   `json:"project_ids"`        // For backwards compatibility
	Projects   []service.ProjectWithOrder `json:"projects,omitempty"` // New field with explicit order
	FolderID   int64                      `json:"folder_id"`
}

// Tracks types
type CreateTrackRequest struct {
	ProjectID int     `json:"project_id"`
	Title     string  `json:"title"`
	Artist    *string `json:"artist,omitempty"`
	Album     *string `json:"album,omitempty"`
}

type UpdateTrackRequest = shared.UpdateTrackRequest

type UpdateVersionRequest struct {
	VersionName *string `json:"version_name,omitempty"`
	Notes       *string `json:"notes,omitempty"`
}

type VersionWithMetadata struct {
	ID                     int64    `json:"id"`
	TrackID                int64    `json:"track_id"`
	VersionName            string   `json:"version_name"`
	Notes                  *string  `json:"notes,omitempty"`
	DurationSeconds        *float64 `json:"duration_seconds,omitempty"`
	VersionOrder           int64    `json:"version_order"`
	CreatedAt              string   `json:"created_at"`
	UpdatedAt              string   `json:"updated_at"`
	SourceFileSize         *int64   `json:"source_file_size,omitempty"`
	SourceFormat           *string  `json:"source_format,omitempty"`
	SourceBitrate          *int64   `json:"source_bitrate,omitempty"`
	SourceOriginalFilename *string  `json:"source_original_filename,omitempty"`
	LossyTranscodingStatus *string  `json:"lossy_transcoding_status,omitempty"`
	Waveform               *string  `json:"waveform,omitempty"`
}

type CreateShareTokenRequest struct {
	TrackID        int        `json:"track_id"`
	VersionID      *int       `json:"version_id,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	MaxAccessCount *int       `json:"max_access_count,omitempty"`
	AllowEditing   *bool      `json:"allow_editing,omitempty"`
	AllowDownloads *bool      `json:"allow_downloads,omitempty"`
	Password       *string    `json:"password,omitempty"`
	VisibilityType *string    `json:"visibility_type,omitempty"` // "invite_only" or "public"
}

type CreateProjectShareTokenRequest struct {
	ProjectID      int        `json:"project_id"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	MaxAccessCount *int       `json:"max_access_count,omitempty"`
	AllowEditing   *bool      `json:"allow_editing,omitempty"`
	AllowDownloads *bool      `json:"allow_downloads,omitempty"`
	Password       *string    `json:"password,omitempty"`
	VisibilityType *string    `json:"visibility_type,omitempty"` // "invite_only" or "public"
}

type UpdateVisibilityRequest struct {
	VisibilityStatus string  `json:"visibility_status"` // "private", "invite_only", or "public"
	AllowEditing     bool    `json:"allow_editing"`
	AllowDownloads   bool    `json:"allow_downloads"`
	Password         *string `json:"password,omitempty"`
}

type AcceptShareRequest struct {
	Password        string  `json:"password,omitempty"`
	UserInstanceURL *string `json:"user_instance_url,omitempty"`
}

type TrackResponse = shared.TrackResponse
type TrackListResponse = shared.TrackListResponse

type NoteResponse struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"user_id"`
	Content    string `json:"content"`
	AuthorName string `json:"author_name"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
	IsOwner    bool   `json:"is_owner"`
}

type UpsertNoteRequest struct {
	Content    string `json:"content"`
	AuthorName string `json:"author_name"`
}

type StorageStatsResponse struct {
	TotalSizeBytes    int64 `json:"total_size_bytes"`
	SourceSizeBytes   int64 `json:"source_size_bytes"`
	LosslessSizeBytes int64 `json:"lossless_size_bytes"`
	LossySizeBytes    int64 `json:"lossy_size_bytes"`
	FileCount         int64 `json:"file_count"`
	ProjectCount      int64 `json:"project_count"`
	TrackCount        int64 `json:"track_count"`
}

type InstanceInfoResponse struct {
	Version           string  `json:"version"`
	CommitSHA         string  `json:"commit_sha,omitempty"`
	Name              string  `json:"name"`
	UserCount         int64   `json:"user_count,omitempty"`
	CreatedAt         *string `json:"created_at,omitempty"`
	StorageQuotaBytes *int64  `json:"storage_quota_bytes,omitempty"`
	StorageUsedBytes  *int64  `json:"storage_used_bytes,omitempty"`
}

type InstanceVersionResponse struct {
	Version   string `json:"version"`
	CommitSHA string `json:"commit_sha,omitempty"`
}

type UpdateInstanceNameRequest struct {
	Name string `json:"name"`
}

type OrganizeItemRequest struct {
	FolderID    *int64 `json:"folder_id,omitempty"`
	CustomOrder *int64 `json:"custom_order,omitempty"`
}

type BulkOrganizeItem struct {
	Type        string `json:"type"` // "project" or "track"
	ID          int64  `json:"id"`
	IsShared    bool   `json:"is_shared"`
	FolderID    *int64 `json:"folder_id,omitempty"`
	CustomOrder int64  `json:"custom_order"`
}

type BulkOrganizeRequest struct {
	Items []BulkOrganizeItem `json:"items"`
}

type SharedProjectOrganization struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	ProjectID   int64  `json:"project_id"`
	FolderID    *int64 `json:"folder_id,omitempty"`
	CustomOrder int64  `json:"custom_order"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type SharedTrackOrganization struct {
	ID          int64  `json:"id"`
	UserID      int64  `json:"user_id"`
	TrackID     int64  `json:"track_id"`
	FolderID    *int64 `json:"folder_id,omitempty"`
	CustomOrder int64  `json:"custom_order"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type SharedTrackResponse = shared.SharedTrackResponse

type SharedTrackDetail struct {
	ID               int64       `json:"id"`
	UserID           int64       `json:"user_id"`
	ProjectID        int64       `json:"project_id"`
	PublicID         string      `json:"public_id"`
	Title            string      `json:"title"`
	Artist           *string     `json:"artist,omitempty"`
	Album            *string     `json:"album,omitempty"`
	Key              *string     `json:"key,omitempty"`
	BPM              *int64      `json:"bpm,omitempty"`
	Waveform         *string     `json:"waveform,omitempty"`
	ActiveVersionID  *int64      `json:"active_version_id,omitempty"`
	TrackOrder       int64       `json:"track_order"`
	VisibilityStatus string      `json:"visibility_status"`
	CoverURL         *string     `json:"cover_url,omitempty"`
	CreatedAt        interface{} `json:"created_at,omitempty"`
	UpdatedAt        interface{} `json:"updated_at,omitempty"`
}

type SharedProjectDetail struct {
	ID             int64       `json:"id"`
	PublicID       string      `json:"public_id"`
	Name           string      `json:"name"`
	UserID         int64       `json:"user_id"`
	AuthorOverride *string     `json:"author_override,omitempty"`
	CoverURL       *string     `json:"cover_url,omitempty"`
	CreatedAt      interface{} `json:"created_at,omitempty"`
	UpdatedAt      interface{} `json:"updated_at,omitempty"`
}

type ValidateShareResponse struct {
	Valid            bool                     `json:"valid"`
	PasswordRequired bool                     `json:"password_required,omitempty"`
	Error            string                   `json:"error,omitempty"`
	Track            *SharedTrackDetail       `json:"track,omitempty"`
	Project          *SharedProjectDetail     `json:"project,omitempty"`
	Tracks           []map[string]interface{} `json:"tracks,omitempty"`
	Version          interface{}              `json:"version,omitempty"`
	AllowEditing     bool                     `json:"allow_editing,omitempty"`
	AllowDownloads   bool                     `json:"allow_downloads,omitempty"`
}

type ShareTokenResponse struct {
	ID                 int64       `json:"id"`
	Token              string      `json:"token"`
	UserID             int64       `json:"user_id"`
	TrackID            int64       `json:"track_id"`
	TrackPublicID      string      `json:"track_public_id,omitempty"`
	VersionID          interface{} `json:"version_id,omitempty"`
	ExpiresAt          interface{} `json:"expires_at,omitempty"`
	MaxAccessCount     interface{} `json:"max_access_count,omitempty"`
	CurrentAccessCount interface{} `json:"current_access_count,omitempty"`
	AllowEditing       bool        `json:"allow_editing"`
	AllowDownloads     bool        `json:"allow_downloads"`
	HasPassword        bool        `json:"has_password"`
	VisibilityType     string      `json:"visibility_type"`
	CreatedAt          interface{} `json:"created_at,omitempty"`
	UpdatedAt          interface{} `json:"updated_at,omitempty"`
	ShareURL           string      `json:"share_url"`
}

type ProjectShareTokenResponse struct {
	ID                 int64       `json:"id"`
	Token              string      `json:"token"`
	UserID             int64       `json:"user_id"`
	ProjectID          int64       `json:"project_id"`
	ProjectPublicID    string      `json:"project_public_id,omitempty"`
	ExpiresAt          interface{} `json:"expires_at,omitempty"`
	MaxAccessCount     interface{} `json:"max_access_count,omitempty"`
	CurrentAccessCount interface{} `json:"current_access_count,omitempty"`
	AllowEditing       bool        `json:"allow_editing"`
	AllowDownloads     bool        `json:"allow_downloads"`
	HasPassword        bool        `json:"has_password"`
	VisibilityType     string      `json:"visibility_type"`
	CreatedAt          interface{} `json:"created_at,omitempty"`
	UpdatedAt          interface{} `json:"updated_at,omitempty"`
	ShareURL           string      `json:"share_url"`
}
