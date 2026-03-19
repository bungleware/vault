package service

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"

	"bungleware/vault/internal/auth"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"

	"golang.org/x/crypto/bcrypt"
)

// -- Input types ----------------------------------------------------------

type CreateTrackShareTokenInput struct {
	VersionID      *int64
	Password       *string
	ExpiresAt      *time.Time
	MaxAccessCount *int64
	AllowEditing   *bool
	AllowDownloads *bool
	VisibilityType *string
}

type CreateProjectShareTokenInput struct {
	Password       *string
	ExpiresAt      *time.Time
	MaxAccessCount *int64
	AllowEditing   *bool
	AllowDownloads *bool
	VisibilityType *string
}

type UpdateShareTokenInput struct {
	AllowEditing   *bool
	AllowDownloads *bool
	Password       *string
}

type ShareWithUsersInput struct {
	UserIDs     []int64
	CanEdit     bool
	CanDownload bool
}

type UpdateVisibilityInput struct {
	VisibilityStatus string
	AllowEditing     bool
	AllowDownloads   bool
	Password         *string
}

// -- Result types ---------------------------------------------------------

type UpdatedTrackShareToken struct {
	Token         sqlc.ShareToken
	TrackPublicID string
}

type UpdatedProjectShareToken struct {
	Token           sqlc.ProjectShareToken
	ProjectPublicID string
}

type ValidateTrackShareResult struct {
	Track          sqlc.GetTrackWithDetailsRow
	Project        sqlc.Project
	User           sqlc.User
	Version        *sqlc.TrackVersion
	AllowEditing   bool
	AllowDownloads bool
	Token          sqlc.ShareToken
}

type ValidateProjectShareResult struct {
	Project        sqlc.Project
	Tracks         []sqlc.ListTracksWithDetailsByProjectIDRow
	User           sqlc.User
	AllowEditing   bool
	AllowDownloads bool
	Token          sqlc.ProjectShareToken
}

type StreamTrackResult struct {
	FilePath string
	TokenID  int64
}

type StreamProjectTrackResult struct {
	FilePath string
	TokenID  int64
}

type ProjectCoverResult struct {
	ProjectPublicID string
	CoverArtPath    string
	CoverArtMime    sql.NullString
	TokenID         int64
	IsProjectToken  bool
}

type DownloadTrackResult struct {
	Title    string
	FilePath string
	Format   string
	TokenID  int64
}

type DownloadProjectResult struct {
	ProjectName string
	TokenID     int64
	Tracks      []DownloadProjectTrack
}

type DownloadProjectTrack struct {
	Title    string
	FilePath string
	Format   string
}

type ProjectWithShareInfo struct {
	Project        sqlc.Project
	OwnerUsername  string
	AllowEditing   bool
	AllowDownloads bool
}

type SharedTrackInfo struct {
	ID               int64
	PublicID         string
	Title            string
	Artist           string
	CoverURL         string
	ProjectName      string
	Waveform         string
	DurationSeconds  float64
	SharedByUsername string
	CanDownload      bool
	FolderID         *int64
	CustomOrder      *int64
}

// -- Interface ------------------------------------------------------------

type SharingService interface {
	// Track share tokens
	CreateTrackShareToken(ctx context.Context, userID int64, trackPublicID string, input CreateTrackShareTokenInput) (sqlc.ShareToken, error)
	ListTrackShareTokens(ctx context.Context, userID int64) ([]sqlc.ListShareTokensWithTrackInfoRow, error)
	UpdateTrackShareToken(ctx context.Context, userID, tokenID int64, input UpdateShareTokenInput) (*UpdatedTrackShareToken, error)
	DeleteTrackShareToken(ctx context.Context, userID, tokenID int64) error

	// Project share tokens
	CreateProjectShareToken(ctx context.Context, userID int64, projectPublicID string, input CreateProjectShareTokenInput) (sqlc.ProjectShareToken, error)
	ListProjectShareTokens(ctx context.Context, userID int64) ([]sqlc.ListProjectShareTokensWithProjectInfoRow, error)
	UpdateProjectShareToken(ctx context.Context, userID, tokenID int64, input UpdateShareTokenInput) (*UpdatedProjectShareToken, error)
	DeleteProjectShareToken(ctx context.Context, userID, tokenID int64) error

	// Token lookup (for handler routing: track vs project)
	GetShareToken(ctx context.Context, token string) (sqlc.ShareToken, error)
	GetProjectShareToken(ctx context.Context, token string) (sqlc.ProjectShareToken, error)

	// Token validation — returns sentinel errors for invalid states
	ValidateTrackShare(ctx context.Context, token, password string) (*ValidateTrackShareResult, error)
	ValidateProjectShare(ctx context.Context, token, password string) (*ValidateProjectShareResult, error)
	UpdateSharedTrackFromToken(ctx context.Context, token string, trackID int64, title, password string) (sqlc.Track, error)

	// Streaming
	GetTrackForStream(ctx context.Context, token string) (*StreamTrackResult, error)
	GetProjectTrackForStream(ctx context.Context, token, trackPublicID string) (*StreamProjectTrackResult, error)
	GetProjectCoverForShare(ctx context.Context, token string) (*ProjectCoverResult, error)
	IncrementTrackAccessCount(ctx context.Context, tokenID int64)
	IncrementProjectAccessCount(ctx context.Context, tokenID int64)

	// Downloads
	GetTrackForDownload(ctx context.Context, token string) (*DownloadTrackResult, error)
	GetProjectForDownload(ctx context.Context, token string) (*DownloadProjectResult, error)
	GetProjectTrackForDownload(ctx context.Context, token, trackPublicID string) (*DownloadTrackResult, error)

	// Share access
	AcceptShare(ctx context.Context, userID int64, token, password string, instanceURL *string) (sqlc.ShareAccess, error)
	ListSharedWithMe(ctx context.Context, userID int64) ([]sqlc.ShareAccess, error)
	LeaveShare(ctx context.Context, userID, shareAccessID int64) error
	LeaveSharedProject(ctx context.Context, userID int64, projectPublicID string) error
	LeaveSharedTrack(ctx context.Context, userID int64, trackIDStr string) error

	// User-to-user sharing
	ShareProjectWithUsers(ctx context.Context, userID int64, projectPublicID string, input ShareWithUsersInput) (sqlc.Project, int, error)
	ShareTrackWithUsers(ctx context.Context, userID int64, trackPublicID string, input ShareWithUsersInput) (sqlc.Track, int, error)
	ListProjectShareUsers(ctx context.Context, userID int64, projectPublicID string) ([]sqlc.UserProjectShare, error)
	ListTrackShareUsers(ctx context.Context, userID int64, trackPublicID string) ([]sqlc.UserTrackShare, error)
	UpdateProjectSharePermissions(ctx context.Context, userID, shareID int64, canEdit, canDownload bool) (sqlc.UserProjectShare, error)
	UpdateTrackSharePermissions(ctx context.Context, userID, shareID int64, canEdit, canDownload bool) (sqlc.UserTrackShare, error)
	RevokeProjectShare(ctx context.Context, userID, shareID int64) error
	RevokeTrackShare(ctx context.Context, userID, shareID int64) error
	ListProjectsSharedWithMe(ctx context.Context, userID int64) ([]ProjectWithShareInfo, error)
	ListTracksSharedWithMe(ctx context.Context, userID int64) ([]SharedTrackInfo, error)

	// Visibility
	UpdateTrackVisibility(ctx context.Context, userID int64, trackPublicID string, input UpdateVisibilityInput) (sqlc.Track, error)
	UpdateProjectVisibility(ctx context.Context, userID int64, projectPublicID string, input UpdateVisibilityInput) (sqlc.Project, error)
}

// -- Implementation -------------------------------------------------------

type sharingService struct {
	db *db.DB
}

func NewSharingService(database *db.DB) SharingService {
	return &sharingService{db: database}
}

// validateShareConstraints checks password, expiry, and access count.
// Returns a sentinel error (ErrPasswordRequired, ErrInvalidPassword, ErrShareExpired,
// ErrAccessLimitReached) or nil on success.
func validateShareConstraints(passwordHash sql.NullString, expiresAt sql.NullTime, maxCount, currentCount sql.NullInt64, password string) error {
	if passwordHash.Valid {
		if password == "" {
			return ErrPasswordRequired
		}
		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash.String), []byte(password)); err != nil {
			return ErrInvalidPassword
		}
	}
	if expiresAt.Valid && expiresAt.Time.Before(time.Now()) {
		return ErrShareExpired
	}
	if maxCount.Valid && currentCount.Int64 >= maxCount.Int64 {
		return ErrAccessLimitReached
	}
	return nil
}

func hashSharePassword(password *string) (sql.NullString, error) {
	if password == nil || *password == "" {
		return sql.NullString{Valid: false}, nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(*password), bcrypt.DefaultCost)
	if err != nil {
		return sql.NullString{}, fmt.Errorf("failed to hash password: %w", err)
	}
	return sql.NullString{String: string(hash), Valid: true}, nil
}

func (s *sharingService) canManageTrackShares(ctx context.Context, track sqlc.Track, userID int64) (bool, error) {
	project, err := s.db.GetProjectByID(ctx, track.ProjectID)
	if err == nil && project.UserID == userID {
		return true, nil
	}
	share, err := s.db.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
		ProjectID: track.ProjectID,
		SharedTo:  userID,
	})
	if err == nil && share.CanEdit {
		return true, nil
	}
	return false, nil
}

func (s *sharingService) getTrackFile(ctx context.Context, versionID int64) (sqlc.TrackFile, error) {
	f, err := s.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{VersionID: versionID, Quality: "lossy"})
	if errors.Is(err, sql.ErrNoRows) {
		return s.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{VersionID: versionID, Quality: "source"})
	}
	return f, err
}

// -- Track share tokens ---------------------------------------------------

func (s *sharingService) CreateTrackShareToken(ctx context.Context, userID int64, trackPublicID string, input CreateTrackShareTokenInput) (sqlc.ShareToken, error) {
	track, err := s.db.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.ShareToken{}, ErrNotFound
		}
		return sqlc.ShareToken{}, err
	}

	canManage, err := s.canManageTrackShares(ctx, track, userID)
	if err != nil {
		return sqlc.ShareToken{}, err
	}
	if !canManage {
		return sqlc.ShareToken{}, ErrForbidden
	}

	if input.VersionID != nil {
		version, err := s.db.GetTrackVersion(ctx, *input.VersionID)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return sqlc.ShareToken{}, fmt.Errorf("version not found: %w", ErrNotFound)
			}
			return sqlc.ShareToken{}, err
		}
		if version.TrackID != track.ID {
			return sqlc.ShareToken{}, fmt.Errorf("version does not belong to track: %w", ErrBadRequest)
		}
	}

	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return sqlc.ShareToken{}, err
	}

	passwordHash, err := hashSharePassword(input.Password)
	if err != nil {
		return sqlc.ShareToken{}, err
	}

	var versionID sql.NullInt64
	if input.VersionID != nil {
		versionID = sql.NullInt64{Int64: *input.VersionID, Valid: true}
	}
	var expiresAt sql.NullTime
	if input.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *input.ExpiresAt, Valid: true}
	}
	var maxAccessCount sql.NullInt64
	if input.MaxAccessCount != nil {
		maxAccessCount = sql.NullInt64{Int64: *input.MaxAccessCount, Valid: true}
	}
	visibilityType := "invite_only"
	if input.VisibilityType != nil {
		visibilityType = *input.VisibilityType
	}

	return s.db.CreateShareToken(ctx, sqlc.CreateShareTokenParams{
		Token:          token,
		UserID:         userID,
		TrackID:        track.ID,
		VersionID:      versionID,
		ExpiresAt:      expiresAt,
		MaxAccessCount: maxAccessCount,
		AllowEditing:   input.AllowEditing != nil && *input.AllowEditing,
		AllowDownloads: input.AllowDownloads == nil || *input.AllowDownloads,
		PasswordHash:   passwordHash,
		VisibilityType: visibilityType,
	})
}

func (s *sharingService) ListTrackShareTokens(ctx context.Context, userID int64) ([]sqlc.ListShareTokensWithTrackInfoRow, error) {
	return s.db.ListShareTokensWithTrackInfo(ctx, userID)
}

func (s *sharingService) UpdateTrackShareToken(ctx context.Context, userID, tokenID int64, input UpdateShareTokenInput) (*UpdatedTrackShareToken, error) {
	existing, err := s.db.GetShareTokenByID(ctx, sqlc.GetShareTokenByIDParams{ID: tokenID, UserID: userID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	passwordHash, err := hashSharePassword(input.Password)
	if err != nil {
		return nil, err
	}

	updated, err := s.db.UpdateShareToken(ctx, sqlc.UpdateShareTokenParams{
		ExpiresAt:      existing.ExpiresAt,
		MaxAccessCount: existing.MaxAccessCount,
		AllowEditing:   input.AllowEditing != nil && *input.AllowEditing,
		AllowDownloads: input.AllowDownloads != nil && *input.AllowDownloads,
		PasswordHash:   passwordHash,
		VisibilityType: existing.VisibilityType,
		ID:             tokenID,
		UserID:         userID,
	})
	if err != nil {
		return nil, err
	}

	track, err := s.db.GetTrackByID(ctx, updated.TrackID)
	if err != nil {
		return nil, err
	}

	return &UpdatedTrackShareToken{Token: updated, TrackPublicID: track.PublicID}, nil
}

func (s *sharingService) DeleteTrackShareToken(ctx context.Context, userID, tokenID int64) error {
	return s.db.DeleteShareToken(ctx, sqlc.DeleteShareTokenParams{ID: tokenID, UserID: userID})
}

// -- Project share tokens -------------------------------------------------

func (s *sharingService) CreateProjectShareToken(ctx context.Context, userID int64, projectPublicID string, input CreateProjectShareTokenInput) (sqlc.ProjectShareToken, error) {
	project, err := s.db.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{PublicID: projectPublicID, UserID: userID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.ProjectShareToken{}, ErrNotFound
		}
		return sqlc.ProjectShareToken{}, err
	}
	if project.UserID != userID {
		return sqlc.ProjectShareToken{}, ErrForbidden
	}

	token, err := auth.GenerateSecureToken(32)
	if err != nil {
		return sqlc.ProjectShareToken{}, err
	}

	passwordHash, err := hashSharePassword(input.Password)
	if err != nil {
		return sqlc.ProjectShareToken{}, err
	}

	var expiresAt sql.NullTime
	if input.ExpiresAt != nil {
		expiresAt = sql.NullTime{Time: *input.ExpiresAt, Valid: true}
	}
	var maxAccessCount sql.NullInt64
	if input.MaxAccessCount != nil {
		maxAccessCount = sql.NullInt64{Int64: *input.MaxAccessCount, Valid: true}
	}
	visibilityType := "invite_only"
	if input.VisibilityType != nil {
		visibilityType = *input.VisibilityType
	}

	return s.db.CreateProjectShareToken(ctx, sqlc.CreateProjectShareTokenParams{
		Token:          token,
		UserID:         userID,
		ProjectID:      project.ID,
		ExpiresAt:      expiresAt,
		MaxAccessCount: maxAccessCount,
		AllowEditing:   input.AllowEditing != nil && *input.AllowEditing,
		AllowDownloads: input.AllowDownloads == nil || *input.AllowDownloads,
		PasswordHash:   passwordHash,
		VisibilityType: visibilityType,
	})
}

func (s *sharingService) ListProjectShareTokens(ctx context.Context, userID int64) ([]sqlc.ListProjectShareTokensWithProjectInfoRow, error) {
	return s.db.ListProjectShareTokensWithProjectInfo(ctx, userID)
}

func (s *sharingService) UpdateProjectShareToken(ctx context.Context, userID, tokenID int64, input UpdateShareTokenInput) (*UpdatedProjectShareToken, error) {
	existing, err := s.db.GetProjectShareTokenByID(ctx, sqlc.GetProjectShareTokenByIDParams{ID: tokenID, UserID: userID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	passwordHash, err := hashSharePassword(input.Password)
	if err != nil {
		return nil, err
	}

	updated, err := s.db.UpdateProjectShareToken(ctx, sqlc.UpdateProjectShareTokenParams{
		ExpiresAt:      existing.ExpiresAt,
		MaxAccessCount: existing.MaxAccessCount,
		AllowEditing:   input.AllowEditing != nil && *input.AllowEditing,
		AllowDownloads: input.AllowDownloads != nil && *input.AllowDownloads,
		PasswordHash:   passwordHash,
		VisibilityType: existing.VisibilityType,
		ID:             tokenID,
		UserID:         userID,
	})
	if err != nil {
		return nil, err
	}

	project, err := s.db.GetProject(ctx, sqlc.GetProjectParams{ID: updated.ProjectID, UserID: userID})
	if err != nil {
		return nil, err
	}

	return &UpdatedProjectShareToken{Token: updated, ProjectPublicID: project.PublicID}, nil
}

func (s *sharingService) DeleteProjectShareToken(ctx context.Context, userID, tokenID int64) error {
	return s.db.DeleteProjectShareToken(ctx, sqlc.DeleteProjectShareTokenParams{ID: tokenID, UserID: userID})
}

// -- Token lookup ---------------------------------------------------------

func (s *sharingService) GetShareToken(ctx context.Context, token string) (sqlc.ShareToken, error) {
	return s.db.GetShareToken(ctx, token)
}

func (s *sharingService) GetProjectShareToken(ctx context.Context, token string) (sqlc.ProjectShareToken, error) {
	return s.db.GetProjectShareToken(ctx, token)
}

// -- Token validation -----------------------------------------------------

func (s *sharingService) ValidateTrackShare(ctx context.Context, token, password string) (*ValidateTrackShareResult, error) {
	shareToken, err := s.db.GetShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if err := validateShareConstraints(shareToken.PasswordHash, shareToken.ExpiresAt, shareToken.MaxAccessCount, shareToken.CurrentAccessCount, password); err != nil {
		return nil, err
	}

	trackDetails, err := s.db.GetTrackWithDetails(ctx, sqlc.GetTrackWithDetailsParams{
		ID:     shareToken.TrackID,
		UserID: shareToken.UserID,
	})
	if err != nil {
		return nil, err
	}

	project, err := s.db.GetProjectByID(ctx, trackDetails.ProjectID)
	if err != nil {
		return nil, err
	}

	user, err := s.db.GetUserByID(ctx, shareToken.UserID)
	if err != nil {
		return nil, err
	}

	var version *sqlc.TrackVersion
	versionID := shareToken.VersionID
	if !versionID.Valid && trackDetails.ActiveVersionID.Valid {
		versionID = trackDetails.ActiveVersionID
	}
	if versionID.Valid {
		v, err := s.db.GetTrackVersion(ctx, versionID.Int64)
		if err == nil {
			version = &v
		}
	}

	s.db.IncrementAccessCount(ctx, shareToken.ID)

	return &ValidateTrackShareResult{
		Track:          trackDetails,
		Project:        project,
		User:           user,
		Version:        version,
		AllowEditing:   shareToken.AllowEditing,
		AllowDownloads: shareToken.AllowDownloads,
		Token:          shareToken,
	}, nil
}

func (s *sharingService) ValidateProjectShare(ctx context.Context, token, password string) (*ValidateProjectShareResult, error) {
	shareToken, err := s.db.GetProjectShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	if err := validateShareConstraints(shareToken.PasswordHash, shareToken.ExpiresAt, shareToken.MaxAccessCount, shareToken.CurrentAccessCount, password); err != nil {
		return nil, err
	}

	project, err := s.db.GetProjectByID(ctx, shareToken.ProjectID)
	if err != nil {
		return nil, err
	}

	tracks, err := s.db.ListTracksWithDetailsByProjectID(ctx, shareToken.ProjectID)
	if err != nil {
		tracks = []sqlc.ListTracksWithDetailsByProjectIDRow{}
	}

	user, err := s.db.GetUserByID(ctx, project.UserID)
	if err != nil {
		return nil, err
	}

	s.db.IncrementProjectAccessCount(ctx, shareToken.ID)

	return &ValidateProjectShareResult{
		Project:        project,
		Tracks:         tracks,
		User:           user,
		AllowEditing:   shareToken.AllowEditing,
		AllowDownloads: shareToken.AllowDownloads,
		Token:          shareToken,
	}, nil
}

func (s *sharingService) UpdateSharedTrackFromToken(ctx context.Context, token string, trackID int64, title, password string) (sqlc.Track, error) {
	shareToken, err := s.db.GetShareToken(ctx, token)
	if err != nil {
		return sqlc.Track{}, ErrForbidden
	}
	if !shareToken.AllowEditing {
		return sqlc.Track{}, ErrForbidden
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return sqlc.Track{}, ErrForbidden
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return sqlc.Track{}, ErrForbidden
	}
	if shareToken.PasswordHash.Valid {
		if password == "" {
			return sqlc.Track{}, ErrPasswordRequired
		}
		if err := bcrypt.CompareHashAndPassword([]byte(shareToken.PasswordHash.String), []byte(password)); err != nil {
			return sqlc.Track{}, ErrInvalidPassword
		}
	}
	if trackID != shareToken.TrackID {
		return sqlc.Track{}, ErrForbidden
	}
	track, err := s.db.GetTrackByID(ctx, trackID)
	if err != nil {
		return sqlc.Track{}, ErrNotFound
	}
	return s.db.UpdateTrack(ctx, sqlc.UpdateTrackParams{ID: track.ID, Title: title})
}

// -- Streaming ------------------------------------------------------------

func (s *sharingService) GetTrackForStream(ctx context.Context, token string) (*StreamTrackResult, error) {
	shareToken, err := s.db.GetShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrShareExpired
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return nil, ErrAccessLimitReached
	}
	if !shareToken.AllowDownloads {
		return nil, ErrDownloadNotAllowed
	}

	track, err := s.db.GetTrackByID(ctx, shareToken.TrackID)
	if err != nil {
		return nil, ErrNotFound
	}
	if !track.ActiveVersionID.Valid {
		return nil, fmt.Errorf("track has no active version: %w", ErrBadRequest)
	}
	version, err := s.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return nil, ErrNotFound
	}
	trackFile, err := s.getTrackFile(ctx, version.ID)
	if err != nil {
		return nil, ErrNotFound
	}
	return &StreamTrackResult{FilePath: trackFile.FilePath, TokenID: shareToken.ID}, nil
}

func (s *sharingService) GetProjectTrackForStream(ctx context.Context, token, trackPublicID string) (*StreamProjectTrackResult, error) {
	shareToken, err := s.db.GetProjectShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrShareExpired
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return nil, ErrAccessLimitReached
	}
	if !shareToken.AllowDownloads {
		return nil, ErrDownloadNotAllowed
	}

	track, err := s.db.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err != nil {
		return nil, ErrNotFound
	}
	if track.ProjectID != shareToken.ProjectID {
		return nil, ErrForbidden
	}
	if !track.ActiveVersionID.Valid {
		return nil, fmt.Errorf("track has no active version: %w", ErrBadRequest)
	}
	version, err := s.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return nil, ErrNotFound
	}
	trackFile, err := s.getTrackFile(ctx, version.ID)
	if err != nil {
		return nil, ErrNotFound
	}
	return &StreamProjectTrackResult{FilePath: trackFile.FilePath, TokenID: shareToken.ID}, nil
}

func (s *sharingService) GetProjectCoverForShare(ctx context.Context, token string) (*ProjectCoverResult, error) {
	// Try project share token first
	projectToken, err := s.db.GetProjectShareToken(ctx, token)
	if err == nil {
		if projectToken.ExpiresAt.Valid && projectToken.ExpiresAt.Time.Before(time.Now()) {
			return nil, ErrShareExpired
		}
		if projectToken.MaxAccessCount.Valid && projectToken.CurrentAccessCount.Int64 >= projectToken.MaxAccessCount.Int64 {
			return nil, ErrAccessLimitReached
		}
		if !projectToken.AllowDownloads {
			return nil, ErrDownloadNotAllowed
		}
		project, err := s.db.GetProjectByID(ctx, projectToken.ProjectID)
		if err != nil {
			return nil, err
		}
		return &ProjectCoverResult{
			ProjectPublicID: project.PublicID,
			CoverArtPath:    project.CoverArtPath.String,
			CoverArtMime:    project.CoverArtMime,
			TokenID:         projectToken.ID,
			IsProjectToken:  true,
		}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// Fall back to track share token
	trackToken, err := s.db.GetShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if trackToken.ExpiresAt.Valid && trackToken.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrShareExpired
	}
	if trackToken.MaxAccessCount.Valid && trackToken.CurrentAccessCount.Int64 >= trackToken.MaxAccessCount.Int64 {
		return nil, ErrAccessLimitReached
	}
	if !trackToken.AllowDownloads {
		return nil, ErrDownloadNotAllowed
	}
	track, err := s.db.GetTrackByID(ctx, trackToken.TrackID)
	if err != nil {
		return nil, ErrNotFound
	}
	project, err := s.db.GetProjectByID(ctx, track.ProjectID)
	if err != nil {
		return nil, err
	}
	return &ProjectCoverResult{
		ProjectPublicID: project.PublicID,
		CoverArtPath:    project.CoverArtPath.String,
		CoverArtMime:    project.CoverArtMime,
		TokenID:         trackToken.ID,
		IsProjectToken:  false,
	}, nil
}

func (s *sharingService) IncrementTrackAccessCount(ctx context.Context, tokenID int64) {
	s.db.IncrementAccessCount(ctx, tokenID)
}

func (s *sharingService) IncrementProjectAccessCount(ctx context.Context, tokenID int64) {
	s.db.IncrementProjectAccessCount(ctx, tokenID)
}

// -- Downloads ------------------------------------------------------------

func (s *sharingService) GetTrackForDownload(ctx context.Context, token string) (*DownloadTrackResult, error) {
	shareToken, err := s.db.GetShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !shareToken.AllowDownloads {
		return nil, ErrDownloadNotAllowed
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrShareExpired
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return nil, ErrAccessLimitReached
	}

	track, err := s.db.GetTrackByID(ctx, shareToken.TrackID)
	if err != nil {
		return nil, ErrNotFound
	}
	if !track.ActiveVersionID.Valid {
		return nil, fmt.Errorf("track has no active version: %w", ErrBadRequest)
	}
	version, err := s.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return nil, ErrNotFound
	}
	trackFile, err := s.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{VersionID: version.ID, Quality: "source"})
	if err != nil {
		return nil, ErrNotFound
	}
	return &DownloadTrackResult{
		Title:    track.Title,
		FilePath: trackFile.FilePath,
		Format:   trackFile.Format,
		TokenID:  shareToken.ID,
	}, nil
}

func (s *sharingService) GetProjectForDownload(ctx context.Context, token string) (*DownloadProjectResult, error) {
	shareToken, err := s.db.GetProjectShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !shareToken.AllowDownloads {
		return nil, ErrDownloadNotAllowed
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrShareExpired
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return nil, ErrAccessLimitReached
	}

	project, err := s.db.GetProjectByID(ctx, shareToken.ProjectID)
	if err != nil {
		return nil, ErrNotFound
	}

	tracks, err := s.db.ListTracksByProjectID(ctx, project.ID)
	if err != nil {
		return nil, err
	}

	result := &DownloadProjectResult{ProjectName: project.Name, TokenID: shareToken.ID}
	for _, track := range tracks {
		if !track.ActiveVersionID.Valid {
			continue
		}
		version, err := s.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
		if err != nil {
			continue
		}
		trackFile, err := s.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{VersionID: version.ID, Quality: "source"})
		if err != nil {
			continue
		}
		result.Tracks = append(result.Tracks, DownloadProjectTrack{
			Title:    track.Title,
			FilePath: trackFile.FilePath,
			Format:   trackFile.Format,
		})
	}
	if len(result.Tracks) == 0 {
		return nil, fmt.Errorf("no tracks in project: %w", ErrBadRequest)
	}
	return result, nil
}

func (s *sharingService) GetProjectTrackForDownload(ctx context.Context, token, trackPublicID string) (*DownloadTrackResult, error) {
	shareToken, err := s.db.GetProjectShareToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if !shareToken.AllowDownloads {
		return nil, ErrDownloadNotAllowed
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return nil, ErrShareExpired
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return nil, ErrAccessLimitReached
	}

	track, err := s.db.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err != nil {
		return nil, ErrNotFound
	}
	if track.ProjectID != shareToken.ProjectID {
		return nil, ErrForbidden
	}
	if !track.ActiveVersionID.Valid {
		return nil, fmt.Errorf("track has no active version: %w", ErrBadRequest)
	}
	version, err := s.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return nil, ErrNotFound
	}
	trackFile, err := s.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{VersionID: version.ID, Quality: "source"})
	if err != nil {
		return nil, ErrNotFound
	}
	return &DownloadTrackResult{
		Title:    track.Title,
		FilePath: trackFile.FilePath,
		Format:   trackFile.Format,
		TokenID:  shareToken.ID,
	}, nil
}

// -- Share access ---------------------------------------------------------

func (s *sharingService) AcceptShare(ctx context.Context, userID int64, token, password string, instanceURL *string) (sqlc.ShareAccess, error) {
	var shareType string
	var shareTokenID int64
	var canEdit, canDownload bool

	trackToken, err := s.db.GetShareToken(ctx, token)
	if err == nil {
		shareType = "track"
		shareTokenID = trackToken.ID
		canEdit = trackToken.AllowEditing
		canDownload = trackToken.AllowDownloads
		if trackToken.ExpiresAt.Valid && trackToken.ExpiresAt.Time.Before(time.Now()) {
			return sqlc.ShareAccess{}, ErrShareExpired
		}
		if trackToken.MaxAccessCount.Valid && trackToken.CurrentAccessCount.Int64 >= trackToken.MaxAccessCount.Int64 {
			return sqlc.ShareAccess{}, ErrAccessLimitReached
		}
		if trackToken.PasswordHash.Valid {
			if password == "" {
				return sqlc.ShareAccess{}, ErrPasswordRequired
			}
			if err := bcrypt.CompareHashAndPassword([]byte(trackToken.PasswordHash.String), []byte(password)); err != nil {
				return sqlc.ShareAccess{}, ErrInvalidPassword
			}
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		projectToken, err := s.db.GetProjectShareToken(ctx, token)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return sqlc.ShareAccess{}, ErrNotFound
			}
			return sqlc.ShareAccess{}, err
		}
		shareType = "project"
		shareTokenID = projectToken.ID
		canEdit = projectToken.AllowEditing
		canDownload = projectToken.AllowDownloads
		if projectToken.ExpiresAt.Valid && projectToken.ExpiresAt.Time.Before(time.Now()) {
			return sqlc.ShareAccess{}, ErrShareExpired
		}
		if projectToken.MaxAccessCount.Valid && projectToken.CurrentAccessCount.Int64 >= projectToken.MaxAccessCount.Int64 {
			return sqlc.ShareAccess{}, ErrAccessLimitReached
		}
		if projectToken.PasswordHash.Valid {
			if password == "" {
				return sqlc.ShareAccess{}, ErrPasswordRequired
			}
			if err := bcrypt.CompareHashAndPassword([]byte(projectToken.PasswordHash.String), []byte(password)); err != nil {
				return sqlc.ShareAccess{}, ErrInvalidPassword
			}
		}
	} else {
		return sqlc.ShareAccess{}, err
	}

	var userInstanceURL sql.NullString
	if instanceURL != nil {
		userInstanceURL = sql.NullString{String: *instanceURL, Valid: true}
	}

	return s.db.CreateShareAccess(ctx, sqlc.CreateShareAccessParams{
		ShareType:         shareType,
		ShareTokenID:      shareTokenID,
		UserID:            userID,
		UserInstanceUrl:   userInstanceURL,
		FederationTokenID: sql.NullInt64{},
		CanEdit:           canEdit,
		CanDownload:       canDownload,
	})
}

func (s *sharingService) ListSharedWithMe(ctx context.Context, userID int64) ([]sqlc.ShareAccess, error) {
	return s.db.ListShareAccessByUser(ctx, userID)
}

func (s *sharingService) LeaveShare(ctx context.Context, userID, shareAccessID int64) error {
	return s.db.DeleteShareAccess(ctx, sqlc.DeleteShareAccessParams{ID: shareAccessID, UserID: userID})
}

func (s *sharingService) LeaveSharedProject(ctx context.Context, userID int64, projectPublicID string) error {
	project, err := s.db.GetProjectByPublicIDNoFilter(ctx, projectPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	projectShare, err := s.db.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
		ProjectID: project.ID,
		SharedTo:  userID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		// No direct project share; delete individual track shares
		tracks, err := s.db.ListTracksByProjectID(ctx, project.ID)
		if err != nil {
			return err
		}
		deletedCount := 0
		for _, track := range tracks {
			err = s.db.DeleteUserTrackShareByID(ctx, sqlc.DeleteUserTrackShareByIDParams{
				TrackID:  track.ID,
				SharedTo: userID,
			})
			if err == nil {
				deletedCount++
			}
		}
		if deletedCount == 0 {
			return fmt.Errorf("no shares found for project: %w", ErrNotFound)
		}
		return nil
	}
	if err != nil {
		return err
	}
	_ = projectShare
	return s.db.DeleteUserProjectShareByID(ctx, sqlc.DeleteUserProjectShareByIDParams{
		ProjectID: project.ID,
		SharedTo:  userID,
	})
}

func (s *sharingService) LeaveSharedTrack(ctx context.Context, userID int64, trackIDStr string) error {
	trackID, err := strconv.ParseInt(trackIDStr, 10, 64)
	if err != nil {
		track, err := s.db.GetTrackByPublicIDNoFilter(ctx, trackIDStr)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		trackID = track.ID
	}

	err = s.db.DeleteUserTrackShareByID(ctx, sqlc.DeleteUserTrackShareByIDParams{
		TrackID:  trackID,
		SharedTo: userID,
	})
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("no share found for track: %w", ErrNotFound)
	}
	return err
}

// -- User-to-user sharing -------------------------------------------------

func (s *sharingService) ShareProjectWithUsers(ctx context.Context, userID int64, projectPublicID string, input ShareWithUsersInput) (sqlc.Project, int, error) {
	projectRow, err := s.db.GetProjectByPublicID(ctx, sqlc.GetProjectByPublicIDParams{PublicID: projectPublicID, UserID: userID})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.Project{}, 0, ErrNotFound
		}
		return sqlc.Project{}, 0, err
	}
	if projectRow.UserID != userID {
		return sqlc.Project{}, 0, ErrForbidden
	}

	var successCount int
	var lastErr error
	for _, toUserID := range input.UserIDs {
		_, err := s.db.CreateUserProjectShare(ctx, sqlc.CreateUserProjectShareParams{
			ProjectID:   projectRow.ID,
			SharedBy:    userID,
			SharedTo:    toUserID,
			CanEdit:     input.CanEdit,
			CanDownload: input.CanDownload,
		})
		if err != nil {
			lastErr = err
			continue
		}
		successCount++
	}
	if successCount == 0 {
		if lastErr != nil {
			return sqlc.Project{}, 0, lastErr
		}
		return sqlc.Project{}, 0, fmt.Errorf("no users shared with: %w", ErrBadRequest)
	}
	project, err := s.db.GetProjectByID(ctx, projectRow.ID)
	if err != nil {
		return sqlc.Project{}, 0, err
	}
	return project, successCount, nil
}

func (s *sharingService) ShareTrackWithUsers(ctx context.Context, userID int64, trackPublicID string, input ShareWithUsersInput) (sqlc.Track, int, error) {
	track, err := s.db.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.Track{}, 0, ErrNotFound
		}
		return sqlc.Track{}, 0, err
	}

	canShare, err := s.canManageTrackShares(ctx, track, userID)
	if err != nil {
		return sqlc.Track{}, 0, err
	}
	if !canShare {
		return sqlc.Track{}, 0, ErrForbidden
	}

	var successCount int
	var lastErr error
	for _, toUserID := range input.UserIDs {
		_, err := s.db.CreateUserTrackShare(ctx, sqlc.CreateUserTrackShareParams{
			TrackID:     track.ID,
			SharedBy:    userID,
			SharedTo:    toUserID,
			CanEdit:     input.CanEdit,
			CanDownload: input.CanDownload,
		})
		if err != nil {
			lastErr = err
			continue
		}
		successCount++
	}
	if successCount == 0 {
		if lastErr != nil {
			return sqlc.Track{}, 0, lastErr
		}
		return sqlc.Track{}, 0, fmt.Errorf("no users shared with: %w", ErrBadRequest)
	}
	return track, successCount, nil
}

func (s *sharingService) ListProjectShareUsers(ctx context.Context, userID int64, projectPublicID string) ([]sqlc.UserProjectShare, error) {
	project, err := s.db.GetProjectByPublicIDNoFilter(ctx, projectPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if project.UserID != userID {
		return nil, ErrForbidden
	}
	return s.db.ListUsersProjectIsSharedWith(ctx, project.ID)
}

func (s *sharingService) ListTrackShareUsers(ctx context.Context, userID int64, trackPublicID string) ([]sqlc.UserTrackShare, error) {
	track, err := s.db.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	canView, err := s.canManageTrackShares(ctx, track, userID)
	if err != nil {
		return nil, err
	}
	if !canView {
		return nil, ErrForbidden
	}
	return s.db.ListUsersTrackIsSharedWith(ctx, track.ID)
}

func (s *sharingService) UpdateProjectSharePermissions(ctx context.Context, userID, shareID int64, canEdit, canDownload bool) (sqlc.UserProjectShare, error) {
	return s.db.UpdateUserProjectShare(ctx, sqlc.UpdateUserProjectShareParams{
		CanEdit: canEdit, CanDownload: canDownload, ID: shareID, SharedBy: userID,
	})
}

func (s *sharingService) UpdateTrackSharePermissions(ctx context.Context, userID, shareID int64, canEdit, canDownload bool) (sqlc.UserTrackShare, error) {
	existing, err := s.db.GetUserTrackShareByID(ctx, shareID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.UserTrackShare{}, ErrNotFound
		}
		return sqlc.UserTrackShare{}, err
	}
	track, err := s.db.GetTrackByID(ctx, existing.TrackID)
	if err != nil {
		return sqlc.UserTrackShare{}, err
	}
	canManage, err := s.canManageTrackShares(ctx, track, userID)
	if err != nil {
		return sqlc.UserTrackShare{}, err
	}
	if !canManage {
		return sqlc.UserTrackShare{}, ErrForbidden
	}
	return s.db.UpdateUserTrackShareByID(ctx, sqlc.UpdateUserTrackShareByIDParams{
		CanEdit: canEdit, CanDownload: canDownload, ID: shareID,
	})
}

func (s *sharingService) RevokeProjectShare(ctx context.Context, userID, shareID int64) error {
	return s.db.DeleteUserProjectShare(ctx, sqlc.DeleteUserProjectShareParams{ID: shareID, SharedBy: userID})
}

func (s *sharingService) RevokeTrackShare(ctx context.Context, userID, shareID int64) error {
	share, err := s.db.GetUserTrackShareByID(ctx, shareID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	track, err := s.db.GetTrackByID(ctx, share.TrackID)
	if err != nil {
		return err
	}
	canManage, err := s.canManageTrackShares(ctx, track, userID)
	if err != nil {
		return err
	}
	if !canManage {
		return ErrForbidden
	}
	return s.db.DeleteUserTrackShareByShareID(ctx, shareID)
}

func (s *sharingService) ListProjectsSharedWithMe(ctx context.Context, userID int64) ([]ProjectWithShareInfo, error) {
	projects, err := s.db.ListProjectsSharedWithUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	result := make([]ProjectWithShareInfo, len(projects))
	for i, project := range projects {
		info := ProjectWithShareInfo{Project: project}
		owner, err := s.db.GetUserByID(ctx, project.UserID)
		if err == nil {
			info.OwnerUsername = owner.Username
		}
		share, err := s.db.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  userID,
		})
		if err == nil {
			info.AllowEditing = share.CanEdit
			info.AllowDownloads = share.CanDownload
		}
		result[i] = info
	}
	return result, nil
}

func (s *sharingService) ListTracksSharedWithMe(ctx context.Context, userID int64) ([]SharedTrackInfo, error) {
	allTracks, err := s.db.ListTracksSharedWithUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	sharedProjects, err := s.db.ListProjectsSharedWithUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	sharedProjectIDs := make(map[int64]bool, len(sharedProjects))
	for _, p := range sharedProjects {
		sharedProjectIDs[p.ID] = true
	}

	var result []SharedTrackInfo
	for _, track := range allTracks {
		if sharedProjectIDs[track.ProjectID] {
			continue
		}
		project, err := s.db.GetProjectByID(ctx, track.ProjectID)
		if err != nil {
			continue
		}
		shares, err := s.db.ListUsersTrackIsSharedWith(ctx, track.ID)
		if err != nil || len(shares) == 0 {
			continue
		}
		var shareRecord sqlc.UserTrackShare
		for _, share := range shares {
			if share.SharedTo == userID {
				shareRecord = share
				break
			}
		}

		sharedByUser, err := s.db.GetUserByID(ctx, shareRecord.SharedBy)
		if err != nil {
			continue
		}

		var waveform string
		var duration float64
		if track.ActiveVersionID.Valid {
			version, err := s.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
			if err == nil && version.DurationSeconds.Valid {
				duration = version.DurationSeconds.Float64
				files, err := s.db.ListTrackFilesByVersion(ctx, track.ActiveVersionID.Int64)
				if err == nil {
					for _, file := range files {
						if file.Waveform.Valid && file.Waveform.String != "" {
							waveform = file.Waveform.String
							break
						}
					}
				}
			}
		}

		coverURL := ""
		if project.CoverArtPath.Valid && project.CoverArtPath.String != "" {
			coverURL = fmt.Sprintf("/api/projects/%s/cover", project.PublicID)
		}

		var folderID *int64
		var customOrder *int64
		org, err := s.db.GetUserSharedTrackOrganization(ctx, sqlc.GetUserSharedTrackOrganizationParams{
			UserID: userID, TrackID: track.ID,
		})
		if err == nil {
			if org.FolderID.Valid {
				folderID = &org.FolderID.Int64
			}
			customOrder = &org.CustomOrder
		}

		var artist string
		if track.Artist.Valid {
			artist = track.Artist.String
		}

		result = append(result, SharedTrackInfo{
			ID:               track.ID,
			PublicID:         track.PublicID,
			Title:            track.Title,
			Artist:           artist,
			CoverURL:         coverURL,
			ProjectName:      project.Name,
			Waveform:         waveform,
			DurationSeconds:  duration,
			SharedByUsername: sharedByUser.Username,
			CanDownload:      shareRecord.CanDownload,
			FolderID:         folderID,
			CustomOrder:      customOrder,
		})
	}
	return result, nil
}

// -- Visibility -----------------------------------------------------------

func (s *sharingService) UpdateTrackVisibility(ctx context.Context, userID int64, trackPublicID string, input UpdateVisibilityInput) (sqlc.Track, error) {
	track, err := s.db.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.Track{}, ErrNotFound
		}
		return sqlc.Track{}, err
	}

	canManage, err := s.canManageTrackShares(ctx, track, userID)
	if err != nil {
		return sqlc.Track{}, err
	}
	if !canManage {
		return sqlc.Track{}, ErrForbidden
	}

	passwordHash, err := hashSharePassword(input.Password)
	if err != nil {
		return sqlc.Track{}, err
	}

	updated, err := s.db.UpdateTrackVisibilityByPublicIDNoUserFilter(ctx, sqlc.UpdateTrackVisibilityByPublicIDNoUserFilterParams{
		VisibilityStatus: input.VisibilityStatus,
		AllowEditing:     input.AllowEditing,
		AllowDownloads:   input.AllowDownloads,
		PasswordHash:     passwordHash,
		PublicID:         trackPublicID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.Track{}, ErrNotFound
		}
		return sqlc.Track{}, err
	}
	return updated, nil
}

func (s *sharingService) UpdateProjectVisibility(ctx context.Context, userID int64, projectPublicID string, input UpdateVisibilityInput) (sqlc.Project, error) {
	passwordHash, err := hashSharePassword(input.Password)
	if err != nil {
		return sqlc.Project{}, err
	}

	updated, err := s.db.UpdateProjectVisibilityByPublicID(ctx, sqlc.UpdateProjectVisibilityByPublicIDParams{
		VisibilityStatus: input.VisibilityStatus,
		AllowEditing:     input.AllowEditing,
		AllowDownloads:   input.AllowDownloads,
		PasswordHash:     passwordHash,
		PublicID:         projectPublicID,
		UserID:           userID,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return sqlc.Project{}, ErrNotFound
		}
		return sqlc.Project{}, err
	}
	return updated, nil
}
