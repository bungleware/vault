package tracks

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/db"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/storage"
	"bungleware/vault/internal/transcoding"
)

type TracksHandler struct {
	db         *db.DB
	storage    storage.Storage
	transcoder Transcoder
}

type Transcoder interface {
	TranscodeVersion(ctx context.Context, input transcoding.TranscodeVersionInput) error
}

func NewTracksHandler(database *db.DB, storageAdapter storage.Storage, transcoder Transcoder) *TracksHandler {
	return &TracksHandler{
		db:         database,
		storage:    storageAdapter,
		transcoder: transcoder,
	}
}

func sanitizeFilenameForPath(name string) string {
	result := strings.ReplaceAll(name, " ", "_")
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		".", "_",
	)
	result = replacer.Replace(result)
	if len(result) > 50 {
		result = result[:50]
	}

	return result
}

type TrackAccessResult struct {
	HasAccess      bool
	CanEdit        bool
	CanDownload    bool
	IsOwner        bool
	IsProjectOwner bool
}

func CheckTrackAccess(ctx context.Context, db *db.DB, trackID int64, projectID int64, userID int64) (TrackAccessResult, error) {
	result := TrackAccessResult{}
	project, err := db.GetProjectByID(ctx, projectID)
	if err == nil && project.UserID == userID {
		result.HasAccess = true
		result.CanEdit = true
		result.CanDownload = true
		result.IsProjectOwner = true
		return result, nil
	}

	trackShare, err := db.Queries.GetUserTrackShare(ctx, sqlc.GetUserTrackShareParams{
		TrackID:  trackID,
		SharedTo: userID,
	})
	if err == nil {
		result.HasAccess = true
		result.CanEdit = trackShare.CanEdit
		result.CanDownload = trackShare.CanDownload
		return result, nil
	}

	projectShare, err := db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
		ProjectID: projectID,
		SharedTo:  userID,
	})
	if err == nil {
		result.HasAccess = true
		result.CanEdit = projectShare.CanEdit
		result.CanDownload = projectShare.CanDownload
		return result, nil
	}

	return result, nil
}

func (h *TracksHandler) ListTracks(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	projectIDStr := r.URL.Query().Get("project_id")
	ctx := r.Context()

	var response []shared.TrackListResponse

	if projectIDStr != "" {
		var projectID int64
		var project sqlc.Project

		if id, err := strconv.ParseInt(projectIDStr, 10, 64); err == nil {
			projectID = id
			p, err := h.db.GetProjectByID(ctx, projectID)
			if err == nil {
				project = p
			}
		}

		if project.ID == 0 {
			p, err := h.db.Queries.GetProjectByPublicIDNoFilter(ctx, projectIDStr)
			if err == nil {
				project = service.ProjectRowToProject(p)
			}
		}

		if project.ID == 0 {
			return apperr.NewNotFound("project not found")
		}

		canAccess := project.UserID == int64(userID)
		if !canAccess {
			_, err := h.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
				ProjectID: project.ID,
				SharedTo:  int64(userID),
			})
			if err != sql.ErrNoRows {
				canAccess = true
			}
		}

		if !canAccess {
			return apperr.NewForbidden("access denied")
		}

		dbTracks, err := h.db.Queries.ListTracksWithDetailsByProjectID(ctx, project.ID)
		if err != nil {
			return apperr.NewInternal("failed to query tracks", err)
		}

		var projectShare *sqlc.UserProjectShare
		if project.UserID != int64(userID) {
			share, err := h.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
				ProjectID: project.ID,
				SharedTo:  int64(userID),
			})
			if err == nil {
				projectShare = &share
			}
		}

		response = convertTracksWithDetailsWithPermissions(dbTracks, int64(userID), project.UserID == int64(userID), projectShare)
	} else {
		dbTracks, err := h.db.ListTracksByUser(ctx, int64(userID))
		if err != nil {
			return apperr.NewInternal("failed to query tracks", err)
		}
		response = convertTrackListRowsFromUser(dbTracks)
	}

	return httputil.OKResult(w, response)
}

func (h *TracksHandler) SearchTracks(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	query := r.URL.Query().Get("q")
	limitStr := r.URL.Query().Get("limit")
	limit := int64(100)
	if limitStr != "" {
		if parsedLimit, err := strconv.ParseInt(limitStr, 10, 64); err == nil && parsedLimit > 0 {
			limit = parsedLimit
		}
	}

	ctx := r.Context()

	dbTracks, err := h.db.Queries.SearchTracksAccessibleByUser(ctx, sqlc.SearchTracksAccessibleByUserParams{
		UserID:      int64(userID),
		SearchQuery: query,
		LimitCount:  limit,
	})
	if err != nil {
		return apperr.NewInternal("failed to search tracks", err)
	}
	response := convertSearchTracksRows(dbTracks)

	return httputil.OKResult(w, response)
}

func (h *TracksHandler) GetTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	ctx := r.Context()

	trackRecord, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to query track"); err != nil {
		return err
	}

	access, err := CheckTrackAccess(ctx, h.db, trackRecord.ID, trackRecord.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}

	track, err := h.db.GetTrackWithDetails(ctx, sqlc.GetTrackWithDetailsParams{
		ID:     trackRecord.ID,
		UserID: trackRecord.UserID,
	})
	if err := httputil.HandleDBError(err, "track not found", "failed to query track"); err != nil {
		return err
	}

	response := convertTrackWithDetails(track)
	project, err := h.db.Queries.GetProjectByID(ctx, trackRecord.ProjectID)
	var projectCoverURL *string
	var projectPublicID *string
	if err == nil {
		projectPublicID = &project.PublicID
		if project.CoverArtPath.Valid && project.CoverArtPath.String != "" {
			coverURL := fmt.Sprintf("/api/projects/%s/cover", project.PublicID)
			projectCoverURL = &coverURL
		}
	}

	var artistName *string
	if response.Artist != nil && *response.Artist != "" {
		artistName = response.Artist
	}
	if artistName == nil && err == nil {
		projectOwner, err := h.db.Queries.GetUserByID(ctx, project.UserID)
		if err == nil {
			artistName = &projectOwner.Username
		}
	}

	var folderID *int64
	if project.UserID != int64(userID) {
		org, err := h.db.Queries.GetUserSharedTrackOrganization(ctx, sqlc.GetUserSharedTrackOrganizationParams{
			UserID:  int64(userID),
			TrackID: trackRecord.ID,
		})
		if err == nil && org.FolderID.Valid {
			folderID = &org.FolderID.Int64
		}
	}

	responseMap := map[string]interface{}{
		"id":                              response.ID,
		"user_id":                         response.UserID,
		"project_id":                      response.ProjectID,
		"public_id":                       response.PublicID,
		"title":                           response.Title,
		"artist":                          artistName,
		"album":                           response.Album,
		"key":                             response.Key,
		"bpm":                             response.Bpm,
		"active_version_id":               response.ActiveVersionID,
		"active_version_duration_seconds": response.ActiveVersionDurationSeconds,
		"track_order":                     response.TrackOrder,
		"visibility_status":               response.VisibilityStatus,
		"created_at":                      response.CreatedAt,
		"updated_at":                      response.UpdatedAt,
		"waveform":                        response.Waveform,
		"lossy_transcoding_status":        response.LossyTranscodingStatus,
		"active_version_name":             response.ActiveVersionName,
		"project_name":                    response.ProjectName,
		"project_public_id":               projectPublicID,
		"project_cover_url":               projectCoverURL,
		"can_edit":                        access.CanEdit,
		"can_download":                    access.CanDownload,
		"folder_id":                       folderID,
	}

	return httputil.OKResult(w, responseMap)
}

func (h *TracksHandler) UpdateTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	req, err := httputil.DecodeJSON[shared.UpdateTrackRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	currentTrack, err := h.db.Queries.GetTrackByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to get current track"); err != nil {
		return err
	}

	access, err := CheckTrackAccess(ctx, h.db, currentTrack.ID, currentTrack.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}
	if !access.CanEdit {
		return apperr.NewForbidden("editing not allowed for this track")
	}

	if req.ProjectID != nil {
		_, err := h.db.GetProject(ctx, sqlc.GetProjectParams{
			ID:     int64(*req.ProjectID),
			UserID: int64(userID),
		})
		if err != nil {
			return apperr.NewBadRequest("invalid project_id")
		}
	}

	title := currentTrack.Title
	if req.Title != nil {
		title = *req.Title
	}

	artist := currentTrack.Artist
	if req.Artist != nil {
		artist = sql.NullString{String: *req.Artist, Valid: true}
	}

	album := currentTrack.Album
	if req.Album != nil {
		album = sql.NullString{String: *req.Album, Valid: true}
	}

	projectID := currentTrack.ProjectID
	if req.ProjectID != nil {
		projectID = int64(*req.ProjectID)
	}

	key := currentTrack.Key
	if req.Key != nil {
		key = sql.NullString{String: *req.Key, Valid: true}
	}

	bpm := currentTrack.Bpm
	if req.BPM != nil {
		bpm = sql.NullInt64{Int64: int64(*req.BPM), Valid: true}
	}

	notes := currentTrack.Notes
	notesAuthorName := currentTrack.NotesAuthorName
	if req.Notes != nil {
		notes = sql.NullString{String: *req.Notes, Valid: true}
		if req.NotesAuthorName != nil {
			notesAuthorName = sql.NullString{String: *req.NotesAuthorName, Valid: true}
		}
	}

	var notesUpdatedAtTrigger interface{}
	if req.Notes != nil {
		notesUpdatedAtTrigger = true
	}

	track, err := h.db.UpdateTrack(ctx, sqlc.UpdateTrackParams{
		Title:           title,
		Artist:          artist,
		Album:           album,
		ProjectID:       projectID,
		Key:             key,
		Bpm:             bpm,
		Notes:           notes,
		NotesAuthorName: notesAuthorName,
		Column9:         notesUpdatedAtTrigger,
		ID:              currentTrack.ID,
		UserID:          currentTrack.UserID,
	})
	if err := httputil.HandleDBError(err, "track not found", "failed to update track"); err != nil {
		return err
	}

	return httputil.OKResult(w, convertTrack(track))
}

func (h *TracksHandler) DeleteTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	ctx := r.Context()

	tx, err := h.db.BeginTx(ctx, nil)
	if err != nil {
		return apperr.NewInternal("failed to start transaction", err)
	}
	defer tx.Rollback()

	queries := sqlc.New(tx)

	track, err := queries.GetTrackByPublicIDNoFilter(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to fetch track"); err != nil {
		return err
	}

	access, err := CheckTrackAccess(ctx, h.db, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}
	if !access.CanEdit {
		return apperr.NewForbidden("editing not allowed for this track")
	}

	project, err := queries.GetProjectByID(ctx, track.ProjectID)
	if err := httputil.HandleDBError(err, "project not found", "failed to fetch project"); err != nil {
		return err
	}

	err = queries.DeleteTrack(ctx, sqlc.DeleteTrackParams{
		ID:     track.ID,
		UserID: track.UserID,
	})
	if err != nil {
		return apperr.NewInternal("failed to delete track", err)
	}

	if err := h.storage.DeleteTrack(ctx, storage.DeleteTrackInput{
		ProjectPublicID: project.PublicID,
		TrackID:         track.ID,
	}); err != nil {
		return apperr.NewInternal("failed to delete track files", err)
	}

	if err := tx.Commit(); err != nil {
		return apperr.NewInternal("failed to finalize deletion", err)
	}

	return httputil.NoContentResult(w)
}
