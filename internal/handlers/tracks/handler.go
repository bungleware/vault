package tracks

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/handlers/shared"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/transcoding"
)

// TrackAccessResult is re-exported from service for callers that still use the package-level helper.
type TrackAccessResult = service.TrackAccessResult

type TracksHandler struct {
	tracks     service.TracksService
	transcoder Transcoder
}

type Transcoder interface {
	TranscodeVersion(ctx context.Context, input transcoding.TranscodeVersionInput) error
}

func NewTracksHandler(tracksService service.TracksService, transcoder Transcoder) *TracksHandler {
	return &TracksHandler{
		tracks:     tracksService,
		transcoder: transcoder,
	}
}

func sanitizeFilenameForPath(name string) string {
	// kept for use in upload.go
	_ = name
	return ""
}

// CheckTrackAccess is a backward-compat package-level wrapper used by handlers outside this package (e.g. notes.go).
// It delegates to the service implementation via the shared db argument.
// TODO(Phase 5): Remove once notes handler is migrated to use TracksService directly.
func CheckTrackAccess(ctx context.Context, svc service.TracksService, trackID int64, projectID int64, userID int64) (TrackAccessResult, error) {
	return svc.CheckTrackAccess(ctx, trackID, projectID, userID)
}

func mapServiceErr(err error) error {
	switch {
	case errors.Is(err, service.ErrNotFound):
		return apperr.NewNotFound(err.Error())
	case errors.Is(err, service.ErrForbidden):
		return apperr.NewForbidden(err.Error())
	case errors.Is(err, service.ErrBadRequest):
		return apperr.NewBadRequest(err.Error())
	case errors.Is(err, service.ErrConflict):
		return apperr.NewConflict(err.Error())
	default:
		return apperr.NewInternal("internal error", err)
	}
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
		result, err := h.tracks.ListTracksByProject(ctx, int64(userID), projectIDStr)
		if err != nil {
			return mapServiceErr(err)
		}
		response = convertTracksWithDetailsWithPermissions(result.Tracks, int64(userID), result.IsProjectOwner, result.ProjectShare)
	} else {
		dbTracks, err := h.tracks.ListAllTracksByUser(ctx, int64(userID))
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

	dbTracks, err := h.tracks.SearchTracks(r.Context(), int64(userID), query, limit)
	if err != nil {
		return apperr.NewInternal("failed to search tracks", err)
	}

	return httputil.OKResult(w, convertSearchTracksRows(dbTracks))
}

func (h *TracksHandler) GetTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	result, err := h.tracks.GetTrack(r.Context(), int64(userID), publicID)
	if err != nil {
		return mapServiceErr(err)
	}

	response := convertTrackWithDetails(result.Track)

	var projectPublicID *string
	var projectCoverURL *string
	if result.Project != nil {
		projectPublicID = &result.Project.PublicID
		if result.Project.CoverArtPath.Valid && result.Project.CoverArtPath.String != "" {
			coverURL := fmt.Sprintf("/api/projects/%s/cover", result.Project.PublicID)
			projectCoverURL = &coverURL
		}
	}

	var artistName *string
	if response.Artist != nil && *response.Artist != "" {
		artistName = response.Artist
	}
	if artistName == nil && result.Owner != nil {
		artistName = &result.Owner.Username
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
		"can_edit":                        result.Access.CanEdit,
		"can_download":                    result.Access.CanDownload,
		"folder_id":                       result.FolderID,
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

	var projectID *int64
	if req.ProjectID != nil {
		id := int64(*req.ProjectID)
		projectID = &id
	}
	var bpm *int64
	if req.BPM != nil {
		b := int64(*req.BPM)
		bpm = &b
	}

	track, err := h.tracks.UpdateTrack(r.Context(), int64(userID), publicID, service.UpdateTrackInput{
		Title:           req.Title,
		Artist:          req.Artist,
		Album:           req.Album,
		ProjectID:       projectID,
		Key:             req.Key,
		BPM:             bpm,
		Notes:           req.Notes,
		NotesAuthorName: req.NotesAuthorName,
	})
	if err != nil {
		return mapServiceErr(err)
	}

	return httputil.OKResult(w, convertTrack(track))
}

func (h *TracksHandler) DeleteTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	publicID := r.PathValue("id")

	if err := h.tracks.DeleteTrack(r.Context(), int64(userID), publicID); err != nil {
		return mapServiceErr(err)
	}

	return httputil.NoContentResult(w)
}
