package handlers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/tracks"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/middleware"
	"bungleware/vault/internal/service"
)

type StreamingHandler struct {
	tracksService service.TracksService
}

func NewStreamingHandler(tracksService service.TracksService) *StreamingHandler {
	return &StreamingHandler{tracksService: tracksService}
}

func (h *StreamingHandler) StreamTrack(w http.ResponseWriter, r *http.Request) error {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		if !middleware.SignedURLValid(r.Context()) {
			return apperr.NewUnauthorized("unauthorized")
		}
		signedUserID := r.URL.Query().Get("user_id")
		if signedUserID == "" {
			return apperr.NewUnauthorized("unauthorized")
		}
		parsed, err := strconv.Atoi(signedUserID)
		if err != nil {
			return apperr.NewBadRequest("invalid user_id")
		}
		userID = parsed
	}

	publicID := r.PathValue("id")

	var versionID *int64
	if versionIDStr := r.URL.Query().Get("version_id"); versionIDStr != "" {
		vid, err := strconv.ParseInt(versionIDStr, 10, 64)
		if err != nil {
			return apperr.NewBadRequest("invalid version_id")
		}
		versionID = &vid
	}

	requestedQuality := r.URL.Query().Get("quality")
	ctx := r.Context()

	track, err := h.tracksService.GetTrackByPublicID(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to query track"); err != nil {
		return err
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access revoked")
	}

	var finalVersionID int64
	if versionID != nil {
		finalVersionID = *versionID
	} else {
		if !track.ActiveVersionID.Valid {
			return apperr.NewBadRequest("track has no active version")
		}
		finalVersionID = track.ActiveVersionID.Int64
	}

	quality := h.resolveQuality(ctx, int64(userID), track.ID, requestedQuality)

	file, err := h.findTrackFile(ctx, finalVersionID, quality)
	if err != nil {
		return apperr.NewInternal(fmt.Sprintf("failed to find track file: %v", err), err)
	}

	h.streamFile(w, r, file)
	return nil
}

func (h *StreamingHandler) resolveQuality(ctx context.Context, userID, trackID int64, requestedQuality string) string {
	if requestedQuality != "" {
		switch requestedQuality {
		case "source", "lossless", "lossy":
			return requestedQuality
		}
	}

	track, err := h.tracksService.GetTrackByID(ctx, trackID)
	if err == nil {
		project, err := h.tracksService.GetProjectByID(ctx, track.ProjectID)
		if err == nil && project.QualityOverride.Valid {
			return project.QualityOverride.String
		}
	}

	prefs, err := h.tracksService.GetUserPreferences(ctx, userID)
	if err == nil {
		return prefs.DefaultQuality
	}

	return "lossy"
}

func (h *StreamingHandler) findTrackFile(ctx context.Context, versionID int64, preferredQuality string) (*sqlc.TrackFile, error) {
	file, err := h.tracksService.GetCompletedTrackFile(ctx, versionID, preferredQuality)
	if err == nil {
		return &file, nil
	}

	if preferredQuality != "lossy" {
		file, err = h.tracksService.GetCompletedTrackFile(ctx, versionID, "lossy")
		if err == nil {
			return &file, nil
		}
	}

	if preferredQuality != "source" {
		file, err = h.tracksService.GetCompletedTrackFile(ctx, versionID, "source")
		if err == nil {
			return &file, nil
		}
	}

	if preferredQuality != "lossless" {
		file, err = h.tracksService.GetCompletedTrackFile(ctx, versionID, "lossless")
		if err == nil {
			return &file, nil
		}
	}

	return nil, fmt.Errorf("no available file found")
}

func (h *StreamingHandler) streamFile(w http.ResponseWriter, r *http.Request, file *sqlc.TrackFile) {
	f, err := os.Open(file.FilePath)
	if err != nil {
		http.Error(w, "failed to open file", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "failed to stat file", http.StatusInternalServerError)
		return
	}

	contentType := "audio/mpeg"
	switch file.Format {
	case "flac":
		contentType = "audio/flac"
	case "mp3":
		contentType = "audio/mpeg"
	case "m4a":
		contentType = "audio/mp4"
	case "wav":
		contentType = "audio/wav"
	}

	w.Header().Set("Content-Type", contentType)
	http.ServeContent(w, r, file.FilePath, stat.ModTime(), f)
}
