package tracks

import (
	"database/sql"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/transcoding"
)

func (h *TracksHandler) UploadTrack(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		return apperr.NewBadRequest("failed to parse form")
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return apperr.NewBadRequest("no file provided")
	}
	defer file.Close()

	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !transcoding.IsAllowedUploadExtension(ext) {
		return apperr.NewBadRequest("unsupported file format")
	}

	projectIDStr := r.FormValue("project_id")
	if projectIDStr == "" {
		return apperr.NewBadRequest("project_id is required")
	}

	title := r.FormValue("title")
	if title == "" {
		title = strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	}

	artist := sql.NullString{}
	if artistVal := r.FormValue("artist"); artistVal != "" {
		artist = sql.NullString{String: artistVal, Valid: true}
	}

	album := sql.NullString{}
	if albumVal := r.FormValue("album"); albumVal != "" {
		album = sql.NullString{String: albumVal, Valid: true}
	}

	ctx := r.Context()

	result, err := h.tracks.SaveUploadedTrack(ctx, int64(userID), service.SaveUploadedTrackInput{
		ProjectIDStr: projectIDStr,
		Title:        title,
		Artist:       artist,
		Album:        album,
		OriginalName: header.Filename,
		Reader:       file,
	})
	if err != nil {
		return mapServiceErr(err)
	}

	savedPath := result.SavedPath

	// Video files: extract audio track before transcoding
	if transcoding.IsVideoExtension(ext) {
		wavPath, err := transcoding.ExtractAudioToWAV(savedPath)
		if err != nil {
			return apperr.NewInternal("failed to extract audio from video", err)
		}
		savedPath = wavPath
	}

	// Extract metadata and persist duration
	metadata, err := transcoding.ExtractMetadata(savedPath)
	if err != nil {
		slog.Debug("failed to extract metadata", "error", err)
		metadata = &transcoding.AudioMetadata{}
	}
	if metadata.Duration > 0 {
		if err := h.tracks.UpdateVersionDuration(ctx, result.Version.ID, metadata.Duration); err != nil {
			slog.Debug("failed to persist version duration", "error", err)
		}
	}

	if h.transcoder != nil {
		if err := h.transcoder.TranscodeVersion(ctx, transcoding.TranscodeVersionInput{
			VersionID:      result.Version.ID,
			SourceFilePath: savedPath,
			TrackPublicID:  result.Track.PublicID,
			UserID:         int64(userID),
		}); err != nil {
			slog.Debug("failed to queue transcoding", "error", err)
		}
	}

	return httputil.CreatedResult(w, convertTrack(result.Track))
}
