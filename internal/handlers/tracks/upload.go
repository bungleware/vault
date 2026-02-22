package tracks

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/ids"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/storage"
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

	projectIDStr := r.FormValue("project_id")
	if projectIDStr == "" {
		return apperr.NewBadRequest("project_id is required")
	}

	ctx := r.Context()
	var project sqlc.Project

	if id, err := strconv.ParseInt(projectIDStr, 10, 64); err == nil {
		p, err := h.db.GetProjectByID(ctx, id)
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

	isProjectOwner := project.UserID == int64(userID)
	if !isProjectOwner {
		share, err := h.db.Queries.GetUserProjectShare(ctx, sqlc.GetUserProjectShareParams{
			ProjectID: project.ID,
			SharedTo:  int64(userID),
		})
		if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewForbidden("access denied")
		}
		if err != nil {
			return apperr.NewInternal("failed to check share access", err)
		}
		if !share.CanEdit {
			return apperr.NewForbidden("editing not allowed for this shared project")
		}
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

	publicID, err := ids.NewPublicID()
	if err != nil {
		return apperr.NewInternal("failed to generate track id", err)
	}

	maxOrderResult, err := h.db.Queries.GetMaxTrackOrderByProject(ctx, project.ID)
	if err != nil {
		return apperr.NewInternal("failed to get track order", err)
	}

	maxOrder, ok := maxOrderResult.(int64)
	if !ok {
		maxOrder = -1
	}

	track, err := h.db.CreateTrack(ctx, sqlc.CreateTrackParams{
		UserID:    int64(userID),
		ProjectID: project.ID,
		Title:     title,
		Artist:    artist,
		Album:     album,
		PublicID:  publicID,
	})
	if err != nil {
		return apperr.NewInternal("failed to create track", err)
	}

	newOrder := maxOrder + 1
	err = h.db.Queries.UpdateTrackOrder(ctx, sqlc.UpdateTrackOrderParams{
		TrackOrder: newOrder,
		ID:         track.ID,
	})
	if err != nil {
		return apperr.NewInternal("failed to set track order", err)
	}

	versionName := strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
	if versionName == "" {
		versionName = "Original Upload"
	}

	version, err := h.db.CreateTrackVersion(ctx, sqlc.CreateTrackVersionParams{
		TrackID:         track.ID,
		VersionName:     versionName,
		Notes:           sql.NullString{},
		DurationSeconds: sql.NullFloat64{},
		VersionOrder:    1,
	})
	if err != nil {
		return apperr.NewInternal("failed to create version", err)
	}

	err = h.db.SetActiveVersion(ctx, sqlc.SetActiveVersionParams{
		ActiveVersionID: sql.NullInt64{Int64: version.ID, Valid: true},
		ID:              track.ID,
	})
	if err != nil {
		return apperr.NewInternal("failed to set active version", err)
	}

	saveResult, err := h.storage.SaveTrackSource(r.Context(), storage.SaveTrackSourceInput{
		ProjectPublicID: project.PublicID,
		TrackID:         track.ID,
		VersionID:       version.ID,
		OriginalName:    header.Filename,
		Reader:          file,
	})
	if err != nil {
		return apperr.NewInternal("failed to save file", err)
	}

	metadata, err := transcoding.ExtractMetadata(saveResult.Path)
	if err != nil {
		slog.Debug("failed to extract metadata", "error", err)
		metadata = &transcoding.AudioMetadata{}
	}

	if metadata.Duration > 0 {
		if err := h.db.UpdateTrackVersionDuration(ctx, sqlc.UpdateTrackVersionDurationParams{
			DurationSeconds: sql.NullFloat64{Float64: metadata.Duration, Valid: true},
			ID:              version.ID,
		}); err != nil {
			slog.Debug("failed to persist version duration", "error", err)
		}
	}

	format := saveResult.Format
	quality := "source"

	var bitrate sql.NullInt64
	if metadata.Bitrate > 0 {
		bitrate = sql.NullInt64{Int64: int64(metadata.Bitrate), Valid: true}
	}

	_, err = h.db.CreateTrackFile(ctx, sqlc.CreateTrackFileParams{
		VersionID:         version.ID,
		Quality:           quality,
		FilePath:          saveResult.Path,
		FileSize:          saveResult.Size,
		Format:            format,
		Bitrate:           bitrate,
		ContentHash:       sql.NullString{},
		TranscodingStatus: sql.NullString{String: "completed", Valid: true},
		OriginalFilename:  sql.NullString{String: header.Filename, Valid: true},
	})
	if err != nil {
		return apperr.NewInternal("failed to create track file record", err)
	}

	if h.transcoder != nil {
		err = h.transcoder.TranscodeVersion(ctx, transcoding.TranscodeVersionInput{
			VersionID:      version.ID,
			SourceFilePath: saveResult.Path,
			TrackPublicID:  track.PublicID,
			UserID:         int64(userID),
		})
		if err != nil {
			slog.Debug("failed to queue transcoding", "error", err)
		}
	}
	return httputil.CreatedResult(w, convertTrack(track))
}
