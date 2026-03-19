package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/handlers/tracks"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/service"
	"bungleware/vault/internal/storage"
	"bungleware/vault/internal/transcoding"
)

type VersionsHandler struct {
	versionsService service.VersionsService
	tracksService   service.TracksService
	storage         storage.Storage
	transcoder      tracks.Transcoder
}

func NewVersionsHandler(versionsService service.VersionsService, tracksService service.TracksService, storageAdapter storage.Storage, transcoder tracks.Transcoder) *VersionsHandler {
	return &VersionsHandler{
		versionsService: versionsService,
		tracksService:   tracksService,
		storage:         storageAdapter,
		transcoder:      transcoder,
	}
}

func (h *VersionsHandler) ListVersions(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	ctx := r.Context()
	publicID := r.PathValue("track_id")

	track, err := h.versionsService.GetTrackByPublicID(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to verify track"); err != nil {
		return err
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}

	versions, err := h.versionsService.ListVersions(ctx, track.ID)
	if err != nil {
		return apperr.NewInternal("failed to query versions", err)
	}

	result := make([]VersionWithMetadata, len(versions))
	for i, v := range versions {
		result[i] = VersionWithMetadata{
			ID:              v.ID,
			TrackID:         v.TrackID,
			VersionName:     v.VersionName,
			Notes:           httputil.NullStringToPtr(v.Notes),
			DurationSeconds: httputil.NullFloat64ToPtr(v.DurationSeconds),
			VersionOrder:    v.VersionOrder,
			CreatedAt:       httputil.FormatNullTimeString(v.CreatedAt),
			UpdatedAt:       httputil.FormatNullTimeString(v.UpdatedAt),
		}

		sourceFile, err := h.versionsService.GetTrackFile(ctx, v.ID, "source")
		if err == nil {
			result[i].SourceFileSize = &sourceFile.FileSize
			result[i].SourceFormat = &sourceFile.Format
			if sourceFile.Bitrate.Valid {
				result[i].SourceBitrate = &sourceFile.Bitrate.Int64
			}
			if sourceFile.OriginalFilename.Valid && sourceFile.OriginalFilename.String != "" {
				result[i].SourceOriginalFilename = &sourceFile.OriginalFilename.String
			}
		}

		lossyFile, err := h.versionsService.GetTrackFile(ctx, v.ID, "lossy")
		if err == nil {
			if lossyFile.TranscodingStatus.Valid {
				result[i].LossyTranscodingStatus = &lossyFile.TranscodingStatus.String
			}
			if lossyFile.Waveform.Valid && lossyFile.Waveform.String != "" {
				result[i].Waveform = &lossyFile.Waveform.String
			}
		}
	}

	return httputil.OKResult(w, result)
}

func (h *VersionsHandler) GetVersion(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	versionID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	ctx := r.Context()

	versionWithOwnership, err := h.versionsService.GetVersionWithOwnership(ctx, versionID)
	if err := httputil.HandleDBError(err, "version not found", "failed to query version"); err != nil {
		return err
	}

	track, err := h.versionsService.GetTrackByID(ctx, versionWithOwnership.TrackID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}

	version, err := h.versionsService.GetVersion(ctx, versionID)
	if err != nil {
		return apperr.NewInternal("failed to query version details", err)
	}

	return httputil.OKResult(w, version)
}

func (h *VersionsHandler) UpdateVersion(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	versionID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	req, err := httputil.DecodeJSON[UpdateVersionRequest](r)
	if err != nil {
		return apperr.NewBadRequest("invalid request body")
	}

	ctx := r.Context()

	versionWithOwnership, err := h.versionsService.GetVersionWithOwnership(ctx, versionID)
	if err := httputil.HandleDBError(err, "version not found", "failed to verify version"); err != nil {
		return err
	}

	track, err := h.versionsService.GetTrackByID(ctx, versionWithOwnership.TrackID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}
	if !access.CanEdit {
		return apperr.NewForbidden("editing not allowed for this track")
	}

	currentVersion, err := h.versionsService.GetVersion(ctx, versionID)
	if err != nil {
		return apperr.NewInternal("failed to get current version", err)
	}

	versionName := currentVersion.VersionName
	if req.VersionName != nil {
		versionName = *req.VersionName
	}

	notes := currentVersion.Notes
	if req.Notes != nil {
		notes = sql.NullString{String: *req.Notes, Valid: true}
	}

	version, err := h.versionsService.UpdateVersion(ctx, sqlc.UpdateTrackVersionParams{
		VersionName: versionName,
		Notes:       notes,
		ID:          versionID,
	})
	if err != nil {
		return apperr.NewInternal("failed to update version", err)
	}

	return httputil.OKResult(w, version)
}

func (h *VersionsHandler) ActivateVersion(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	versionID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	ctx := r.Context()

	versionWithOwnership, err := h.versionsService.GetVersionWithOwnership(ctx, versionID)
	if err := httputil.HandleDBError(err, "version not found", "failed to query version"); err != nil {
		return err
	}

	track, err := h.versionsService.GetTrackByID(ctx, versionWithOwnership.TrackID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}
	if !access.CanEdit {
		return apperr.NewForbidden("editing not allowed for this track")
	}

	if err := h.versionsService.SetActiveVersion(ctx, versionID, versionWithOwnership.TrackID); err != nil {
		return apperr.NewInternal("failed to activate version", err)
	}

	return httputil.NoContentResult(w)
}

func (h *VersionsHandler) DeleteVersion(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	versionID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	ctx := r.Context()

	versionWithOwnership, err := h.versionsService.GetVersionWithOwnership(ctx, versionID)
	if err := httputil.HandleDBError(err, "version not found", "failed to query version"); err != nil {
		return err
	}

	track, err := h.versionsService.GetTrackByID(ctx, versionWithOwnership.TrackID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}
	if !access.CanEdit {
		return apperr.NewForbidden("editing not allowed for this track")
	}

	result, err := h.versionsService.DeleteVersion(ctx, versionID)
	if err != nil {
		if errors.Is(err, service.ErrBadRequest) {
			return apperr.NewBadRequest("Cannot delete the active version or the only version.")
		}
		return apperr.NewInternal("failed to delete version", err)
	}

	if err := h.storage.DeleteVersion(ctx, storage.DeleteVersionInput{
		ProjectPublicID: result.ProjectPublicID,
		TrackID:         result.TrackID,
		VersionID:       versionID,
	}); err != nil {
		return apperr.NewInternal("failed to delete version files", err)
	}

	return httputil.NoContentResult(w)
}

func (h *VersionsHandler) UploadVersion(w http.ResponseWriter, r *http.Request) error {
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

	ctx := r.Context()
	publicID := r.PathValue("track_id")

	track, err := h.versionsService.GetTrackByPublicID(ctx, publicID)
	if err := httputil.HandleDBError(err, "track not found", "failed to verify track"); err != nil {
		return err
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}
	if !access.CanEdit {
		return apperr.NewForbidden("editing not allowed for this track")
	}

	project, err := h.versionsService.GetProjectByID(ctx, track.ProjectID)
	if err := httputil.HandleDBError(err, "project not found", "failed to load project"); err != nil {
		return err
	}

	versionName := r.FormValue("version_name")
	if versionName == "" {
		versionName = strings.TrimSuffix(header.Filename, filepath.Ext(header.Filename))
		if versionName == "" {
			count, err := h.versionsService.CountVersions(ctx, track.ID)
			if err != nil {
				return apperr.NewInternal("failed to count versions", err)
			}
			versionName = fmt.Sprintf("Version %d", count+1)
		}
	}

	notes := sql.NullString{}
	if notesVal := r.FormValue("notes"); notesVal != "" {
		notes = sql.NullString{String: notesVal, Valid: true}
	}

	maxOrder, err := h.versionsService.GetMaxVersionOrder(ctx, track.ID)
	if err != nil {
		return apperr.NewInternal("failed to get max version order", err)
	}

	version, err := h.versionsService.CreateVersion(ctx, sqlc.CreateTrackVersionParams{
		TrackID:         track.ID,
		VersionName:     versionName,
		Notes:           notes,
		DurationSeconds: sql.NullFloat64{},
		VersionOrder:    maxOrder + 1,
	})
	if err != nil {
		return apperr.NewInternal("failed to create version", err)
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

	if transcoding.IsVideoExtension(ext) {
		wavPath, err := transcoding.ExtractAudioToWAV(saveResult.Path)
		if err != nil {
			return apperr.NewInternal("failed to extract audio from video", err)
		}
		saveResult.Path = wavPath
		saveResult.Format = "wav"
		if fi, err := os.Stat(wavPath); err == nil {
			saveResult.Size = fi.Size()
		}
	}

	metadata, err := transcoding.ExtractMetadata(saveResult.Path)
	if err != nil {
		slog.Debug("failed to extract metadata", "error", err)
		metadata = &transcoding.AudioMetadata{}
	}

	if metadata.Duration > 0 {
		if err := h.versionsService.UpdateVersionDuration(ctx, version.ID, metadata.Duration); err != nil {
			slog.Debug("failed to persist version duration", "error", err)
		}
	}

	format := saveResult.Format
	quality := "source"

	var bitrate sql.NullInt64
	if metadata.Bitrate > 0 {
		bitrate = sql.NullInt64{Int64: int64(metadata.Bitrate), Valid: true}
	}

	_, err = h.versionsService.CreateTrackFile(ctx, sqlc.CreateTrackFileParams{
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

	return httputil.CreatedResult(w, version)
}

func (h *VersionsHandler) DownloadVersion(w http.ResponseWriter, r *http.Request) error {
	userID, err := httputil.RequireUserID(r)
	if err != nil {
		return apperr.NewUnauthorized("user not found in context")
	}

	versionID, err := httputil.PathInt64(r, "id")
	if err != nil {
		return err
	}

	ctx := r.Context()

	versionWithOwnership, err := h.versionsService.GetVersionWithOwnership(ctx, versionID)
	if err := httputil.HandleDBError(err, "version not found", "failed to query version"); err != nil {
		return err
	}

	track, err := h.versionsService.GetTrackByID(ctx, versionWithOwnership.TrackID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	access, err := tracks.CheckTrackAccess(ctx, h.tracksService, track.ID, track.ProjectID, int64(userID))
	if err != nil {
		return apperr.NewInternal("failed to check track access", err)
	}
	if !access.HasAccess {
		return apperr.NewForbidden("access denied")
	}
	if !access.CanDownload {
		return apperr.NewForbidden("download not allowed for this track")
	}

	sourceFile, err := h.versionsService.GetTrackFile(ctx, versionID, "source")
	if err := httputil.HandleDBError(err, "source file not found", "failed to query source file"); err != nil {
		return err
	}

	f, err := os.Open(sourceFile.FilePath)
	if err != nil {
		return apperr.NewInternal("failed to open file", err)
	}
	defer f.Close()

	fileInfo, err := f.Stat()
	if err != nil {
		return apperr.NewInternal("failed to stat file", err)
	}

	filename := fmt.Sprintf("%s.%s", versionWithOwnership.VersionName, sourceFile.Format)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(fileInfo.Size(), 10))

	io.Copy(w, f)
	return nil
}
