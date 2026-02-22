package sharing

import (
	"archive/zip"
	"io"
	"net/http"
	"os"
	"time"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
)

func (h *SharingHandler) DownloadSharedTrack(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token required")
	}

	ctx := r.Context()

	shareToken, err := h.db.GetShareToken(ctx, token)
	if err := httputil.HandleDBError(err, "invalid share token", "failed to query share token"); err != nil {
		return err
	}

	if !shareToken.AllowDownloads {
		return apperr.NewForbidden("downloads not allowed for this share")
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return apperr.NewForbidden("share token expired")
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return apperr.NewForbidden("max access count reached")
	}

	track, err := h.db.GetTrackByID(ctx, shareToken.TrackID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	if !track.ActiveVersionID.Valid {
		return apperr.NewBadRequest("track has no active version")
	}

	version, err := h.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return apperr.NewNotFound("version not found")
	}
	trackFile, err := h.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{
		VersionID: version.ID,
		Quality:   "source",
	})
	if err != nil {
		return apperr.NewNotFound("no audio file available")
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+track.Title+"."+trackFile.Format+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, trackFile.FilePath)
	return nil
}

func (h *SharingHandler) DownloadShared(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token required")
	}

	ctx := r.Context()

	_, err := h.db.GetShareToken(ctx, token)
	if err == nil {
		return h.DownloadSharedTrack(w, r)
	}

	projectShareToken, err := h.db.GetProjectShareToken(ctx, token)
	if err := httputil.HandleDBError(err, "invalid share token", "failed to query share token"); err != nil {
		return err
	}

	if !projectShareToken.AllowDownloads {
		return apperr.NewForbidden("downloads not allowed for this share")
	}

	if projectShareToken.ExpiresAt.Valid && projectShareToken.ExpiresAt.Time.Before(time.Now()) {
		return apperr.NewForbidden("share token expired")
	}

	if projectShareToken.MaxAccessCount.Valid && projectShareToken.CurrentAccessCount.Int64 >= projectShareToken.MaxAccessCount.Int64 {
		return apperr.NewForbidden("max access count reached")
	}

	project, err := h.db.GetProjectByID(ctx, projectShareToken.ProjectID)
	if err != nil {
		return apperr.NewNotFound("project not found")
	}

	tracks, err := h.db.ListTracksByProjectID(ctx, project.ID)
	if err != nil {
		return apperr.NewInternal("failed to get tracks", err)
	}

	if len(tracks) == 0 {
		return apperr.NewBadRequest("no tracks in project")
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+project.Name+".zip\"")

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	for _, track := range tracks {
		if !track.ActiveVersionID.Valid {
			continue
		}

		version, err := h.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
		if err != nil {
			continue
		}

		trackFile, err := h.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{
			VersionID: version.ID,
			Quality:   "source",
		})
		if err != nil {
			continue
		}

		file, err := os.Open(trackFile.FilePath)
		if err != nil {
			continue
		}

		zipEntry, err := zipWriter.Create(track.Title + "." + trackFile.Format)
		if err != nil {
			file.Close()
			continue
		}

		_, err = io.Copy(zipEntry, file)
		file.Close()
		if err != nil {
			continue
		}
	}
	return nil
}

func (h *SharingHandler) DownloadSharedProjectTrack(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	trackPublicID := r.PathValue("trackId")

	if token == "" || trackPublicID == "" {
		return apperr.NewBadRequest("token and trackId required")
	}

	ctx := r.Context()

	shareToken, err := h.db.GetProjectShareToken(ctx, token)
	if err := httputil.HandleDBError(err, "invalid share token", "failed to query share token"); err != nil {
		return err
	}

	if !shareToken.AllowDownloads {
		return apperr.NewForbidden("downloads not allowed for this share")
	}
	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return apperr.NewForbidden("share token expired")
	}
	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return apperr.NewForbidden("max access count reached")
	}

	track, err := h.db.GetTrackByPublicIDNoFilter(ctx, trackPublicID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	if track.ProjectID != shareToken.ProjectID {
		return apperr.NewForbidden("track not in shared project")
	}

	if !track.ActiveVersionID.Valid {
		return apperr.NewBadRequest("track has no active version")
	}

	version, err := h.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return apperr.NewNotFound("version not found")
	}
	trackFile, err := h.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{
		VersionID: version.ID,
		Quality:   "source",
	})
	if err != nil {
		return apperr.NewNotFound("no audio file available")
	}
	w.Header().Set("Content-Disposition", "attachment; filename=\""+track.Title+"."+trackFile.Format+"\"")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, trackFile.FilePath)
	return nil
}
