package sharing

import (
	"database/sql"
	"errors"
	"io"
	"net/http"
	"time"

	"bungleware/vault/internal/apperr"
	sqlc "bungleware/vault/internal/db/sqlc"
	"bungleware/vault/internal/httputil"
	"bungleware/vault/internal/storage"
)

func (h *SharingHandler) StreamSharedTrack(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token required")
	}

	ctx := r.Context()

	shareToken, err := h.db.GetShareToken(ctx, token)
	if err := httputil.HandleDBError(err, "invalid share token", "failed to query share token"); err != nil {
		return err
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

	// Get version
	version, err := h.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return apperr.NewNotFound("version not found")
	}

	trackFile, err := h.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{
		VersionID: version.ID,
		Quality:   "lossy",
	})
	if errors.Is(err, sql.ErrNoRows) {
		trackFile, err = h.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{
			VersionID: version.ID,
			Quality:   "source",
		})
		if err != nil {
			return apperr.NewNotFound("no audio file available")
		}
	} else if err != nil {
		return apperr.NewInternal("failed to query track file", err)
	}

	http.ServeFile(w, r, trackFile.FilePath)
	return nil
}

func (h *SharingHandler) StreamSharedProjectTrack(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	trackID := r.PathValue("trackId")

	if token == "" || trackID == "" {
		return apperr.NewBadRequest("token and trackId required")
	}

	ctx := r.Context()

	shareToken, err := h.db.GetProjectShareToken(ctx, token)
	if err := httputil.HandleDBError(err, "invalid share token", "failed to query share token"); err != nil {
		return err
	}

	if shareToken.ExpiresAt.Valid && shareToken.ExpiresAt.Time.Before(time.Now()) {
		return apperr.NewForbidden("share token expired")
	}

	if shareToken.MaxAccessCount.Valid && shareToken.CurrentAccessCount.Int64 >= shareToken.MaxAccessCount.Int64 {
		return apperr.NewForbidden("max access count reached")
	}

	track, err := h.db.GetTrackByPublicIDNoFilter(ctx, trackID)
	if err != nil {
		return apperr.NewNotFound("track not found")
	}

	if track.ProjectID != shareToken.ProjectID {
		return apperr.NewForbidden("track does not belong to shared project")
	}

	if !track.ActiveVersionID.Valid {
		return apperr.NewBadRequest("track has no active version")
	}

	// Get version
	version, err := h.db.GetTrackVersion(ctx, track.ActiveVersionID.Int64)
	if err != nil {
		return apperr.NewNotFound("version not found")
	}

	trackFile, err := h.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{
		VersionID: version.ID,
		Quality:   "lossy",
	})
	if errors.Is(err, sql.ErrNoRows) {
		trackFile, err = h.db.GetTrackFile(ctx, sqlc.GetTrackFileParams{
			VersionID: version.ID,
			Quality:   "source",
		})
		if err != nil {
			return apperr.NewNotFound("no audio file available")
		}
	} else if err != nil {
		return apperr.NewInternal("failed to query track file", err)
	}

	http.ServeFile(w, r, trackFile.FilePath)
	return nil
}

func (h *SharingHandler) GetSharedProjectCover(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token required")
	}

	ctx := r.Context()

	var projectID int64

	projectShareToken, err := h.db.GetProjectShareToken(ctx, token)
	if err == nil {
		if projectShareToken.ExpiresAt.Valid && projectShareToken.ExpiresAt.Time.Before(time.Now()) {
			return apperr.NewForbidden("share token expired")
		}
		if projectShareToken.MaxAccessCount.Valid && projectShareToken.CurrentAccessCount.Int64 >= projectShareToken.MaxAccessCount.Int64 {
			return apperr.NewForbidden("max access count reached")
		}
		projectID = projectShareToken.ProjectID
	} else if errors.Is(err, sql.ErrNoRows) {
		trackShareToken, err := h.db.GetShareToken(ctx, token)
		if err == nil {
			if trackShareToken.ExpiresAt.Valid && trackShareToken.ExpiresAt.Time.Before(time.Now()) {
				return apperr.NewForbidden("share token expired")
			}
			if trackShareToken.MaxAccessCount.Valid && trackShareToken.CurrentAccessCount.Int64 >= trackShareToken.MaxAccessCount.Int64 {
				return apperr.NewForbidden("max access count reached")
			}
			track, err := h.db.GetTrackByID(ctx, trackShareToken.TrackID)
			if err != nil {
				return apperr.NewNotFound("track not found")
			}
			projectID = track.ProjectID
		} else if errors.Is(err, sql.ErrNoRows) {
			return apperr.NewNotFound("invalid share token")
		} else {
			return apperr.NewInternal("failed to query share token", err)
		}
	} else {
		return apperr.NewInternal("failed to query share token", err)
	}

	project, err := h.db.GetProjectByID(ctx, projectID)
	if err := httputil.HandleDBError(err, "project not found", "failed to query project"); err != nil {
		return err
	}

	if !project.CoverArtPath.Valid {
		return apperr.NewNotFound("project has no cover art")
	}

	size := r.URL.Query().Get("size")

	stream, err := h.storage.OpenProjectCover(ctx, storage.OpenProjectCoverInput{
		ProjectPublicID: project.PublicID,
		Path:            project.CoverArtPath.String,
		Size:            size,
	})
	if err != nil {
		return apperr.NewInternal("failed to open cover", err)
	}
	defer stream.Reader.Close()

	if size != "" && size != "source" {
		w.Header().Set("Content-Type", "image/webp")
	} else if project.CoverArtMime.Valid {
		w.Header().Set("Content-Type", project.CoverArtMime.String)
	} else {
		w.Header().Set("Content-Type", "image/jpeg")
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	io.Copy(w, stream.Reader)
	return nil
}
