package sharing

import (
	"io"
	"net/http"

	"bungleware/vault/internal/apperr"
	"bungleware/vault/internal/storage"
)

func (h *SharingHandler) StreamSharedTrack(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token required")
	}

	result, err := h.svc.GetTrackForStream(r.Context(), token)
	if err != nil {
		return mapSharingErr(err)
	}
	if err := h.validateFilePath(result.FilePath); err != nil {
		return err
	}
	h.svc.IncrementTrackAccessCount(r.Context(), result.TokenID)
	http.ServeFile(w, r, result.FilePath)
	return nil
}

func (h *SharingHandler) StreamSharedProjectTrack(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	trackID := r.PathValue("trackId")
	if token == "" || trackID == "" {
		return apperr.NewBadRequest("token and trackId required")
	}

	result, err := h.svc.GetProjectTrackForStream(r.Context(), token, trackID)
	if err != nil {
		return mapSharingErr(err)
	}
	if err := h.validateFilePath(result.FilePath); err != nil {
		return err
	}
	h.svc.IncrementProjectAccessCount(r.Context(), result.TokenID)
	http.ServeFile(w, r, result.FilePath)
	return nil
}

func (h *SharingHandler) GetSharedProjectCover(w http.ResponseWriter, r *http.Request) error {
	token := r.PathValue("token")
	if token == "" {
		return apperr.NewBadRequest("token required")
	}

	result, err := h.svc.GetProjectCoverForShare(r.Context(), token)
	if err != nil {
		return mapSharingErr(err)
	}

	if result.CoverArtPath == "" {
		return apperr.NewNotFound("project has no cover art")
	}

	size := r.URL.Query().Get("size")
	stream, err := h.storage.OpenProjectCover(r.Context(), storage.OpenProjectCoverInput{
		ProjectPublicID: result.ProjectPublicID,
		Path:            result.CoverArtPath,
		Size:            size,
	})
	if err != nil {
		return apperr.NewInternal("failed to open cover", err)
	}
	defer stream.Reader.Close()

	if size != "" && size != "source" {
		w.Header().Set("Content-Type", "image/webp")
	} else if result.CoverArtMime.Valid {
		w.Header().Set("Content-Type", result.CoverArtMime.String)
	} else {
		w.Header().Set("Content-Type", "image/jpeg")
	}
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")

	if result.IsProjectToken {
		h.svc.IncrementProjectAccessCount(r.Context(), result.TokenID)
	} else {
		h.svc.IncrementTrackAccessCount(r.Context(), result.TokenID)
	}
	io.Copy(w, stream.Reader)
	return nil
}

